import functools
import hmac
import json
import math
import re
from datetime import datetime, timezone
import os
import secrets
import time
from pathlib import Path
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from .db import Store, uid
from .engine import SEVERITIES
from .security import Vault, digest, validate_url
from .diagnostics import redact

AI_DEFAULTS = {'model': '', 'triage_tokens': 4000, 'incident_tokens': 20000, 'daily_tokens': 50000, 'monthly_tokens': 500000, 'daily_cost': 2.0, 'monthly_cost': 20.0, 'max_turns': 4, 'input_price': 0.0, 'output_price': 0.0}


def create_app(data_dir=None, testing=False):
    directory = Path(data_dir or os.environ.get('AITICKET_DATA', 'data'))
    store = Store(directory / 'app.db')
    vault = Vault(os.environ.get('AITICKET_KEY_FILE', str(directory / 'encryption.key')))
    if not store.setting('session_secret') or not store.setting('admin_hash'):
        raise RuntimeError('Run python -m aiticket init before starting the server.')
    app = Flask(__name__)
    app.config.update(SECRET_KEY=vault.decrypt(store.setting('session_secret')), TESTING=testing,
                      MAX_CONTENT_LENGTH=2100000, MAX_FORM_MEMORY_SIZE=2100000, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=not testing and os.environ.get('AITICKET_LOCAL_HTTP') != '1' and os.environ.get('AITICKET_ALLOW_INSECURE_HTTP') != '1',
                      PERMANENT_SESSION_LIFETIME=3600)
    app.extensions.update(store=store, vault=vault)

    def login_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get('admin') or session.get('auth_generation') != store.setting('auth_generation'):
                if session.get('admin'):
                    with store.connect() as c:
                        store.audit(c,'security.session_invalid','administrator',actor='security')
                    session.clear()
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def guard():
        if request.method == 'POST' and not request.path.startswith(('/api/agent/', '/api/hermes/','/api/operations/')):
            if not hmac.compare_digest(session.get('csrf', ''), request.form.get('csrf', '')) or not session.get('csrf'):
                abort(403)

    @app.after_request
    def headers(response):
        if response.status_code in (401,403,429):
            with store.connect() as c:
                store.audit(c,'security.request_denied',request.endpoint or 'unknown',{'status':response.status_code,'address_digest':digest(request.remote_addr or 'unknown')},actor='security')
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.template_filter('timestamp')
    def timestamp(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if value else 'Never'

    @app.context_processor
    def context():
        session.setdefault('csrf', secrets.token_urlsafe(32))
        return {'csrf': session['csrf'], 'severities': SEVERITIES,'ai_execution_mode':store.setting('hermes_config',{}).get('execution_mode','gateway')}

    @app.errorhandler(ValueError)
    def invalid(exc):
        if request.path.startswith(('/api/hermes/','/api/operations/')):
            return {'error':redact(str(exc))[:500],'state':'rejected'},400
        return render_template('error.html', message=str(exc)), 400

    @app.get('/health')
    def health():
        return {'status': 'ok', 'ai_dispatch': 'enabled' if store.setting('hermes_config', {}).get('enabled') else 'disabled', 'version': '0.1.0'}

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            address = request.remote_addr or 'unknown'
            now = time.time()
            with store.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                row = c.execute('SELECT * FROM login_attempts WHERE address=?', (address,)).fetchone()
                if row and row['blocked_until'] > now:
                    abort(429)
                if check_password_hash(store.setting('admin_hash'), request.form.get('password', '')):
                    c.execute('DELETE FROM login_attempts WHERE address=?', (address,))
                    store.audit(c,'security.login_succeeded','administrator',{'address_digest':digest(address)},actor='security')
                    session.clear()
                    session.update(admin=True, csrf=secrets.token_urlsafe(32), auth_generation=store.setting('auth_generation'))
                    session.permanent = True
                    return redirect(url_for('dashboard'))
                failures = (row['failures'] if row else 0) + 1
                c.execute('INSERT INTO login_attempts VALUES(?,?,?) ON CONFLICT(address) DO UPDATE SET failures=excluded.failures,blocked_until=excluded.blocked_until', (address, failures, now + 60 if failures >= 5 else 0))
                store.audit(c,'security.login_failed','administrator',{'address_digest':digest(address)},actor='security')
            flash('Incorrect password.')
        return render_template('login.html')

    @app.post('/logout')
    @login_required
    def logout():
        with store.connect() as c:
            store.audit(c,'security.logout','administrator',actor='security')
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @login_required
    def dashboard():
        from .hostview import overview
        return render_template('dashboard.html', connections=store.rows('SELECT id,name,last_discovery FROM proxmox_connections ORDER BY name'), hosts=overview(store), checks=store.rows("SELECT checks.*,machines.name AS machine FROM checks JOIN machines ON machines.id=machine_id WHERE checks.kind<>'manual' ORDER BY machines.name"),
                               incidents=store.rows('SELECT incidents.*,machines.name AS machine FROM incidents JOIN machines ON machines.id=machine_id WHERE incidents.archived_at IS NULL ORDER BY first_seen DESC LIMIT 100'),
                               jobs=store.rows('SELECT state,count(*) AS count FROM deliveries GROUP BY state'), ai_enabled=store.setting('hermes_config', {}).get('enabled', False))

    @app.get('/hosts/<machine_id>')
    @login_required
    def host_detail(machine_id):
        from .hostview import detail
        data=detail(store,machine_id)
        if not data: abort(404)
        from .commands import view as command_view
        data.update(command_request_id=uid(),command_policy=next(iter(store.rows('SELECT * FROM command_policies WHERE machine_id=?',(machine_id,))),None),command_jobs=[command_view(store,vault,r['id']) for r in store.rows('SELECT id FROM command_jobs WHERE machine_id=? ORDER BY created DESC LIMIT 20',(machine_id,))])
        from .proxmox_operations import view as px_view
        data['proxmox_api_jobs']=[px_view(store,vault,r['id']) for r in store.rows('SELECT id FROM proxmox_api_jobs WHERE machine_id=? ORDER BY created DESC LIMIT 20',(machine_id,))]
        from .metric_history import charts
        data['history']=charts(store,data['host'],request.args.get('window','6h'))
        return render_template('host-detail.html',**data)

    @app.get('/hosts/<machine_id>/checks/new')
    @login_required
    def host_add_check(machine_id):
        machines=store.rows('SELECT id,name FROM machines WHERE id=?',(machine_id,))
        if not machines: abort(404)
        return render_template('host-add-check.html',machines=machines)

    @app.route('/hosts/<machine_id>/settings',methods=['GET','POST'])
    @login_required
    def host_settings(machine_id):
        from .hostview import detail
        from .commands import configure
        from .machine_context import context as access_context
        data=detail(store,machine_id)
        if not data: abort(404)
        old=next(iter(store.rows('SELECT * FROM command_policies WHERE machine_id=?',(machine_id,))),None)
        if request.method=='POST':
            mode=request.form.get('access_mode')
            if mode not in ('readonly','guarded','immediate'): raise ValueError('Choose one of the three host access modes.')
            configure(store,machine_id,{'enabled':'yes','hermes':'yes','external':'yes','approval':mode,'timeout':request.form.get('timeout','120'),'output_limit':request.form.get('output_limit','8192')})
            flash('Host access saved: '+{'readonly':'Read only commands','guarded':'Ask before potentially dangerous commands','immediate':'Full access — commands run without per-command approval'}[mode]+'.')
            return redirect(url_for('host_settings',machine_id=machine_id))
        with store.connect() as c: access=access_context(c,machine_id)
        data.update(command_policy=old,access=access,access_mode=old['approval'] if old and old['enabled'] else 'readonly')
        return render_template('host-settings.html',**data)

    @app.post('/hosts/<machine_id>/command-policy')
    @login_required
    def command_policy(machine_id):
        from .commands import configure
        if request.form.get('confirm')!='yes': raise ValueError('Confirm arbitrary remote command permissions for this host.')
        configure(store,machine_id,request.form)
        return redirect(url_for('host_detail',machine_id=machine_id))

    @app.post('/hosts/<machine_id>/command')
    @login_required
    def manual_command(machine_id):
        from .commands import queue
        queue(store,vault,machine_id,request.form.get('command'),request.form.get('request_id'),request.form.get('incident_id') or None)
        return redirect(url_for('host_detail',machine_id=machine_id))

    @app.post('/commands/<identifier>/decide')
    @login_required
    def command_decision(identifier):
        from .commands import decide
        if request.form.get('confirm')!='yes': raise ValueError('Confirm the exact command or independently verified unknown outcome.')
        decide(store,identifier,request.form.get('operation'),request.form.get('fingerprint'))
        machine=store.rows('SELECT machine_id FROM command_jobs WHERE id=?',(identifier,))[0]['machine_id']
        return redirect(url_for('host_detail',machine_id=machine))

    @app.post('/proxmox-requests/<identifier>/decide')
    @login_required
    def proxmox_request_decision(identifier):
        from .proxmox_operations import decide,view
        if request.form.get('confirm')!='yes': raise ValueError('Confirm the exact Proxmox API decision.')
        decide(store,vault,identifier,request.form.get('operation'),request.form.get('fingerprint'))
        return redirect(url_for('host_detail',machine_id=view(store,vault,identifier)['machine_id']))

    def command_agent():
        bearer=request.headers.get('Authorization','')
        rows=store.rows('SELECT id FROM agents WHERE credential_digest=? AND revoked=0',(digest(bearer[7:]) if bearer.startswith('Bearer ') else '',))
        if not rows: abort(401)
        return rows[0]['id']

    @app.post('/api/agent/command-permission')
    def command_permission():
        from .commands import permission
        return permission(store,command_agent(),request.get_json() or {})

    @app.post('/api/agent/command-result')
    def command_result():
        from .commands import complete
        return complete(store,command_agent(),request.get_json() or {})

    def command_tool_action(payload,ai_job=None,external=False):
        from .commands import queue,view,decide
        if not isinstance(payload,dict) or set(payload)-{'action','machine_id','incident_id','command','id','connection_id','method','path','params','summary'}: raise ValueError('Invalid command tool envelope.')
        if any(k in payload and (not isinstance(payload[k],str) or len(payload[k])>100) for k in ('id','machine_id','incident_id')): raise ValueError('Invalid command target identity.')
        action=payload.get('action')
        if ai_job:
            with store.connect() as c:
                from .commands import ai_allowed
                job=ai_allowed(c,ai_job)
                if not job: abort(403)
                incident=store.rows('SELECT machine_id FROM incidents WHERE id=?',(job['incident_id'],))[0]
                machine=incident['machine_id'];incident_id=job['incident_id']
        else:
            machine=payload.get('machine_id');incident_id=payload.get('incident_id')
        if action=='block':
            if not ai_job: abort(403)
            reason=payload.get('summary')
            if not isinstance(reason,str) or not 1<=len(reason.strip())<=1000: raise ValueError('Supply a brief blocker explanation.')
            from .worklog import block
            with store.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                if not ai_allowed(c,ai_job): abort(403)
                block(c,store,incident_id,ai_job,reason,time.time())
            return {'state':'waiting_for_human','note':'Finish this run with a brief note. The administrator can reply and resume this ticket.'}
        if action=='resolve':
            if not ai_job: abort(403)
            summary=payload.get('summary')
            if not isinstance(summary,str) or not 1<=len(summary.strip())<=1000: raise ValueError('Supply a brief repair summary of 1–1000 characters.')
            with store.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                from .commands import ai_allowed
                current=ai_allowed(c,ai_job)
                if not current: abort(403)
                c.execute('UPDATE ai_jobs SET resolution_summary=? WHERE id=?',(redact(summary.strip()),ai_job))
                c.execute('UPDATE checks SET next_run=0 WHERE machine_id=? AND enabled=1',(machine,))
                store.timeline(c,incident_id,'resolution_requested','AI requested closure after independent monitoring verification: '+redact(summary.strip()),actor='hermes')
            return {'state':'verification_pending','note':'Finish this investigation. After it completes, the server resolves and sends the configured recovery notification only once fresh independent monitoring is healthy. No closure from AI text alone.'}
        from . import proxmox_operations as pxops
        if action=='targets':
            targets=store.rows('SELECT m.id,m.name FROM machines m JOIN command_policies p ON p.machine_id=m.id WHERE p.enabled=1 AND '+('m.id=? AND p.hermes=1' if ai_job else 'p.external=1'),(machine,) if ai_job else ())
            if ai_job: targets=store.rows('SELECT id,name FROM machines WHERE id=?',(machine,))
            with store.connect() as c:
                from .machine_context import context as machine_context
                targets=[{**machine_context(c,target['id'],external=external),'proxmox':pxops.context(c,target['id'])} for target in targets]
            return {'targets':targets}
        if action=='proxmox':
            identifier=pxops.queue(store,vault,machine,payload,ai_job,external)
            return pxops.view(store,vault,identifier)
        if action=='proxmox_status':
            result=pxops.view(store,vault,payload.get('id'))
            if ai_job:
                prior=store.rows('SELECT incident_id FROM ai_jobs WHERE id=?',(result['ai_job_id'],))
                if result['machine_id']!=machine or not prior or prior[0]['incident_id']!=incident_id: abort(403)
            with store.connect() as c: pxops.policy(c,result['machine_id'],ai_job,external)
            return result
        if action=='run':
            identifier=queue(store,vault,machine,payload.get('command'),payload.get('id'),incident_id,ai_job,external)
        else:
            identifier=payload.get('id')
            rows=store.rows('SELECT machine_id,ai_job_id,incident_id FROM command_jobs WHERE id=?',(identifier,))
            if not rows:
                return {'state':'not_recorded','id':identifier,'note':'No command with this UUID is currently recorded. A failed status lookup does not establish dispatch.'}
            if ai_job and (rows[0]['machine_id']!=machine or rows[0]['incident_id']!=incident_id or (action!='status' and rows[0]['ai_job_id']!=ai_job)): abort(403)
            machine=rows[0]['machine_id']
            if external and not store.rows('SELECT 1 FROM command_policies WHERE machine_id=? AND external=1',(machine,)): abort(403)
            if action=='cancel': decide(store,identifier,'cancel')
            elif action!='status': raise ValueError('Unknown command tool action.')
        return view(store,vault,identifier)

    @app.post('/api/hermes/<job_id>/command')
    def ai_command_tool(job_id):
        execution_auth(job_id)
        return command_tool_action(request.get_json() or {},ai_job=job_id)

    @app.post('/api/operations/command')
    def external_command_tool():
        from .hermes_bridge import authenticate
        secret=store.setting('hermes_secret')
        if not secret or not authenticate(vault.decrypt(secret),request.get_data(),request.headers): abort(401)
        return command_tool_action(request.get_json() or {},external=True)

    @app.post('/hosts/<machine_id>/edit')
    @login_required
    def edit_host(machine_id):
        from .host_admin import edit
        edit(store,machine_id,request.form.get('name',''),request.form.get('parent'))
        return redirect(url_for('host_detail',machine_id=machine_id))

    @app.post('/hosts/<machine_id>/proxmox-link')
    @login_required
    def link_host(machine_id):
        from .proxmox import link
        if request.form.get('confirm')!='yes': raise ValueError('Confirm the exact machine/resource link.')
        link(store,request.form.get('object_id'),machine_id,request.form.get('expected'))
        return redirect(url_for('host_detail',machine_id=machine_id))

    @app.post('/proxmox/resources/<object_id>/link')
    @login_required
    def assign_resource(object_id):
        from .proxmox import link
        f=request.form
        if f.get('confirm')!='yes': raise ValueError('Confirm the exact machine/resource link.')
        link(store,object_id,f.get('machine_id'),f.get('expected'),f.get('create_name','').strip() if not f.get('machine_id') else None)
        machine=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(object_id,))[0]['machine_id']
        return redirect(url_for('host_detail',machine_id=machine))

    @app.route('/tickets/new',methods=['GET','POST'])
    @login_required
    def new_ticket():
        if request.method=='POST':
            from .host_admin import open_ticket
            f=request.form
            handling=f.get('handling_mode','automatic')
            if handling not in ('automatic','human','paused'): raise ValueError('Unknown handling mode.')
            identifier=open_ticket(store,f.get('machine_id'),f.get('title',''),f.get('description',''),f.get('severity','low'),f.get('notify')=='yes',handling_mode=handling)
            return redirect(url_for('incident',incident_id=identifier))
        from .hostview import overview
        return render_template('ticket-new.html',host_previews=overview(store),machines=store.rows('SELECT id,name FROM machines ORDER BY name'),selected=request.args.get('machine',''))

    @app.post('/hosts/<machine_id>/power-policy')
    @login_required
    def power_policy(machine_id):
        from .power import configure
        f=request.form
        configure(store,vault,machine_id,f.get('backend'),f.get('connection_id'),f.get('token_id',''),f.get('token_secret',''),enabled=f.get('enabled')=='yes',validated=f.get('validated')=='yes',confirm=f.get('confirm')=='yes')
        return redirect(url_for('host_detail',machine_id=machine_id))

    @app.post('/hosts/<machine_id>/power')
    @login_required
    def request_power(machine_id):
        from .power import propose
        propose(store,machine_id,request.form.get('operation'),request.form.get('reason',''))
        return redirect(url_for('host_detail',machine_id=machine_id))

    @app.post('/power/<job_id>/decide')
    @login_required
    def decide_power(job_id):
        from .power import decide
        if request.form.get('confirm')!='yes':
            raise ValueError('Confirm the exact power operation or independently checked unknown outcome.')
        decide(store,job_id,request.form.get('payload_hash'),request.form.get('decision'))
        rows=store.rows('SELECT machine_id FROM power_jobs WHERE id=?',(job_id,))
        return redirect(url_for('host_detail',machine_id=rows[0]['machine_id']))

    @app.get('/proxmox/resources/<object_id>')
    @login_required
    def resource_detail(object_id):
        from .hostview import object_detail
        data=object_detail(store,object_id)
        if not data: abort(404)
        from .proxmox_operations import view as px_view
        data['proxmox_api_jobs']=[px_view(store,vault,r['id']) for r in store.rows('SELECT id FROM proxmox_api_jobs WHERE machine_id=? ORDER BY created DESC LIMIT 20',(machine_id,))]
        from .metric_history import charts
        data['history']=charts(store,data['host'],request.args.get('window','6h'))
        return render_template('host-detail.html',**data)

    @app.route('/hosts', methods=['GET', 'POST'])
    @login_required
    def hosts():
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            if not 1 <= len(name) <= 100:
                raise ValueError('Machine name must contain 1–100 characters.')
            parent = request.form.get('parent') or None
            with store.connect() as c:
                if parent and not c.execute('SELECT 1 FROM machines WHERE id=?', (parent,)).fetchone():
                    raise ValueError('Unknown parent machine.')
                machine_id = uid()
                c.execute('INSERT INTO machines(id,name,parent_id,created) VALUES(?,?,?,?)', (machine_id, name, parent, time.time()))
                store.audit(c, 'machine.created', machine_id, {'parent_id': parent})
            return redirect(url_for('hosts'))
        return render_template('hosts.html', checks=store.rows("SELECT c.*,m.name AS machine FROM checks c JOIN machines m ON m.id=c.machine_id WHERE c.kind<>'manual' ORDER BY m.name,c.name"), machines=store.rows('SELECT * FROM machines ORDER BY name'), agents=store.rows('SELECT agents.*,machines.name FROM agents JOIN machines ON machines.id=machine_id'))

    @app.post('/checks')
    @login_required
    def add_check():
        f = request.form
        kind = f.get('kind')
        machine = f.get('machine_id')
        if not store.rows('SELECT id FROM machines WHERE id=?', (machine,)):
            raise ValueError('Select an existing machine.')
        if kind == 'http':
            cfg = {'url': validate_url(f.get('url', '')), 'status': int(f.get('expected_status', 200))}
            if not 100 <= cfg['status'] <= 599:
                raise ValueError('Invalid HTTP status.')
        elif kind in ('process','smb'):
            target=f.get('target','').strip()
            if kind=='process':
                if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}',target) or target.startswith('-'):
                    raise ValueError('Enter a process name or systemd .service unit.')
            elif not target.startswith('/') or len(target)>512 or '\n' in target:
                raise ValueError('Enter the absolute mounted SMB directory on the monitored host.')
            if not store.rows('SELECT id FROM agents WHERE machine_id=? AND revoked=0',(machine,)):
                raise ValueError('Enroll an agent on this host first.')
            cfg={'target':target}
        elif kind == 'ping':
            target=f.get('host','').strip()
            if not target or target.startswith('-') or len(target)>253 or not re.fullmatch(r'[A-Za-z0-9_.:-]+',target):
                raise ValueError('Enter a valid ping IP or hostname.')
            cfg={'host':target}
        elif kind == 'tcp':
            cfg = {'host': f.get('host', '').strip(), 'port': int(f.get('port', 0))}
            if not cfg['host'] or len(cfg['host']) > 253 or not 1 <= cfg['port'] <= 65535:
                raise ValueError('Enter a valid host and port.')
        elif kind == 'proxmox':
            cfg = {'url': validate_url(f.get('url', ''), ('https',)), 'token_id': f.get('token_id', ''), 'token_secret': vault.encrypt(f.get('token_secret', '')), 'resource': f.get('resource', '').strip(), 'expected': f.get('expected', 'running')}
            if not cfg['token_id'] or not f.get('token_secret') or cfg['expected'] not in ('running', 'stopped', 'online', 'offline', 'available'):
                raise ValueError('Provide a read-only token and valid expected state.')
        else:
            raise ValueError('Unsupported check type.')
        interval, fail, recover = int(f.get('interval', 60)), int(f.get('fail_after', 3)), int(f.get('recover_after', 2))
        severity = f.get('severity', 'medium')
        if not (1 if kind=='ping' else 20 if kind in ('process','smb') else 10) <= interval <= 86400 or not 1 <= fail <= 100 or not 1 <= recover <= 100 or severity not in SEVERITIES:
            raise ValueError('Invalid interval, thresholds or severity.')
        name = f.get('name', '').strip()
        if not 1 <= len(name) <= 100:
            raise ValueError('Check name must contain 1–100 characters.')
        with store.connect() as c:
            check_id = uid()
            c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,?,?,?,?,?,?)', (check_id, machine, name, kind, json.dumps(cfg), interval, fail, recover, severity))
            store.audit(c, 'check.created', check_id, {'machine_id': machine, 'kind': kind})
        return redirect(url_for('host_detail',machine_id=machine))

    @app.post('/checks/<check_id>/maintenance')
    @login_required
    def maintenance(check_id):
        minutes = int(request.form.get('minutes', 60))
        if not 0 <= minutes <= 10080:
            raise ValueError('Maintenance must be between 0 and 10080 minutes.')
        with store.connect() as c:
            result = c.execute('UPDATE checks SET maintenance_until=? WHERE id=?', (time.time() + minutes * 60, check_id))
            if not result.rowcount:
                abort(404)
            store.audit(c, 'check.maintenance', check_id, {'minutes': minutes})
        return redirect(url_for('dashboard'))

    @app.get('/incidents/<incident_id>')
    @login_required
    def incident(incident_id):
        rows = store.rows('SELECT * FROM incidents WHERE id=?', (incident_id,))
        if not rows:
            abort(404)
        from .ai import meter
        from .handoff import view
        from .worklog import view as work_view
        from .hostview import detail
        return render_template('incident.html', machine_detail=detail(store,rows[0]['machine_id']),work=work_view(store,incident_id),recovery_drafts=[{**d,'data':json.loads(d['payload'])} for d in store.rows('SELECT d.*,a.proposal_id FROM recovery_drafts d LEFT JOIN draft_adoptions a ON a.job_id=d.job_id WHERE d.incident_id=? ORDER BY d.created DESC LIMIT 100',(incident_id,))], merge_candidates=store.rows("SELECT id,severity,first_seen FROM incidents WHERE machine_id=? AND id<>? AND closed IS NULL AND status<>'Resolved'",(rows[0]['machine_id'],incident_id)), ownership=view(store, incident_id), handoff_request_id=uid(), proposals=[{**p,'data':json.loads(p['payload'])} for p in store.rows('SELECT * FROM action_proposals WHERE incident_id=? ORDER BY created DESC LIMIT 100',(incident_id,))], action_agents=[{**a,'action_services':json.loads(a['capabilities']).get('action_services',{})} for a in store.rows('SELECT * FROM agents WHERE machine_id=? AND revoked=0',(rows[0]['machine_id'],))], automatic_ai_config=store.setting('hermes_config',{}),workspace_request_id=uid(), workspace_messages=store.rows('SELECT m.*,j.state,j.mode FROM ai_messages m JOIN ai_jobs j ON j.id=m.job_id WHERE m.incident_id=? ORDER BY m.created DESC LIMIT 100', (incident_id,)), workspace_sources=store.rows('SELECT s.check_id,c.name FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(incident_id,)), ai_jobs=store.rows('SELECT id,state,mode,execution_mode,model,reasoning_effort,created,summary,error,resolution_summary FROM ai_jobs WHERE incident_id=? ORDER BY created DESC LIMIT 100', (incident_id,)), ai_meter=meter(store, incident_id), incident=rows[0], report=json.loads(rows[0]['report']), timeline=store.rows('SELECT * FROM timeline WHERE incident_id=? ORDER BY at', (incident_id,)), links=store.rows('SELECT * FROM incident_links WHERE left_id=? OR right_id=?',(incident_id,incident_id)), diagnostic_jobs=store.rows('SELECT * FROM diagnostic_jobs WHERE incident_id=? ORDER BY created DESC LIMIT 100',(incident_id,)), diagnostic_agents=[{**a,'caps':json.loads(a['capabilities'])} for a in store.rows('SELECT * FROM agents WHERE machine_id=? AND revoked=0',(rows[0]['machine_id'],))])

    @app.post('/incidents/<incident_id>/archive')
    @login_required
    def archive(incident_id):
        from .administration import archive_incident
        operation=request.form.get('operation')
        if operation not in ('archive','restore'):
            raise ValueError('Unknown archive operation.')
        archive_incident(store,incident_id,restore=operation=='restore')
        return redirect(url_for('incident',incident_id=incident_id))

    @app.get('/incidents/<incident_id>/archive-export')
    @login_required
    def archive_export(incident_id):
        rows=store.rows('SELECT document FROM incident_archives WHERE incident_id=? ORDER BY created DESC LIMIT 1',(incident_id,))
        if not rows: abort(404)
        response=app.response_class(rows[0]['document'],mimetype='application/json')
        response.headers['Content-Disposition']='attachment; filename="aiticket-incident-archive.json"'
        return response

    @app.post('/incidents/<incident_id>/merge')
    @login_required
    def merge_incident(incident_id):
        from .correlation import merge
        if request.form.get('confirm')!='yes':
            raise ValueError('Confirm grouping conditions while retaining original evidence.')
        target=merge(store,request.form.get('source_id'),incident_id,request.form.get('reason',''))
        return redirect(url_for('incident',incident_id=target))

    @app.post('/incidents/<incident_id>/note')
    @login_required
    def note(incident_id):
        text = request.form.get('note', '').strip()
        operation = request.form.get('operation', 'note')
        if not text or len(text) > 4000 or operation not in ('note', 'acknowledge', 'resolve'):
            raise ValueError('Supply a note of 1–4000 characters and a valid operation.')
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
            if not row:
                abort(404)
            store.timeline(c, incident_id, operation, text, actor='user')
            store.audit(c, 'incident.' + operation, incident_id)
            if operation == 'resolve':
                from .handoff import take_control
                take_control(c, store, incident_id)
                # Keep the condition attached; no endless reopening while it is unhealthy.
                report = json.loads(row['report'])
                from .worklog import end,clear
                end(c,incident_id,'hermes','Resolved',time.time(),text)
                end(c,incident_id,'user','Resolved',time.time(),text)
                clear(c,incident_id,time.time())
                report['manual_resolution'] = True
                report['recovery_summary']='Administrator marked resolved: '+text[:1000]
                c.execute("UPDATE incidents SET status='Resolved',report=? WHERE id=?", (json.dumps(report), incident_id))
                if report.get('manual_ticket'):
                    c.execute('UPDATE incidents SET closed=?,last_seen=? WHERE id=?',(time.time(),time.time(),incident_id))
                from .engine import enqueue
                enqueue(c,incident_id,'recovery',time.time(),store)
        return redirect(url_for('incident', incident_id=incident_id))

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        if request.method == 'POST':
            if request.form.get('section') == 'monitoring':
                interval=int(request.form.get('agent_interval','30'))
                if not 20<=interval<=300: raise ValueError('Agent reporting interval must be 20–300 seconds.')
                store.save('agent_interval',interval)
                with store.connect() as c:
                    c.execute("UPDATE checks SET interval=?,next_run=0 WHERE kind IN ('agent','agent_metric')",(interval,))
                    store.audit(c,'monitoring.agent_interval','agents',{'seconds':interval})
                flash('Agent reporting interval saved; updated agents apply it on their next heartbeat.')
                return redirect(url_for('settings'))
            if request.form.get('section') == 'discord':
                from .worklog import public_url
                updates = {'public_url':public_url(request.form.get('public_url',store.setting('public_url',''))),'discord_blockers':bool(request.form.get('blockers'))}
                secret = request.form.get('webhook', '').strip()
                if secret:
                    validate_url(secret, ('https',))
                    p = __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(secret)
                    if p.hostname not in ('discord.com', 'discordapp.com') or not p.path.startswith('/api/webhooks/'):
                        raise ValueError('Use a Discord webhook URL.')
                    updates['discord_secret'] = vault.encrypt(secret)
                minimum = request.form.get('minimum', 'medium')
                if minimum not in SEVERITIES:
                    raise ValueError('Unknown severity.')
                updates.update(discord_minimum=minimum, discord_recovery=bool(request.form.get('recovery')))
                store.save_many(updates, actor='user')
            else:
                cfg = {}
                for key, default in AI_DEFAULTS.items():
                    value = request.form.get(key, str(default))
                    cfg[key] = str(value)[:100] if isinstance(default, str) else type(default)(value)
                    if not isinstance(default, str) and (not math.isfinite(cfg[key]) or not 0 <= cfg[key] <= 1000000000):
                        raise ValueError('Budget values must be nonnegative and bounded.')
                store.save_many({'ai_config': cfg}, actor='user')
            flash('Settings saved. AI activation is managed on the Hermes page.')
            return redirect(url_for('settings'))
        return render_template('settings.html', public_url=store.setting('public_url',''),blockers=store.setting('discord_blockers',True),agent_interval=store.setting('agent_interval',30),ai=store.setting('ai_config', AI_DEFAULTS), discord_configured=bool(store.setting('discord_secret')), minimum=store.setting('discord_minimum', 'medium'), recovery=store.setting('discord_recovery', True), ai_enabled=store.setting('hermes_config', {}).get('enabled', False))


    @app.route('/administration', methods=['GET', 'POST'])
    @login_required
    def administration():
        from .administration import change_password, import_preferences, validate
        if request.method == 'POST':
            operation = request.form.get('operation')
            if operation == 'password':
                if not check_password_hash(store.setting('admin_hash'), request.form.get('current', '')):
                    raise ValueError('Current password is incorrect.')
                password = request.form.get('password', '')
                if password != request.form.get('confirm', ''):
                    raise ValueError('Password confirmation does not match.')
                change_password(store, password)
                session.clear()
                return redirect(url_for('login'))
            elif operation == 'retention':
                values = validate({'retention_days': int(request.form.get('days', '90'))})
                store.save_many(values, actor='user')
            elif operation == 'inventory_import':
                from .inventory import import_inventory
                if request.form.get('confirm')!='yes':
                    raise ValueError('Confirm importing inventory with monitoring disabled for review.')
                try:
                    document=json.loads(request.form.get('document',''))
                except (ValueError,RecursionError):
                    raise ValueError('Provide valid inventory JSON.')
                import_inventory(store,vault,document)
            elif operation == 'import':
                try:
                    document = json.loads(request.form.get('document', ''))
                except (ValueError, RecursionError):
                    raise ValueError('Provide a valid preferences JSON file.')
                import_preferences(store, document)
            else:
                raise ValueError('Unknown administration operation.')
            flash('Administration preferences saved.')
            return redirect(url_for('administration'))
        return render_template('administration.html', days=store.setting('retention_days', 90))

    @app.get('/administration/export')
    @login_required
    def export_preferences():
        from .administration import export_preferences as export
        with store.connect() as c:
            store.audit(c, 'preferences.exported', 'settings')
        response = app.response_class(json.dumps(export(store), indent=2), mimetype='application/json')
        response.headers['Content-Disposition'] = 'attachment; filename="aiticket-preferences.json"'
        return response

    @app.get('/administration/inventory-export')
    @login_required
    def inventory_export():
        from .inventory import export_inventory
        document=export_inventory(store)
        with store.connect() as c:
            store.audit(c,'inventory.exported','inventory')
        response=app.response_class(json.dumps(document,indent=2),mimetype='application/json')
        response.headers['Content-Disposition']='attachment; filename="aiticket-inventory.json"'
        return response

    @app.post('/checks/<check_id>/enabled')
    @login_required
    def check_enabled(check_id):
        enabled=request.form.get('enabled')=='yes'
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM checks WHERE id=?',(check_id,)).fetchone()
            if not row: abort(404)
            if row['kind']=='manual': raise ValueError('Manual tickets cannot be enabled as monitoring checks.')
            cfg=json.loads(row['config'])
            if enabled:
                from .inventory import config,CONFIG
                config(row['kind'],{k:v for k,v in cfg.items() if k in CONFIG[row['kind']]})
                if row['kind']=='proxmox':
                    secret=request.form.get('token_secret','')
                    if secret: cfg['token_secret']=vault.encrypt(secret)
                    if not vault.decrypt(cfg.get('token_secret','')):
                        raise ValueError('Provide the read-only token secret before enabling this imported check.')
                if row['kind'] in ('agent','agent_metric') and not c.execute('SELECT 1 FROM agents WHERE id=? AND machine_id=? AND revoked=0',(cfg['agent_id'],row['machine_id'])).fetchone():
                    raise ValueError('Enroll this agent before enabling its checks.')
                if row['kind']=='proxmox_linked':
                    obj=c.execute('SELECT * FROM proxmox_objects WHERE id=? AND present=1 AND template=0 AND machine_id=? AND check_id=?',(cfg['object_id'],row['machine_id'],check_id)).fetchone()
                    credentials=c.execute('SELECT token_secret FROM proxmox_connections WHERE cluster_id=?',(cfg['cluster_id'],)).fetchall()
                    if not obj or not any(vault.decrypt(r[0]) for r in credentials):
                        raise ValueError('Review the source identity and restore a read-only connection credential first.')
            c.execute('UPDATE checks SET enabled=?,config=?,lease_token=NULL,lease_until=NULL,next_run=0 WHERE id=?',(int(enabled),json.dumps(cfg),check_id))
            store.audit(c,'check.enabled' if enabled else 'check.disabled',check_id)
        return redirect(url_for('hosts'))

    @app.post('/agents/<agent_id>/rotate')
    @login_required
    def rotate_agent(agent_id):
        token = secrets.token_urlsafe(32)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            agent = c.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not agent:
                abort(404)
            c.execute('UPDATE agents SET revoked=1,action_credential_digest=NULL WHERE id=?', (agent_id,))
            c.execute('UPDATE enrollments SET used=? WHERE machine_id=? AND used IS NULL', (time.time(), agent['machine_id']))
            c.execute("UPDATE diagnostic_jobs SET state='expired',lease_until=NULL,lease_token=NULL WHERE agent_id=? AND state IN ('pending','leased')", (agent_id,))
            c.execute('INSERT INTO enrollments VALUES(?,?,?,NULL)', (digest(token), agent['machine_id'], time.time()+600))
            store.audit(c, 'agent.rotation_requested', agent_id)
        return render_template('enrollment.html', token=token)

    @app.get('/history')
    @login_required
    def history():
        clauses, params = [], []
        filters = {key: request.args.get(key, '') for key in ('machine', 'severity', 'status', 'from', 'to','archived')}
        if filters['archived'] not in ('','only','all'):
            raise ValueError('Invalid archive filter.')
        if filters['archived']!='all':
            clauses.append('i.archived_at IS NOT NULL' if filters['archived']=='only' else 'i.archived_at IS NULL')
        page = int(request.args.get('page', 1))
        if not 1 <= page <= 100000:
            raise ValueError('Invalid page.')
        if filters['machine']:
            clauses.append('i.machine_id=?')
            params.append(filters['machine'])
        if filters['severity']:
            if filters['severity'] not in SEVERITIES:
                raise ValueError('Invalid severity.')
            clauses.append('i.severity=?')
            params.append(filters['severity'])
        statuses = ['Open', 'Investigating', 'Awaiting approval', 'Needs user intervention', 'Monitoring recovery', 'Resolved']
        if filters['status']:
            if filters['status'] not in statuses:
                raise ValueError('Invalid status.')
            clauses.append('i.status=?')
            params.append(filters['status'])
        dates = {}
        for key in ('from', 'to'):
            if filters[key]:
                dates[key] = datetime.strptime(filters[key], '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp()
        if 'from' in dates and 'to' in dates and dates['from'] > dates['to']:
            raise ValueError('Start date must precede end date.')
        if 'from' in dates:
            clauses.append('i.first_seen>=?')
            params.append(dates['from'])
        if 'to' in dates:
            clauses.append('i.first_seen<?')
            params.append(dates['to'] + 86400)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        total = store.rows('SELECT count(*) AS total FROM incidents i' + where, params)[0]['total']
        rows = store.rows('SELECT i.*,m.name AS machine FROM incidents i JOIN machines m ON m.id=i.machine_id' + where + ' ORDER BY i.first_seen DESC,i.id LIMIT 50 OFFSET ?', params + [(page - 1) * 50])
        links = {key: value for key, value in filters.items() if value}
        return render_template('history.html', incidents=rows, filters=filters, statuses=statuses,
                               machines=store.rows('SELECT * FROM machines ORDER BY name'), page=page, total=total,
                               previous=url_for('history', **links, page=page-1) if page>1 else None,
                               following=url_for('history', **links, page=page+1) if page*50<total else None)

    @app.get('/audit')
    @login_required
    def audit_log():
        page = int(request.args.get('page', 1))
        if not 1 <= page <= 100000:
            raise ValueError('Invalid page.')
        rows = store.rows('SELECT * FROM audit ORDER BY at DESC,id LIMIT 51 OFFSET ?', ((page-1)*50,))
        return render_template('audit.html', entries=rows[:50], page=page, more=len(rows)>50)

    @app.get('/queue')
    @login_required
    def queue():
        return render_template('queue.html', jobs=store.rows('SELECT * FROM deliveries ORDER BY created DESC LIMIT 200'))

    @app.post('/queue/<job_id>/retry')
    @login_required
    def retry(job_id):
        with store.connect() as c:
            result = c.execute("UPDATE deliveries SET state='pending',next_attempt=?,expires=?,last_error=NULL WHERE id=? AND state IN ('failed','expired','pending')", (time.time(), time.time() + 86400, job_id))
            if not result.rowcount:
                abort(409)
            store.audit(c, 'delivery.retry_requested', job_id)
        return redirect(url_for('queue'))

    @app.post('/enrollments')
    @login_required
    def enrollment():
        machine = request.form.get('machine_id')
        if not store.rows('SELECT id FROM machines WHERE id=?', (machine,)):
            raise ValueError('Unknown machine.')
        token = secrets.token_urlsafe(32)
        with store.connect() as c:
            c.execute('INSERT INTO enrollments VALUES(?,?,?,NULL)', (digest(token), machine, time.time() + 600))
            store.audit(c, 'agent.enrollment_issued', machine, {'ttl_seconds': 600})
        return render_template('enrollment.html', token=token)

    @app.post('/agents/<agent_id>/revoke')
    @login_required
    def revoke(agent_id):
        with store.connect() as c:
            result = c.execute('UPDATE agents SET revoked=1,action_credential_digest=NULL WHERE id=?', (agent_id,))
            if not result.rowcount:
                abort(404)
            store.audit(c, 'agent.revoked', agent_id)
        return redirect(url_for('hosts'))

    @app.post('/api/agent/enroll')
    def enroll_api():
        payload = request.get_json() or {}
        if not isinstance(payload, dict):
            abort(400)
        token = payload.get('token', '')
        if not isinstance(token, str):
            abort(400)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT * FROM enrollments WHERE digest=? AND used IS NULL AND expires>?', (digest(token), time.time())).fetchone()
            if not row:
                abort(401)
            existing = c.execute('SELECT * FROM agents WHERE machine_id=?', (row['machine_id'],)).fetchone()
            if existing and not existing['revoked']:
                abort(409)
            credential, agent_id = secrets.token_urlsafe(48), existing['id'] if existing else uid()
            if existing:
                c.execute('UPDATE agents SET credential_digest=?,revoked=0,action_credential_digest=NULL WHERE id=?', (digest(credential), agent_id))
            else:
                c.execute('INSERT INTO agents(id,machine_id,credential_digest) VALUES(?,?,?)', (agent_id, row['machine_id'], digest(credential)))
                c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES(?,?,?,?,?,?)', (uid(), row['machine_id'], 'Agent heartbeat', 'agent', json.dumps({'agent_id': agent_id, 'max_age': 180}), store.setting('agent_interval',30)))
            c.execute('UPDATE enrollments SET used=? WHERE digest=?', (time.time(), row['digest']))
            store.audit(c, 'agent.reenrolled' if existing else 'agent.enrolled', agent_id, {'machine_id': row['machine_id']}, actor='agent')
        return {'agent_id': agent_id, 'credential': credential}

    @app.post('/api/agent/heartbeat')
    def heartbeat():
        from .power import poll as power_poll
        bearer = request.headers.get('Authorization', '')
        if not bearer.startswith('Bearer '):
            abort(401)
        payload = request.get_json() or {}
        if not isinstance(payload, dict):
            abort(400)
        event = payload.get('event_id')
        if not isinstance(event, str) or not 1 <= len(event) <= 100:
            abort(400)
        # Only numeric, bounded telemetry is accepted; no logs or arbitrary text.
        telemetry = payload.get('telemetry', {})
        allowed = {'uptime_seconds', 'load_1', 'memory_available_bytes', 'memory_total_bytes', 'disk_free_bytes', 'disk_total_bytes', 'inode_free', 'inode_total', 'cpu_percent', 'memory_pressure_percent','load_5','load_15','cpu_cores','swap_total_bytes','swap_free_bytes'}
        if not isinstance(telemetry, dict) or set(telemetry) - allowed or any(type(v) not in (float, int) or (not math.isfinite(v) or not 0 <= v <= 1e18) for v in telemetry.values()):
            abort(400)
        if any(telemetry.get(key,0)>100 for key in ('cpu_percent','memory_pressure_percent')):
            abort(400)
        for free,total in (('memory_available_bytes','memory_total_bytes'),('disk_free_bytes','disk_total_bytes'),('inode_free','inode_total'),('swap_free_bytes','swap_total_bytes')):
            if free in telemetry and total in telemetry and telemetry[free]>telemetry[total]:
                abort(400)
        host_info=payload.get('host_info',{})
        if not isinstance(host_info,dict) or set(host_info)-{'hostname','os','kernel','architecture'} or any(not isinstance(v,str) or len(v)>200 for v in host_info.values()):
            abort(400)
        capabilities=payload.get('capabilities',{})
        if not isinstance(capabilities,dict) or set(capabilities)-{'operations','services','actions','action_services','power_operations','shell_commands'} or any(not isinstance(capabilities.get(k,[]),list) for k in ('operations','services')):
            abort(400)
        if len(capabilities.get('operations',[]))>3 or any(x not in ('process_summary','service_status','service_logs') for x in capabilities.get('operations',[])) or len(capabilities.get('services',[]))>20 or any(not isinstance(x,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',x) for x in capabilities.get('services',[])):
            abort(400)
        if type(capabilities.get('shell_commands',False)) is not bool: abort(400)
        power_operations=capabilities.get('power_operations',[])
        if not isinstance(power_operations,list) or len(power_operations)>2 or any(op not in ('host_restart','host_shutdown') for op in power_operations):
            abort(400)
        actions=capabilities.get('actions',[])
        action_services=capabilities.get('action_services',{})
        if not isinstance(actions,list) or any(a!='service_restart' for a in actions) or len(actions)>1 or not isinstance(action_services,dict) or len(action_services)>20 or any(not isinstance(k,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',k) or not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}\.service',v) or v.startswith('-') for k,v in action_services.items()):
            abort(400)
        sampled_at=payload.get('sampled_at')
        if sampled_at is not None and (type(sampled_at) not in (float,int) or not math.isfinite(sampled_at) or sampled_at<0):
            abort(400)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT * FROM agents WHERE credential_digest=? AND revoked=0', (digest(bearer[7:]),)).fetchone()
            if not row:
                abort(401)
            if c.execute('SELECT 1 FROM agent_events WHERE agent_id=? AND event_id=?', (row['id'], event)).fetchone():
                from .diagnostics import poll
                from .actions import poll as action_poll
                from .commands import poll as command_poll
                return {'poll_interval_seconds':store.setting('agent_interval',30),'commands':command_poll(c,store,vault,row['id'],time.time()),'status': 'duplicate', 'jobs': poll(c,row['id'],time.time()), 'actions': action_poll(c,store,row['id'],time.time()) or power_poll(c,store,row['id'],time.time())}
            now = time.time()
            c.execute('UPDATE agents SET host_info=? WHERE id=?',(json.dumps(host_info),row['id']))
            c.execute('INSERT INTO agent_events VALUES(?,?,?)', (row['id'], event, now))
            c.execute('DELETE FROM agent_events WHERE at<?', (now - 604800,))
            c.execute('UPDATE agents SET last_seen=?,address=?,version=?,telemetry=?,capabilities=?,sampled_at=? WHERE id=?', (now, request.remote_addr, str(payload.get('version', ''))[:32], json.dumps(telemetry), json.dumps(capabilities),sampled_at,row['id']))
            from .metric_history import record
            record(c,row['machine_id'],'agent',sampled_at or now,telemetry)
            from .diagnostics import poll
            jobs=poll(c,row['id'],now)
            from .actions import poll as action_poll
            actions=action_poll(c,store,row['id'],now) or power_poll(c,store,row['id'],now)
            from .commands import poll as command_poll
            commands=command_poll(c,store,vault,row['id'],now)
        return {'poll_interval_seconds':store.setting('agent_interval',30),'status': 'accepted', 'jobs': jobs, 'actions': actions,'commands':commands}

    @app.post('/api/agent/checks')
    def agent_checks():
        bearer=request.headers.get('Authorization','')
        rows=store.rows('SELECT * FROM agents WHERE credential_digest=? AND revoked=0',(digest(bearer[7:]) if bearer.startswith('Bearer ') else '',))
        if not rows: abort(401)
        machine=rows[0]['machine_id']
        payload=request.get_json() or {}
        results=payload.get('results',[])
        if not isinstance(results,list) or len(results)>20: abort(400)
        from .engine import observe
        for result in results:
            if not isinstance(result,dict) or type(result.get('healthy')) is not bool: abort(400)
            checks=store.rows("SELECT * FROM checks WHERE id=? AND machine_id=? AND enabled=1 AND kind IN ('process','smb')",(result.get('id'),machine))
            if not checks: continue
            check=checks[0]
            sampled=result.get('sampled_at')
            if type(sampled) not in (int,float) or not math.isfinite(sampled) or not 0<=time.time()-sampled<=180: continue
            previous=store.rows('SELECT evidence FROM observations WHERE check_id=? ORDER BY at DESC LIMIT 1',(check['id'],))
            if previous and json.loads(previous[0]['evidence']).get('sampled_at',0)>=sampled: continue
            if result.get('config')!=json.loads(check['config']) or check['next_run']>time.time(): continue
            observe(store,check['id'],result['healthy'],{'target':result['config']['target'],'reason':'Agent check passed' if result['healthy'] else 'Agent check failed','sampled_at':sampled})
        return {'checks':[{'id':r['id'],'kind':r['kind'],'config':json.loads(r['config'])} for r in store.rows("SELECT * FROM checks WHERE machine_id=? AND enabled=1 AND kind IN ('process','smb') AND next_run<=? ORDER BY next_run,id LIMIT 20",(machine,time.time()))]}

    @app.route('/proxmox', methods=['GET','POST'])
    @login_required
    def proxmox_inventory():
        from .proxmox import Client, discover, link, unlink, schedule
        if request.method == 'POST':
            f=request.form
            operation=f.get('operation')
            if operation=='connection':
                name=f.get('name','').strip()
                cluster=f.get('cluster_id','')
                cluster_name=f.get('cluster_name','').strip()
                url=validate_url(f.get('url','').rstrip('/'),('https',))
                token_id=f.get('token_id','').strip()
                secret=f.get('token_secret','')
                if not 1<=len(name)<=100 or not token_id or not secret or (not cluster and not 1<=len(cluster_name)<=100):
                    raise ValueError('Supply a connection name, cluster namespace and read-only credentials.')
                ca=f.get('ca','').strip() or None
                if ca and (not Path(ca).is_absolute() or not Path(ca).is_file()):
                    raise ValueError('CA must be an existing absolute path on the application server.')
                with store.connect() as c:
                    c.execute('BEGIN IMMEDIATE')
                    if c.execute('SELECT 1 FROM proxmox_connections WHERE url=?',(url,)).fetchone():
                        raise ValueError('Endpoint is already configured.')
                    if cluster:
                        if not c.execute('SELECT 1 FROM proxmox_clusters WHERE id=?',(cluster,)).fetchone():
                            raise ValueError('Unknown cluster namespace.')
                    else:
                        cluster=uid()
                        c.execute('INSERT INTO proxmox_clusters VALUES(?,?)',(cluster,cluster_name))
                    connection_id=uid()
                    c.execute('INSERT INTO proxmox_connections VALUES(?,?,?,?,?,?,?,NULL,NULL)',(connection_id,cluster,name,url,token_id,vault.encrypt(secret),ca))
                    store.audit(c,'proxmox.connection_created',connection_id,{'cluster_id':cluster})
            elif operation=='credentials':
                identifier=f.get('connection_id')
                secret=f.get('token_secret','')
                ca=f.get('ca','').strip() or None
                if not 1<=len(secret)<=2048 or (ca and (not Path(ca).is_absolute() or not Path(ca).is_file())):
                    raise ValueError('Supply a read-only secret and an optional existing absolute CA path.')
                with store.connect() as c:
                    changed=c.execute('UPDATE proxmox_connections SET token_secret=?,ca=?,last_test=NULL WHERE id=?',(vault.encrypt(secret),ca,identifier))
                    if not changed.rowcount: abort(404)
                    store.audit(c,'proxmox.credentials_replaced',identifier)
            elif operation=='schedule':
                schedule(store,f.get('connection_id'),int(f.get('interval','0')))
            elif operation in ('test','discover'):
                connection_id=f.get('connection_id')
                rows=store.rows('SELECT * FROM proxmox_connections WHERE id=?',(connection_id,))
                if not rows:
                    abort(404)
                if operation=='test':
                    results=Client(rows[0],vault).test()
                    with store.connect() as c:
                        c.execute('UPDATE proxmox_connections SET last_test=? WHERE id=?',(json.dumps(results),connection_id))
                        store.audit(c,'proxmox.connection_tested',connection_id)
                else:
                    try:
                        count=discover(store,vault,connection_id)
                    except Exception as exc:
                        flash('Discovery failed: '+type(exc).__name__+'. Review reachability, trust and token permissions.')
                    else:
                        flash(str(count)+' visible resources refreshed. Linking requires confirmation.')
            elif operation=='link':
                if f.get('confirm')!='yes':
                    raise ValueError('Confirm the exact machine/resource link.')
                create_name=f.get('create_name','').strip() or None
                if create_name and len(create_name)>100:
                    raise ValueError('Machine name exceeds 100 characters.')
                if create_name and f.get('machine_id'):
                    raise ValueError('Select an existing machine OR create a new one.')
                link(store,f.get('object_id'),f.get('machine_id'),f.get('expected'),create_name)
            elif operation in ('unlink','retire'):
                if f.get('confirm')!='yes':
                    raise ValueError('Confirm unlinking or retirement; history will be preserved.')
                unlink(store,f.get('object_id'),retire=operation=='retire')
            else:
                raise ValueError('Unknown inventory operation.')
            return redirect(url_for('proxmox_inventory'))
        connections=store.rows('SELECT p.id,p.cluster_id,p.name,p.url,p.ca,p.last_test,p.last_discovery,s.interval,s.next_run,s.last_error FROM proxmox_connections p LEFT JOIN discovery_schedules s ON s.connection_id=p.id ORDER BY p.name')
        for connection in connections:
            connection['test']=json.loads(connection['last_test']) if connection['last_test'] else None
        return render_template('proxmox.html',connections=connections,
            clusters=store.rows('SELECT * FROM proxmox_clusters ORDER BY name'),
            objects=store.rows('SELECT o.*,m.name AS machine FROM proxmox_objects o LEFT JOIN machines m ON m.id=o.machine_id ORDER BY o.cluster_id,o.kind,o.object_key,o.generation'),
            machines=store.rows('SELECT * FROM machines ORDER BY name'))

    @app.post('/api/agent/result')
    def diagnostic_result():
        from .diagnostics import complete
        bearer=request.headers.get('Authorization','')
        if not bearer.startswith('Bearer '):
            abort(401)
        agents=store.rows('SELECT id FROM agents WHERE credential_digest=? AND revoked=0',(digest(bearer[7:]),))
        if not agents:
            abort(401)
        return {'status':complete(store,agents[0]['id'],request.get_json())}

    @app.post('/incidents/<incident_id>/diagnostics')
    @login_required
    def request_diagnostic(incident_id):
        from .diagnostics import request_job
        request_job(store,request.form.get('agent_id'),incident_id,request.form.get('operation'),request.form.get('service_id'))
        return redirect(url_for('incident',incident_id=incident_id))

    @app.route('/resources',methods=['GET','POST'])
    @login_required
    def resource_rules():
        from .diagnostics import METRICS
        if request.method=='POST':
            f=request.form
            agents=store.rows('SELECT * FROM agents WHERE id=? AND revoked=0',(f.get('agent_id'),))
            if not agents or f.get('metric') not in METRICS:
                raise ValueError('Choose an enrolled agent and supported resource metric.')
            fail,recover=float(f.get('fail_above',90)),float(f.get('recover_below',80))
            duration=int(f.get('sustain_seconds',120))
            if not 0<=recover<fail<=100 or not 30<=duration<=86400:
                raise ValueError('Thresholds must satisfy 0 ≤ recovery < failure ≤ 100; duration 30–86400 seconds.')
            config={'agent_id':agents[0]['id'],'metric':f['metric'],'fail_above':fail,'recover_below':recover,'sustain_seconds':duration}
            with store.connect() as c:
                check_id=uid()
                c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after) VALUES(?,?,?,?,?,?,1,2)',(check_id,agents[0]['machine_id'],f['metric'],'agent_metric',json.dumps(config),store.setting('agent_interval',30)))
                store.audit(c,'resource_rule.created',check_id,{'metric':f['metric']})
            return redirect(url_for('resource_rules'))
        return render_template('resources.html',metrics=METRICS,agents=store.rows('SELECT a.id,m.name,a.capabilities FROM agents a JOIN machines m ON m.id=a.machine_id WHERE revoked=0'),rules=store.rows("SELECT c.name,c.config,m.name AS machine FROM checks c JOIN machines m ON m.id=c.machine_id WHERE kind='agent_metric'"))

    @app.route('/policies',methods=['GET','POST'])
    @login_required
    def maintenance_policies():
        from .policies import add_window,DEFAULTS,active,override,group_create,group_assign,effective
        if request.method=='POST':
            f=request.form
            if f.get('operation')=='window':
                add_window(store,f.get('name','').strip(),f.get('machine_id') or None,f.get('kind'),f.get('timezone','UTC'),f)
            elif f.get('operation')=='toggle':
                enabled=int(f.get('enabled',1))
                if enabled not in (0,1):
                    raise ValueError('Invalid enabled state.')
                with store.connect() as c:
                    result=c.execute('UPDATE maintenance_windows SET enabled=? WHERE id=?',(enabled,f.get('window_id')))
                    if not result.rowcount:
                        abort(404)
                    store.audit(c,'maintenance.enabled' if enabled else 'maintenance.disabled',f.get('window_id'))
            elif f.get('operation')=='group':
                group_create(store,f.get('name',''))
            elif f.get('operation')=='membership':
                group_assign(store,f.get('machine_id'),f.get('group_id') or None)
            elif f.get('operation') in ('override','inherit'):
                values=None
                if f['operation']=='override':
                    values={'enabled':f.get('enabled')=='yes','minimum':f.get('minimum','medium'),'recovery':f.get('recovery')=='yes','reminder_seconds':int(f.get('reminder_seconds','0')),'escalate_after_seconds':int(f.get('escalate_after_seconds','0')),'escalate_to':f.get('escalate_to','high')}
                override(store,f.get('scope_kind'),f.get('scope_id'),values)
            elif f.get('operation')=='notifications':
                reminder=int(f.get('reminder_seconds',0))
                delay=int(f.get('escalate_after_seconds',0))
                severity=f.get('escalate_to','high')
                if any(x!=0 and not 60<=x<=2592000 for x in (reminder,delay)) or severity not in SEVERITIES:
                    raise ValueError('Intervals must be zero (disabled) or 60–2592000 seconds; select a valid severity.')
                store.save_many({'notification_policy':{'reminder_seconds':reminder,'escalate_after_seconds':delay,'escalate_to':severity}},actor='user')
            else:
                raise ValueError('Unknown policy operation.')
            return redirect(url_for('maintenance_policies'))
        windows=store.rows('SELECT w.*,m.name AS machine FROM maintenance_windows w LEFT JOIN machines m ON m.id=w.machine_id ORDER BY w.name')
        for window in windows:
            window['active_now']=active(window,time.time())
        with store.connect() as c:
            effective_policies=[{**dict(m),'policy':effective(c,m['id'])} for m in c.execute('SELECT * FROM machines ORDER BY name').fetchall()]
        return render_template('policies.html',groups=store.rows('SELECT * FROM notification_groups ORDER BY name'),overrides=[{**r,'data':json.loads(r['policy'])} for r in store.rows('SELECT * FROM notification_overrides')],effective_policies=effective_policies,windows=windows,machines=store.rows('SELECT * FROM machines ORDER BY name'),policy=store.setting('notification_policy',DEFAULTS))

    @app.post('/incidents/<incident_id>/silence')
    @login_required
    def silence_incident(incident_id):
        minutes=int(request.form.get('minutes',60))
        if not 0<=minutes<=10080:
            raise ValueError('Silence must be 0–10080 minutes; zero resumes delivery.')
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            result=c.execute('UPDATE incidents SET silence_until=? WHERE id=?',(time.time()+minutes*60,incident_id))
            if not result.rowcount:
                abort(404)
            store.timeline(c,incident_id,'silenced' if minutes else 'notifications_resumed','Notification pause: '+str(minutes)+' minutes.',actor='user')
            store.audit(c,'incident.silence_changed',incident_id,{'minutes':minutes})
        return redirect(url_for('incident',incident_id=incident_id))

    @app.route('/hermes', methods=['GET', 'POST'])
    @login_required
    def hermes():
        from .ai import BRIDGE_DEFAULTS, PROVIDER_DEFAULTS, meter, valid_configuration
        bridge = store.setting('hermes_config', BRIDGE_DEFAULTS)
        provider = store.setting('ai_provider', PROVIDER_DEFAULTS)
        if request.method == 'POST':
            f = request.form
            if f.get('operation') == 'disable':
                bridge = {**bridge, 'enabled': False}
                store.save_many({'hermes_config': bridge}, actor='user')
            elif f.get('operation') == 'save':
                bridge = {'url': validate_url(f.get('url', '').strip(), ('https',)).rstrip('/'), 'ca': f.get('bridge_ca', '').strip(), 'enabled': False, 'automatic': bool(f.get('automatic')), 'minimum': f.get('minimum', 'high'), 'runtime_verified': bool(f.get('runtime_verified'))}
                mode=f.get('execution_mode','gateway')
                if mode not in ('gateway','codex'): raise ValueError('Unknown AI execution mode.')
                bridge['execution_mode']=mode
                bridge['command_tools']=f.get('command_tools')=='yes'
                if bridge['command_tools'] and mode!='codex': raise ValueError('Operational command tools require Codex mode.')
                if mode=='codex':
                    from .codex_mode import options
                    bridge.update(options({'reasoning':f.get('reasoning','low'),**{k:int(f.get(k,v)) for k,v in [('incident_runs',3),('daily_runs',10),('monthly_runs',100),('timeout_seconds',90)]}}))
                provider = {'url': validate_url(f.get('provider_url', '').strip(), ('https',)).rstrip('/') if mode=='gateway' else provider.get('url',''), 'ca': f.get('provider_ca', '').strip(), 'verified': bool(f.get('provider_verified')), 'input_overhead': int(f.get('input_overhead', 8192)), 'output_tokens': int(f.get('output_tokens', 1000)), 'verified_model': store.setting('ai_config', {}).get('model', '')}
                if bridge['minimum'] not in SEVERITIES or not 0 <= provider['input_overhead'] <= 1000000 or not 1 <= provider['output_tokens'] <= 100000:
                    raise ValueError('Invalid severity or provider bounds.')
                updates = {'hermes_config': bridge, 'ai_provider': provider, 'hermes_validation': None}
                if mode=='codex':
                    model=f.get('codex_model','').strip()
                    if not 1<=len(model)<=100: raise ValueError('Supply the exact Codex model ID.')
                    updates['ai_config']={**AI_DEFAULTS,**store.setting('ai_config',{}),'model':model}
                for field, key in (('secret', 'hermes_secret'), ('provider_secret', 'ai_provider_secret')):
                    value = f.get(field, '').strip()
                    if value:
                        if not 16 <= len(value) <= 2048:
                            raise ValueError('Credentials must contain 16–2048 characters.')
                        updates[key] = vault.encrypt(value)
                store.save_many(updates, actor='user')
            elif f.get('operation') == 'test':
                from .ai import bridge_request
                secret = store.setting('hermes_secret')
                if not secret:
                    raise ValueError('Save bridge credentials first.')
                try:
                    result = bridge_request(vault, {'id': uid(), 'endpoint': bridge['url'], 'bridge_secret': secret}, 'GET', '/v1/capabilities', ca=bridge.get('ca'))
                except Exception:
                    raise ValueError('Bridge check failed. Review reachability, TLS, authentication and installed compatibility.')
                if result.get('version') != 1 or result.get('tools') != (['aiticket_host'] if bridge.get('command_tools') else []) or result.get('model_gateway') is not (bridge.get('execution_mode','gateway')=='gateway') or result.get('execution_mode','gateway')!=bridge.get('execution_mode','gateway') or result.get('compatible') is not True:
                    raise ValueError('Bridge reports an incompatible or unrestricted Hermes adapter.')
                store.save_many({'hermes_validation': {'at': time.time(), 'url': bridge['url'], 'execution_mode':bridge.get('execution_mode','gateway'), 'workspace_modes': [m for m in ('advice', 'exploration','recovery_proposal') if m in result.get('workspace_modes', [])]}}, actor='user')
                flash('Signed bridge compatibility check passed. No model request was made.')
            elif f.get('operation') == 'enable':
                validation = store.setting('hermes_validation') or {}
                if validation.get('url') != bridge['url'] or time.time()-validation.get('at', 0)>86400:
                    raise ValueError('Run a recent bridge compatibility check before enabling.')
                bridge = {**bridge, 'enabled': True}
                valid_configuration(store.setting('ai_config', {}), bridge, provider, mode='advice')
                if bridge.get('execution_mode','gateway')=='gateway' and not store.setting('ai_provider_secret'):
                    raise ValueError('Save model-provider credentials first.')
                store.save_many({'hermes_config': bridge}, actor='user')
            else:
                raise ValueError('Unknown Hermes settings operation.')
            return redirect(url_for('hermes'))
        return render_template('hermes.html', codex_model=store.setting('ai_config',{}).get('model',''), codex_runs=store.rows("SELECT state,count(*) count FROM ai_jobs WHERE execution_mode='codex' GROUP BY state"), bridge=bridge, provider=provider, usage=meter(store), validation=store.setting('hermes_validation'), configured=bool(store.setting('hermes_secret')), provider_configured=bool(store.setting('ai_provider_secret')), held_calls=store.rows("SELECT id,job_id,created,input_reserved,output_reserved,cost_reserved FROM ai_calls WHERE state!='known' ORDER BY created LIMIT 100"), ai_jobs=store.rows('SELECT id,incident_id,execution_mode,model,reasoning_effort,state,error FROM ai_jobs ORDER BY created DESC LIMIT 100'))

    @app.post('/incidents/<incident_id>/ai')
    @login_required
    def investigate(incident_id):
        from .ai import request_job
        request_job(store, vault, incident_id)
        return redirect(url_for('incident', incident_id=incident_id))

    @app.route('/recovery-policy', methods=['GET','POST'])
    @login_required
    def recovery_policy():
        from .actions import DEFAULTS
        cfg=store.setting('action_policy',DEFAULTS)
        if request.method=='POST':
            f=request.form
            if f.get('operation')=='disable':
                store.save_many({'action_policy':{**cfg,'enabled':False}},actor='user')
            elif f.get('operation')=='target':
                if f.get('confirm_application')!='yes':
                    raise ValueError('Explicitly confirm this is an application machine outside protected infrastructure.')
                machine=f.get('machine_id')
                services=f.get('services','').split()
                if not 1<=len(services)<=20 or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',s) for s in services):
                    raise ValueError('Choose 1–20 local service aliases.')
                with store.connect() as c:
                    c.execute('BEGIN IMMEDIATE')
                    if not c.execute('SELECT 1 FROM machines WHERE id=?',(machine,)).fetchone() or c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND kind IN ('node','storage')",(machine,)).fetchone():
                        raise ValueError('Unknown or protected infrastructure target.')
                    c.execute("UPDATE machines SET recovery_role='application' WHERE id=?",(machine,))
                    targets={**cfg.get('targets',{}),machine:services}
                    updated={**cfg,'targets':targets,'enabled':False,'validated':False}
                    c.execute("INSERT INTO settings VALUES('action_policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(updated),))
                    store.audit(c,'action.target_configured',machine,{'service_aliases':services})
            elif f.get('operation')=='enable':
                if f.get('validated')!='yes' or not cfg.get('targets'):
                    raise ValueError('Validate the target capability and permission with a bounded live test before enabling.')
                store.save_many({'action_policy':{**cfg,'enabled':True,'validated':True}},actor='user')
            else:
                raise ValueError('Unknown recovery policy operation.')
            return redirect(url_for('recovery_policy'))
        return render_template('recovery-policy.html',policy=cfg,machines=store.rows('SELECT id,name,recovery_role FROM machines ORDER BY name'), agents=store.rows("SELECT a.id,m.name FROM agents a JOIN machines m ON m.id=a.machine_id WHERE a.revoked=0 AND m.recovery_role='application'"))

    @app.post('/agents/<agent_id>/action-credential')
    @login_required
    def action_credential(agent_id):
        credential=secrets.token_urlsafe(48)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute("SELECT a.id FROM agents a JOIN machines m ON m.id=a.machine_id WHERE a.id=? AND a.revoked=0 AND m.recovery_role='application'",(agent_id,)).fetchone()
            if not row: raise ValueError('Configure an eligible application agent before issuing an action credential.')
            c.execute('UPDATE agents SET action_credential_digest=? WHERE id=?',(digest(credential),agent_id))
            store.audit(c,'action.credential_rotated',agent_id)
        return render_template('action-credential.html',credential=credential)

    @app.post('/incidents/<incident_id>/recovery-draft')
    @login_required
    def request_recovery_draft(incident_id):
        from .recovery_drafts import request_draft
        request_draft(store,vault,incident_id,request.form.get('agent_id'),request.form.get('service_id'),request.form.get('diagnostic_id'),request.form.get('request_id'))
        return redirect(url_for('incident',incident_id=incident_id))

    @app.post('/incidents/<incident_id>/recovery-draft/<job_id>/adopt')
    @login_required
    def adopt_recovery_draft(incident_id,job_id):
        from .recovery_drafts import adopt
        if request.form.get('reviewed')!='yes':
            raise ValueError('Review the unverified AI draft before creating an approval-required proposal.')
        adopt(store,incident_id,job_id)
        return redirect(url_for('incident',incident_id=incident_id))

    @app.post('/incidents/<incident_id>/proposals')
    @login_required
    def action_propose(incident_id):
        from .actions import propose
        f=request.form
        propose(store,incident_id,f.get('agent_id'),f.get('service_id'),f.get('diagnostic_id'),f.get('rationale',''),f.get('impact',''),f.get('risk',''),f.get('alternatives',''),parent_id=f.get('parent_id') or None)
        return redirect(url_for('incident',incident_id=incident_id))

    @app.post('/proposals/<proposal_id>/decide')
    @login_required
    def action_decide(proposal_id):
        from .actions import decide
        decide(store,proposal_id,request.form.get('payload_hash'),request.form.get('decision'))
        rows=store.rows('SELECT incident_id FROM action_proposals WHERE id=?',(proposal_id,))
        return redirect(url_for('incident',incident_id=rows[0]['incident_id']))

    def action_agent():
        bearer=request.headers.get('Authorization','')
        if not bearer.startswith('Bearer '): abort(401)
        rows=store.rows('SELECT id FROM agents WHERE action_credential_digest=? AND revoked=0',(digest(bearer[7:]),))
        if not rows: abort(401)
        return rows[0]['id']

    @app.post('/api/agent/action-authorize')
    def action_authorize():
        from .actions import authorize
        payload=request.get_json()
        if not isinstance(payload,dict): raise ValueError('Invalid action envelope.')
        agent_id=action_agent()
        if store.rows('SELECT id FROM power_jobs WHERE id=?',(payload.get('id'),)):
            from .power import authorize as power_authorize
            return power_authorize(store,agent_id,payload)
        return authorize(store,agent_id,payload)

    @app.post('/api/agent/action-result')
    def action_result():
        from .actions import complete
        agent_id=action_agent();payload=request.get_json()
        if isinstance(payload,dict) and store.rows('SELECT id FROM power_jobs WHERE id=?',(payload.get('id'),)):
            from .power import complete as power_complete
            return {'status':power_complete(store,agent_id,payload)}
        return {'status':complete(store,agent_id,payload)}

    @app.post('/incidents/<incident_id>/work')
    @login_required
    def human_work(incident_id):
        from .worklog import start,end
        operation=request.form.get('operation')
        if operation not in ('start','stop'): raise ValueError('Unknown work operation.')
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT status FROM incidents WHERE id=?',(incident_id,)).fetchone()
            if not row: abort(404)
            if operation=='start':
                if row['status']=='Resolved': raise ValueError('This ticket is already resolved.')
                start(c,incident_id,'user',time.time())
            else: end(c,incident_id,'user','Session complete',time.time())
        return redirect(url_for('incident',incident_id=incident_id))

    @app.post('/incidents/<incident_id>/handling')
    @login_required
    def ticket_handling(incident_id):
        from .handoff import pause,resume,view
        mode=request.form.get('handling_mode')
        if mode not in ('automatic','human','paused'): raise ValueError('Unknown handling mode.')
        generation=int(request.form.get('generation','-1'))
        current=view(store,incident_id)
        if generation!=current['generation']: raise ValueError('Ticket control changed; reload before switching modes.')
        if mode=='automatic':
            if current['owner']=='user':
                resume(store,vault,incident_id,current['checkpoint_id'],generation,request.form.get('request_id'),request.form.get('current_task'))
        else: pause(store,incident_id,generation)
        with store.connect() as c:
            c.execute('UPDATE incident_control SET handling_mode=? WHERE incident_id=?',(mode,incident_id))
            if mode!='human':
                from .worklog import end
                end(c,incident_id,'user','Stopped',time.time())
        return redirect(url_for('incident',incident_id=incident_id))

    @app.post('/incidents/<incident_id>/continue')
    @login_required
    def continue_ticket(incident_id):
        from .handoff import view,pause,resume
        task=request.form.get('current_task','').strip()
        if not task or len(task)>2000: raise ValueError('Provide a task or clarification of 1–2000 characters.')
        current=view(store,incident_id)
        if current['owner']!='user':
            pause(store,incident_id,current['generation'])
            current=view(store,incident_id)
        task=request.form.get('current_task','').strip()
        if not task or len(task)>2000: raise ValueError('Provide a task or clarification of 1–2000 characters.')
        resume(store,vault,incident_id,current['checkpoint_id'],current['generation'],request.form.get('request_id'),task)
        return redirect(url_for('incident',incident_id=incident_id))

    @app.post('/incidents/<incident_id>/handoff')
    @login_required
    def handoff(incident_id):
        from .handoff import pause, resume
        generation = int(request.form.get('generation', '-1'))
        if request.form.get('operation')=='pause':
            pause(store, incident_id, generation)
        elif request.form.get('operation')=='resume':
            resume(store, vault, incident_id, request.form.get('checkpoint_id'), generation, request.form.get('request_id'),request.form.get('current_task'))
        else:
            raise ValueError('Unknown handoff operation.')
        return redirect(url_for('incident', incident_id=incident_id))

    @app.post('/incidents/<incident_id>/workspace')
    @login_required
    def incident_workspace(incident_id):
        from .ai import request_job
        request_job(store, vault, incident_id, mode=request.form.get('mode'), question=request.form.get('question', ''), request_id=request.form.get('request_id'), source_ids=request.form.getlist('source_id'), diagnostic_ids=request.form.getlist('diagnostic_id'))
        return redirect(url_for('incident', incident_id=incident_id))

    @app.post('/ai/<job_id>/cancel')
    @login_required
    def cancel_ai(job_id):
        from .ai import cancel
        cancel(store, job_id)
        return redirect(url_for('hermes'))

    @app.post('/ai/calls/<call_id>/reconcile')
    @login_required
    def reconcile_ai(call_id):
        from .ai import reconcile
        if len(request.form.get('evidence', '').strip()) < 10:
            raise ValueError('Record the provider usage evidence before reconciliation.')
        usage = {'prompt_tokens': int(request.form.get('input_tokens', '')), 'completion_tokens': int(request.form.get('output_tokens', '')), 'prompt_tokens_details': {'cached_tokens': int(request.form.get('cached_tokens', '0'))}}
        if not reconcile(store, call_id, usage, {}, manual=True):
            raise ValueError('Usage rejected or exceeded the configured bound; inspect the budget ledger.')
        with store.connect() as c:
            store.audit(c, 'ai.usage_reconciled', call_id, {'evidence': redact(request.form['evidence'])[:1000]})
        return redirect(url_for('hermes'))

    def execution_auth(job_id):
        bearer = request.headers.get('Authorization', '')
        if not bearer.startswith('Bearer '):
            abort(401)
        rows = store.rows('SELECT id FROM ai_jobs WHERE id=? AND credential_digest=?', (job_id, digest(bearer[7:])))
        if not rows:
            abort(401)

    @app.get('/api/hermes/<job_id>/permission')
    def codex_permission(job_id):
        execution_auth(job_id)
        from .codex_mode import permission
        with store.connect() as c:
            job=c.execute('SELECT * FROM ai_jobs WHERE id=?',(job_id,)).fetchone()
            allowed=permission(c,job)
            if allowed:
                from .worklog import update_job
                update_job(c,store,dict(job),'running',time.time())
        response=app.json.response({'allowed':allowed})
        response.headers['Cache-Control']='no-store'
        return response

    @app.get('/api/hermes/<job_id>/v1/models')
    def execution_models(job_id):
        execution_auth(job_id)
        model = store.rows('SELECT model FROM ai_jobs WHERE id=?', (job_id,))[0]['model']
        return {'object': 'list', 'data': [{'id': model, 'object': 'model'}]}

    @app.post('/api/hermes/<job_id>/v1/chat/completions')
    def execution_model(job_id):
        from .ai import model_call
        execution_auth(job_id)
        return model_call(store, vault, job_id, request.get_json())

    return app
