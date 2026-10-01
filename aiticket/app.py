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
                      MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=not testing and os.environ.get('AITICKET_LOCAL_HTTP') != '1',
                      PERMANENT_SESSION_LIFETIME=3600)
    app.extensions.update(store=store, vault=vault)

    def login_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get('admin') or session.get('auth_generation') != store.setting('auth_generation'):
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def guard():
        if request.method == 'POST' and not request.path.startswith(('/api/agent/', '/api/hermes/')):
            if not hmac.compare_digest(session.get('csrf', ''), request.form.get('csrf', '')) or not session.get('csrf'):
                abort(403)

    @app.after_request
    def headers(response):
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
        return {'csrf': session['csrf'], 'severities': SEVERITIES}

    @app.errorhandler(ValueError)
    def invalid(exc):
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
                    session.clear()
                    session.update(admin=True, csrf=secrets.token_urlsafe(32), auth_generation=store.setting('auth_generation'))
                    session.permanent = True
                    return redirect(url_for('dashboard'))
                failures = (row['failures'] if row else 0) + 1
                c.execute('INSERT INTO login_attempts VALUES(?,?,?) ON CONFLICT(address) DO UPDATE SET failures=excluded.failures,blocked_until=excluded.blocked_until', (address, failures, now + 60 if failures >= 5 else 0))
            flash('Incorrect password.')
        return render_template('login.html')

    @app.post('/logout')
    @login_required
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @login_required
    def dashboard():
        return render_template('dashboard.html', checks=store.rows('SELECT checks.*,machines.name AS machine FROM checks JOIN machines ON machines.id=machine_id ORDER BY machines.name'),
                               incidents=store.rows('SELECT incidents.*,machines.name AS machine FROM incidents JOIN machines ON machines.id=machine_id ORDER BY first_seen DESC LIMIT 100'),
                               jobs=store.rows('SELECT state,count(*) AS count FROM deliveries GROUP BY state'), ai_enabled=store.setting('hermes_config', {}).get('enabled', False))

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
                c.execute('INSERT INTO machines VALUES(?,?,?,?)', (machine_id, name, parent, time.time()))
                store.audit(c, 'machine.created', machine_id, {'parent_id': parent})
            return redirect(url_for('hosts'))
        return render_template('hosts.html', machines=store.rows('SELECT * FROM machines ORDER BY name'), agents=store.rows('SELECT agents.*,machines.name FROM agents JOIN machines ON machines.id=machine_id'))

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
        if not 10 <= interval <= 86400 or not 1 <= fail <= 100 or not 1 <= recover <= 100 or severity not in SEVERITIES:
            raise ValueError('Invalid interval, thresholds or severity.')
        name = f.get('name', '').strip()
        if not 1 <= len(name) <= 100:
            raise ValueError('Check name must contain 1–100 characters.')
        with store.connect() as c:
            check_id = uid()
            c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,?,?,?,?,?,?)', (check_id, machine, name, kind, json.dumps(cfg), interval, fail, recover, severity))
            store.audit(c, 'check.created', check_id, {'machine_id': machine, 'kind': kind})
        return redirect(url_for('dashboard'))

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
        return render_template('incident.html', workspace_request_id=uid(), workspace_messages=store.rows('SELECT m.*,j.state,j.mode FROM ai_messages m JOIN ai_jobs j ON j.id=m.job_id WHERE m.incident_id=? ORDER BY m.created DESC LIMIT 100', (incident_id,)), workspace_sources=store.rows('SELECT s.check_id,c.name FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(incident_id,)), ai_jobs=store.rows('SELECT id,state,mode,created,summary,error FROM ai_jobs WHERE incident_id=? ORDER BY created DESC LIMIT 100', (incident_id,)), ai_meter=meter(store, incident_id), incident=rows[0], report=json.loads(rows[0]['report']), timeline=store.rows('SELECT * FROM timeline WHERE incident_id=? ORDER BY at', (incident_id,)), links=store.rows('SELECT * FROM incident_links WHERE left_id=? OR right_id=?',(incident_id,incident_id)), diagnostic_jobs=store.rows('SELECT * FROM diagnostic_jobs WHERE incident_id=? ORDER BY created DESC LIMIT 100',(incident_id,)), diagnostic_agents=[{**a,'caps':json.loads(a['capabilities'])} for a in store.rows('SELECT * FROM agents WHERE machine_id=? AND revoked=0',(rows[0]['machine_id'],))])

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
                # Keep the condition attached; no endless reopening while it is unhealthy.
                report = json.loads(row['report'])
                report['manual_resolution'] = True
                c.execute("UPDATE incidents SET status='Resolved',report=? WHERE id=?", (json.dumps(report), incident_id))
        return redirect(url_for('incident', incident_id=incident_id))

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        if request.method == 'POST':
            if request.form.get('section') == 'discord':
                updates = {}
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
        return render_template('settings.html', ai=store.setting('ai_config', AI_DEFAULTS), discord_configured=bool(store.setting('discord_secret')), minimum=store.setting('discord_minimum', 'medium'), recovery=store.setting('discord_recovery', True), ai_enabled=store.setting('hermes_config', {}).get('enabled', False))


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

    @app.post('/agents/<agent_id>/rotate')
    @login_required
    def rotate_agent(agent_id):
        token = secrets.token_urlsafe(32)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            agent = c.execute('SELECT * FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not agent:
                abort(404)
            c.execute('UPDATE agents SET revoked=1 WHERE id=?', (agent_id,))
            c.execute('UPDATE enrollments SET used=? WHERE machine_id=? AND used IS NULL', (time.time(), agent['machine_id']))
            c.execute("UPDATE diagnostic_jobs SET state='expired',lease_until=NULL,lease_token=NULL WHERE agent_id=? AND state IN ('pending','leased')", (agent_id,))
            c.execute('INSERT INTO enrollments VALUES(?,?,?,NULL)', (digest(token), agent['machine_id'], time.time()+600))
            store.audit(c, 'agent.rotation_requested', agent_id)
        return render_template('enrollment.html', token=token)

    @app.get('/history')
    @login_required
    def history():
        clauses, params = [], []
        filters = {key: request.args.get(key, '') for key in ('machine', 'severity', 'status', 'from', 'to')}
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
            result = c.execute('UPDATE agents SET revoked=1 WHERE id=?', (agent_id,))
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
                c.execute('UPDATE agents SET credential_digest=?,revoked=0 WHERE id=?', (digest(credential), agent_id))
            else:
                c.execute('INSERT INTO agents(id,machine_id,credential_digest) VALUES(?,?,?)', (agent_id, row['machine_id'], digest(credential)))
                c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES(?,?,?,?,?,?)', (uid(), row['machine_id'], 'Agent heartbeat', 'agent', json.dumps({'agent_id': agent_id, 'max_age': 180}), 60))
            c.execute('UPDATE enrollments SET used=? WHERE digest=?', (time.time(), row['digest']))
            store.audit(c, 'agent.reenrolled' if existing else 'agent.enrolled', agent_id, {'machine_id': row['machine_id']}, actor='agent')
        return {'agent_id': agent_id, 'credential': credential}

    @app.post('/api/agent/heartbeat')
    def heartbeat():
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
        allowed = {'uptime_seconds', 'load_1', 'memory_available_bytes', 'memory_total_bytes', 'disk_free_bytes', 'disk_total_bytes', 'inode_free', 'inode_total', 'cpu_percent', 'memory_pressure_percent'}
        if not isinstance(telemetry, dict) or set(telemetry) - allowed or any(type(v) not in (float, int) or (not math.isfinite(v) or not 0 <= v <= 1e18) for v in telemetry.values()):
            abort(400)
        if any(telemetry.get(key,0)>100 for key in ('cpu_percent','memory_pressure_percent')):
            abort(400)
        for free,total in (('memory_available_bytes','memory_total_bytes'),('disk_free_bytes','disk_total_bytes'),('inode_free','inode_total')):
            if free in telemetry and total in telemetry and telemetry[free]>telemetry[total]:
                abort(400)
        capabilities=payload.get('capabilities',{})
        if not isinstance(capabilities,dict) or set(capabilities)-{'operations','services'} or any(not isinstance(capabilities.get(k,[]),list) for k in ('operations','services')):
            abort(400)
        if len(capabilities.get('operations',[]))>3 or any(x not in ('process_summary','service_status','service_logs') for x in capabilities.get('operations',[])) or len(capabilities.get('services',[]))>20 or any(not isinstance(x,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',x) for x in capabilities.get('services',[])):
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
                return {'status': 'duplicate', 'jobs': poll(c,row['id'],time.time())}
            now = time.time()
            c.execute('INSERT INTO agent_events VALUES(?,?,?)', (row['id'], event, now))
            c.execute('DELETE FROM agent_events WHERE at<?', (now - 604800,))
            c.execute('UPDATE agents SET last_seen=?,address=?,version=?,telemetry=?,capabilities=?,sampled_at=? WHERE id=?', (now, request.remote_addr, str(payload.get('version', ''))[:32], json.dumps(telemetry), json.dumps(capabilities),sampled_at,row['id']))
            from .diagnostics import poll
            jobs=poll(c,row['id'],now)
        return {'status': 'accepted', 'jobs': jobs}

    @app.route('/proxmox', methods=['GET','POST'])
    @login_required
    def proxmox_inventory():
        from .proxmox import Client, discover, link, unlink
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
        connections=store.rows('SELECT id,cluster_id,name,url,ca,last_test,last_discovery FROM proxmox_connections ORDER BY name')
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
                c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after) VALUES(?,?,?,?,?,30,1,2)',(check_id,agents[0]['machine_id'],f['metric'],'agent_metric',json.dumps(config)))
                store.audit(c,'resource_rule.created',check_id,{'metric':f['metric']})
            return redirect(url_for('resource_rules'))
        return render_template('resources.html',metrics=METRICS,agents=store.rows('SELECT a.id,m.name,a.capabilities FROM agents a JOIN machines m ON m.id=a.machine_id WHERE revoked=0'),rules=store.rows("SELECT c.name,c.config,m.name AS machine FROM checks c JOIN machines m ON m.id=c.machine_id WHERE kind='agent_metric'"))

    @app.route('/policies',methods=['GET','POST'])
    @login_required
    def maintenance_policies():
        from .policies import add_window,DEFAULTS,active
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
        return render_template('policies.html',windows=windows,machines=store.rows('SELECT * FROM machines ORDER BY name'),policy=store.setting('notification_policy',DEFAULTS))

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
                provider = {'url': validate_url(f.get('provider_url', '').strip(), ('https',)).rstrip('/'), 'ca': f.get('provider_ca', '').strip(), 'verified': bool(f.get('provider_verified')), 'input_overhead': int(f.get('input_overhead', 8192)), 'output_tokens': int(f.get('output_tokens', 1000)), 'verified_model': store.setting('ai_config', {}).get('model', '')}
                if bridge['minimum'] not in SEVERITIES or not 0 <= provider['input_overhead'] <= 1000000 or not 1 <= provider['output_tokens'] <= 100000:
                    raise ValueError('Invalid severity or provider bounds.')
                updates = {'hermes_config': bridge, 'ai_provider': provider, 'hermes_validation': None}
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
                if result.get('version') != 1 or result.get('tools') != [] or result.get('model_gateway') is not True or result.get('compatible') is not True:
                    raise ValueError('Bridge reports an incompatible or unrestricted Hermes adapter.')
                store.save_many({'hermes_validation': {'at': time.time(), 'url': bridge['url'], 'workspace_modes': [m for m in ('advice', 'exploration') if m in result.get('workspace_modes', [])]}}, actor='user')
                flash('Signed bridge compatibility check passed. No model request was made.')
            elif f.get('operation') == 'enable':
                validation = store.setting('hermes_validation') or {}
                if validation.get('url') != bridge['url'] or time.time()-validation.get('at', 0)>86400:
                    raise ValueError('Run a recent bridge compatibility check before enabling.')
                bridge = {**bridge, 'enabled': True}
                valid_configuration(store.setting('ai_config', {}), bridge, provider, mode='advice')
                if not store.setting('ai_provider_secret'):
                    raise ValueError('Save model-provider credentials first.')
                store.save_many({'hermes_config': bridge}, actor='user')
            else:
                raise ValueError('Unknown Hermes settings operation.')
            return redirect(url_for('hermes'))
        return render_template('hermes.html', bridge=bridge, provider=provider, usage=meter(store), validation=store.setting('hermes_validation'), configured=bool(store.setting('hermes_secret')), provider_configured=bool(store.setting('ai_provider_secret')), held_calls=store.rows("SELECT id,job_id,created,input_reserved,output_reserved,cost_reserved FROM ai_calls WHERE state!='known' ORDER BY created LIMIT 100"), ai_jobs=store.rows('SELECT id,incident_id,state,error FROM ai_jobs ORDER BY created DESC LIMIT 100'))

    @app.post('/incidents/<incident_id>/ai')
    @login_required
    def investigate(incident_id):
        from .ai import request_job
        request_job(store, vault, incident_id)
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
