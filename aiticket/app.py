import functools
import hmac
import json
import math
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
            if not session.get('admin'):
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def guard():
        if request.method == 'POST' and not request.path.startswith('/api/agent/'):
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
        return {'status': 'ok', 'ai_dispatch': 'disabled', 'version': '0.1.0'}

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
                    session.update(admin=True, csrf=secrets.token_urlsafe(32))
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
                               jobs=store.rows('SELECT state,count(*) AS count FROM deliveries GROUP BY state'))

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
                c.execute('INSERT INTO machines VALUES(?,?,?,?)', (uid(), name, parent, time.time()))
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
            c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,?,?,?,?,?,?)', (uid(), machine, name, kind, json.dumps(cfg), interval, fail, recover, severity))
        return redirect(url_for('dashboard'))

    @app.post('/checks/<check_id>/maintenance')
    @login_required
    def maintenance(check_id):
        minutes = int(request.form.get('minutes', 60))
        if not 0 <= minutes <= 10080:
            raise ValueError('Maintenance must be between 0 and 10080 minutes.')
        with store.connect() as c:
            c.execute('UPDATE checks SET maintenance_until=? WHERE id=?', (time.time() + minutes * 60, check_id))
        return redirect(url_for('dashboard'))

    @app.get('/incidents/<incident_id>')
    @login_required
    def incident(incident_id):
        rows = store.rows('SELECT * FROM incidents WHERE id=?', (incident_id,))
        if not rows:
            abort(404)
        return render_template('incident.html', incident=rows[0], report=json.loads(rows[0]['report']), timeline=store.rows('SELECT * FROM timeline WHERE incident_id=? ORDER BY at', (incident_id,)))

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
                secret = request.form.get('webhook', '').strip()
                if secret:
                    validate_url(secret, ('https',))
                    p = __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(secret)
                    if p.hostname not in ('discord.com', 'discordapp.com') or not p.path.startswith('/api/webhooks/'):
                        raise ValueError('Use a Discord webhook URL.')
                    store.save('discord_secret', vault.encrypt(secret))
                minimum = request.form.get('minimum', 'medium')
                if minimum not in SEVERITIES:
                    raise ValueError('Unknown severity.')
                store.save('discord_minimum', minimum)
                store.save('discord_recovery', bool(request.form.get('recovery')))
            else:
                cfg = {}
                for key, default in AI_DEFAULTS.items():
                    value = request.form.get(key, str(default))
                    cfg[key] = str(value)[:100] if isinstance(default, str) else type(default)(value)
                    if not isinstance(default, str) and (not math.isfinite(cfg[key]) or not 0 <= cfg[key] <= 1000000000):
                        raise ValueError('Budget values must be nonnegative and bounded.')
                store.save('ai_config', cfg)
            flash('Settings saved. AI remains disabled pending bridge validation.')
            return redirect(url_for('settings'))
        return render_template('settings.html', ai=store.setting('ai_config', AI_DEFAULTS), discord_configured=bool(store.setting('discord_secret')), minimum=store.setting('discord_minimum', 'medium'), recovery=store.setting('discord_recovery', True))

    @app.get('/queue')
    @login_required
    def queue():
        return render_template('queue.html', jobs=store.rows('SELECT * FROM deliveries ORDER BY created DESC LIMIT 200'))

    @app.post('/queue/<job_id>/retry')
    @login_required
    def retry(job_id):
        with store.connect() as c:
            c.execute("UPDATE deliveries SET state='pending',next_attempt=?,expires=?,last_error=NULL WHERE id=? AND state IN ('failed','expired','pending')", (time.time(), time.time() + 86400, job_id))
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
        return render_template('enrollment.html', token=token)

    @app.post('/agents/<agent_id>/revoke')
    @login_required
    def revoke(agent_id):
        with store.connect() as c:
            c.execute('UPDATE agents SET revoked=1 WHERE id=?', (agent_id,))
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
        allowed = {'uptime_seconds', 'load_1', 'memory_available_bytes', 'memory_total_bytes', 'disk_free_bytes', 'disk_total_bytes'}
        if not isinstance(telemetry, dict) or set(telemetry) - allowed or any(type(v) not in (float, int) or (not math.isfinite(v) or not 0 <= v <= 1e18) for v in telemetry.values()):
            abort(400)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT * FROM agents WHERE credential_digest=? AND revoked=0', (digest(bearer[7:]),)).fetchone()
            if not row:
                abort(401)
            if c.execute('SELECT 1 FROM agent_events WHERE agent_id=? AND event_id=?', (row['id'], event)).fetchone():
                return {'status': 'duplicate', 'jobs': []}
            now = time.time()
            c.execute('INSERT INTO agent_events VALUES(?,?,?)', (row['id'], event, now))
            c.execute('DELETE FROM agent_events WHERE at<?', (now - 604800,))
            c.execute('UPDATE agents SET last_seen=?,address=?,version=?,telemetry=? WHERE id=?', (now, request.remote_addr, str(payload.get('version', ''))[:32], json.dumps(telemetry), row['id']))
        return {'status': 'accepted', 'jobs': []}

    return app
