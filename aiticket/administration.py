"""Bounded housekeeping and explicitly nonsecret preference transfer."""
import json
import math
import secrets
import time
from werkzeug.security import generate_password_hash
from .engine import SEVERITIES

KEYS = {'ai_config', 'discord_minimum', 'discord_recovery', 'notification_policy', 'retention_days'}


def validate(values):
    if not isinstance(values, dict) or set(values) - KEYS:
        raise ValueError('Only supported nonsecret preferences can be imported.')
    for key, value in values.items():
        if key == 'retention_days':
            if type(value) is not int or not 1 <= value <= 3650:
                raise ValueError('Retention must be 1–3650 days.')
        elif key == 'discord_minimum':
            if value not in SEVERITIES:
                raise ValueError('Unknown severity.')
        elif key == 'discord_recovery':
            if type(value) is not bool:
                raise ValueError('Recovery preference must be true or false.')
        elif key == 'ai_config':
            from .app import AI_DEFAULTS
            if not isinstance(value, dict) or set(value) != set(AI_DEFAULTS):
                raise ValueError('AI preferences must contain all supported fields.')
            for field, default in AI_DEFAULTS.items():
                item = value[field]
                if isinstance(default, str):
                    if not isinstance(item, str) or len(item) > 100:
                        raise ValueError('Model name is too long.')
                elif type(item) not in (int, float) or not math.isfinite(item) or not 0 <= item <= 10**9 or (type(default) is int and type(item) is not int):
                    raise ValueError('Invalid AI allowance.')
        elif key == 'notification_policy':
            from .policies import DEFAULTS
            if not isinstance(value, dict) or set(value) != set(DEFAULTS):
                raise ValueError('Invalid notification preferences.')
            if value['escalate_to'] not in SEVERITIES:
                raise ValueError('Unknown escalation severity.')
            for field in ('reminder_seconds', 'escalate_after_seconds'):
                if type(value[field]) is not int or (value[field] != 0 and not 60 <= value[field] <= 2592000):
                    raise ValueError('Notification intervals must be zero (disabled) or 60–2592000 seconds.')
    return values


def export_preferences(store):
    values = {row['key']: json.loads(row['value']) for row in store.rows('SELECT key,value FROM settings') if row['key'] in KEYS}
    return {'format': 'aiticket-preferences', 'version': 1, 'settings': values}


def import_preferences(store, document):
    if not isinstance(document, dict) or set(document) != {'format', 'version', 'settings'} or document['format'] != 'aiticket-preferences' or type(document['version']) is not int or document['version'] != 1:
        raise ValueError('Unsupported preferences file.')
    store.save_many(validate(document['settings']), actor='user')


def change_password(store, password, actor='user'):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError('Password must contain 12–1024 characters.')
    store.save_many({'admin_hash': generate_password_hash(password), 'auth_generation': secrets.token_urlsafe(32)}, actor=actor)


def prune(store, now=None):
    now = time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        previous = c.execute("SELECT value FROM settings WHERE key='retention_last_run'").fetchone()
        if previous and now - json.loads(previous[0]) < 3600:
            return
        days = c.execute("SELECT value FROM settings WHERE key='retention_days'").fetchone()
        cutoff = now - (json.loads(days[0]) if days else 90) * 86400
        # Preserve all evidence attached to incidents, immutable timelines and audit.
        count = c.execute('DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE at<? AND NOT EXISTS (SELECT 1 FROM incident_observations WHERE observation_id=observations.id) LIMIT 1000)', (cutoff,)).rowcount
        events = c.execute('DELETE FROM agent_events WHERE rowid IN (SELECT rowid FROM agent_events WHERE at<? LIMIT 1000)', (now - 30 * 86400,)).rowcount
        c.execute('DELETE FROM enrollments WHERE expires<?', (now - 86400,))
        c.execute("INSERT INTO settings VALUES('retention_last_run',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(now),))
        if count or events:
            store.audit(c, 'retention.pruned', 'housekeeping', {'observations': count, 'agent_events': events}, 'system')


def rotate_key(store, old_vault, destination):
    """Offline rotation. Retain old key; switch configured key after commit."""
    import os
    from pathlib import Path
    from cryptography.fernet import Fernet
    from .security import Vault
    path = Path(destination)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(Fernet.generate_key())
        f.flush()
        os.fsync(f.fileno())
    new_vault = Vault(path)
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        for row in c.execute("SELECT key,value FROM settings WHERE key IN ('session_secret','discord_secret','hermes_secret','ai_provider_secret')").fetchall():
            encrypted = new_vault.encrypt(old_vault.decrypt(json.loads(row['value'])))
            c.execute('UPDATE settings SET value=? WHERE key=?', (json.dumps(encrypted), row['key']))
        for row in c.execute('SELECT id,token_secret FROM proxmox_connections').fetchall():
            c.execute('UPDATE proxmox_connections SET token_secret=? WHERE id=?', (new_vault.encrypt(old_vault.decrypt(row['token_secret'])), row['id']))
        for row in c.execute("SELECT id,config FROM checks WHERE kind='proxmox'").fetchall():
            config = json.loads(row['config'])
            if config.get('token_secret'):
                config['token_secret'] = new_vault.encrypt(old_vault.decrypt(config['token_secret']))
                c.execute('UPDATE checks SET config=? WHERE id=?', (json.dumps(config), row['id']))
        for row in c.execute('SELECT id,credential,bridge_secret FROM ai_jobs').fetchall():
            c.execute('UPDATE ai_jobs SET credential=?,bridge_secret=? WHERE id=?', (new_vault.encrypt(old_vault.decrypt(row['credential'])), new_vault.encrypt(old_vault.decrypt(row['bridge_secret'])), row['id']))
        for row in c.execute('SELECT machine_id,token_secret FROM power_policies WHERE token_secret IS NOT NULL').fetchall():
            c.execute('UPDATE power_policies SET token_secret=? WHERE machine_id=?',(new_vault.encrypt(old_vault.decrypt(row['token_secret'])),row['machine_id']))
        store.audit(c, 'encryption.rotated', 'vault', actor='console')
    return new_vault


def archive_incident(store,incident_id,restore=False):
    from .db import uid
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        incident=c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not incident or incident['closed'] is None:
            raise ValueError('Only closed incidents can be archived; manually resolved unhealthy conditions remain active.')
        if restore:
            if incident['archived_at'] is None:
                return
            c.execute('UPDATE incidents SET archived_at=NULL WHERE id=?',(incident_id,))
            store.timeline(c,incident_id,'unarchived','Restored to normal history; archived snapshots are retained.',actor='user')
            store.audit(c,'incident.unarchived',incident_id)
            return
        if incident['archived_at'] is not None:
            return
        now=time.time()
        c.execute('UPDATE incidents SET archived_at=? WHERE id=?',(now,incident_id))
        store.timeline(c,incident_id,'archived','Closed incident archived; all evidence remains accessible.',actor='user')
        snapshot={
            'format':'aiticket-incident-archive','version':1,'incident':dict(c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()),
            'sources':[dict(r) for r in c.execute('SELECT * FROM incident_sources WHERE incident_id=?',(incident_id,))],
            'observations':[dict(r) for r in c.execute('SELECT o.* FROM observations o JOIN incident_observations i ON i.observation_id=o.id WHERE i.incident_id=? ORDER BY o.at',(incident_id,))],
            'timeline':[dict(r) for r in c.execute('SELECT * FROM timeline WHERE incident_id=? ORDER BY at',(incident_id,))],
            'diagnostics':[dict(r) for r in c.execute('SELECT id,agent_id,operation,parameters,state,created,result,completed FROM diagnostic_jobs WHERE incident_id=?',(incident_id,))],
            'ai_messages':[dict(r) for r in c.execute('SELECT * FROM ai_messages WHERE incident_id=? ORDER BY created',(incident_id,))],
            'proposals':[dict(r) for r in c.execute('SELECT id,version,parent_id,payload,payload_hash,state,created,result,completed,verification FROM action_proposals WHERE incident_id=?',(incident_id,))],
            'links':[dict(r) for r in c.execute('SELECT * FROM incident_links WHERE left_id=? OR right_id=?',(incident_id,incident_id))],
        }
        c.execute('INSERT INTO incident_archives VALUES(?,?,?,?)',(uid(),incident_id,now,json.dumps(snapshot)))
        store.audit(c,'incident.archived',incident_id)
