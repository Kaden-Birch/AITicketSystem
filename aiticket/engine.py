import json
import time
from .db import uid

SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']


def observe(store, check_id, healthy, evidence, now=None, lease_token=None):
    """Observation, incident and outbox changes are committed together."""
    now = time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        check = c.execute('SELECT * FROM checks WHERE id=?', (check_id,)).fetchone()
        if not check or (lease_token and check['lease_token'] != lease_token):
            return
        c.execute('INSERT INTO observations VALUES(?,?,?,?,?)', (uid(), check_id, now, 'healthy' if healthy else 'down', json.dumps(evidence)))
        failures = 0 if healthy else check['failures'] + 1
        successes = check['successes'] + 1 if healthy else 0
        health = check['health']
        if failures >= check['fail_after']:
            health = 'down'
        if successes >= check['recover_after']:
            health = 'healthy'
        c.execute('UPDATE checks SET failures=?,successes=?,health=?,lease_until=NULL,lease_token=NULL,next_run=? WHERE id=?',
                  (failures, successes, health, now + check['interval'], check_id))
        incident = c.execute('SELECT * FROM incidents WHERE check_id=? AND closed IS NULL', (check_id,)).fetchone()
        machine = c.execute('SELECT * FROM machines WHERE id=?', (check['machine_id'],)).fetchone()
        suppressed = check['maintenance_until'] > now
        parent = machine['parent_id']
        visited = set()
        while parent and parent not in visited:
            visited.add(parent)
            if c.execute("SELECT 1 FROM checks WHERE machine_id=? AND health='down'", (parent,)).fetchone():
                suppressed = True
            row = c.execute('SELECT parent_id FROM machines WHERE id=?', (parent,)).fetchone()
            parent = row[0] if row else None
        first_failure = now
        if failures:
            recent = c.execute('SELECT at FROM observations WHERE check_id=? ORDER BY at DESC LIMIT ?', (check_id, failures)).fetchall()
            first_failure = min(r['at'] for r in recent)
        report = {'first_failure': first_failure if failures else None, 'last_observation': now, 'target': machine['name'], 'check': check['name'], 'expected': 'healthy',
                  'observed': health, 'latest_sample': 'healthy' if healthy else 'down',
                  'severity': check['severity'], 'justification': f"{failures} consecutive failures; threshold {check['fail_after']}",
                  'evidence': evidence, 'observed_at': now, 'cause': 'Unknown', 'suppressed': suppressed, 'ai_status': 'disabled'}
        if incident:
            c.execute('UPDATE incidents SET last_seen=?,report=? WHERE id=?', (now, json.dumps(report), incident['id']))
            if health == 'healthy':
                c.execute("UPDATE incidents SET status='Resolved',closed=? WHERE id=?", (now, incident['id']))
                store.timeline(c, incident['id'], 'recovery', 'Independent checks confirmed recovery.', now=now)
                enqueue(c, incident['id'], 'recovery', now, store)
        elif health == 'down' and not suppressed:
            iid = uid()
            c.execute('INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,NULL)',
                      (iid, machine['id'], check_id, check['severity'], 'Open', first_failure, now, json.dumps(report)))
            store.timeline(c, iid, 'opened', 'Failure threshold reached. Cause unknown.', now=now)
            enqueue(c, iid, 'opened', now, store)


def enqueue(c, incident_id, event, now, store):
    severity = c.execute('SELECT severity FROM incidents WHERE id=?', (incident_id,)).fetchone()[0]
    minimum = store.setting('discord_minimum', 'medium')
    if SEVERITIES.index(severity) < SEVERITIES.index(minimum):
        return
    if event == 'recovery' and not store.setting('discord_recovery', True):
        return
    c.execute('INSERT OR IGNORE INTO deliveries VALUES(?,?,?, ?,0,?,NULL,NULL,NULL,?,?)',
              (uid(), incident_id, incident_id + ':' + event, 'pending', now, now, now + 86400))


def claim(store, table, now=None, lease=60):
    if table not in ('checks', 'deliveries'):
        raise ValueError('Unsupported job table')
    now = time.time() if now is None else now
    token = uid()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if table == 'checks':
            row = c.execute('SELECT * FROM checks WHERE next_run<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_run LIMIT 1', (now, now)).fetchone()
        else:
            c.execute("UPDATE deliveries SET state='expired',lease_until=NULL WHERE expires<=? AND state IN ('pending','leased')", (now,))
            row = c.execute("SELECT * FROM deliveries WHERE ((state='pending' AND next_attempt<=?) OR (state='leased' AND lease_until<=?)) AND expires>? ORDER BY created LIMIT 1", (now, now, now)).fetchone()
        if not row:
            return None
        c.execute(f'UPDATE {table} SET lease_until=?,lease_token=? WHERE id=?', (now + lease, token, row['id']))
        if table == 'deliveries':
            c.execute("UPDATE deliveries SET state='leased',attempts=attempts+1 WHERE id=?", (row['id'],))
        result = dict(row)
        result['lease_token'] = token
        return result
