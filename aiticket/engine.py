import json
import time
from .db import uid

SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']


def source_condition(check, evidence):
    cfg = json.loads(check['config'])
    guest = check['kind'] in ('proxmox', 'proxmox_linked') and cfg.get('resource', '').startswith(('qemu/', 'lxc/'))
    if guest and cfg.get('expected', 'running') == 'running' and evidence.get('status') == 'stopped':
        return 'guest-down'
    if check['kind'] == 'agent':
        return 'agent-communication'
    return 'check:' + check['id']


def observe(store, check_id, healthy, evidence, now=None, lease_token=None):
    """Persist each source independently; correlate only explicit compatible evidence."""
    now = time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        check = c.execute('SELECT * FROM checks WHERE id=?', (check_id,)).fetchone()
        if not check or not check['enabled'] or (lease_token and check['lease_token'] != lease_token):
            return
        observation_id = uid()
        c.execute('INSERT INTO observations VALUES(?,?,?,?,?)', (observation_id, check_id, now, 'healthy' if healthy else 'down', json.dumps(evidence)))
        failures = 0 if healthy else check['failures'] + 1
        successes = check['successes'] + 1 if healthy else 0
        health = check['health']
        if failures >= check['fail_after']:
            health = 'down'
        if successes >= check['recover_after']:
            health = 'healthy'
        first_failure_at = None if healthy else (check['first_failure_at'] if check['failures'] and check['first_failure_at'] is not None else now)
        c.execute('UPDATE checks SET failures=?,successes=?,health=?,first_failure_at=?,lease_until=NULL,lease_token=NULL,next_run=? WHERE id=?',
                  (failures, successes, health, first_failure_at, now + check['interval'], check_id))
        incident = c.execute('SELECT i.* FROM incidents i JOIN incident_sources s ON s.incident_id=i.id WHERE s.check_id=? AND i.closed IS NULL', (check_id,)).fetchone()
        machine = c.execute('SELECT * FROM machines WHERE id=?', (check['machine_id'],)).fetchone()
        suppressed = check['maintenance_until'] > now
        parent, visited = machine['parent_id'], set()
        while parent and parent not in visited:
            visited.add(parent)
            if c.execute("SELECT 1 FROM checks WHERE machine_id=? AND enabled=1 AND health='down'", (parent,)).fetchone():
                suppressed = True
            row = c.execute('SELECT parent_id FROM machines WHERE id=?', (parent,)).fetchone()
            parent = row[0] if row else None
        first_failure = first_failure_at if first_failure_at is not None else now
        source = {'check_id':check_id, 'kind':check['kind'], 'first_failure':first_failure if failures else None,
                  'last_observation':now, 'check':check['name'], 'expected':'healthy', 'observed':health,
                  'latest_sample':'healthy' if healthy else 'down', 'severity':check['severity'],
                  'justification':f"{failures} consecutive failures; threshold {check['fail_after']}",
                  'evidence':evidence, 'observed_at':now, 'suppressed':suppressed}
        condition = source_condition(check, evidence)
        attached = False
        if not incident and health == 'down' and not suppressed:
            # Identity is explicit machine linkage, never IP/name similarity.
            partner = 'agent-communication' if condition == 'guest-down' else 'guest-down' if condition == 'agent-communication' else None
            if partner:
                candidates = c.execute('SELECT * FROM incidents WHERE machine_id=? AND condition_key=? AND closed IS NULL AND last_seen>=? ORDER BY first_seen',
                                       (machine['id'], partner, now-300)).fetchall()
                for candidate in candidates:
                    if partner == 'guest-down':
                        reports = c.execute('SELECT report FROM incident_sources WHERE incident_id=?',(candidate['id'],)).fetchall()
                        if not any(json.loads(r[0]).get('evidence',{}).get('status')=='stopped' and json.loads(r[0]).get('latest_sample')=='down' and json.loads(r[0]).get('observed_at',0)>=now-300 for r in reports):
                            continue
                    incident = candidate
                    attached = True
                    c.execute("UPDATE incidents SET condition_key='guest-down' WHERE id=?",(incident['id'],))
                    store.timeline(c,incident['id'],'source_correlated','Compatible guest-state and agent-communication evidence linked by machine identity.',now=now)
                    break
            if not incident:
                iid=uid()
                c.execute('INSERT INTO incidents(id,machine_id,check_id,severity,status,first_seen,last_seen,report,condition_key) VALUES(?,?,?,?,?,?,?,?,?)',
                          (iid,machine['id'],check_id,check['severity'],'Open',first_failure,now,'{}',condition))
                incident = c.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
                store.timeline(c,iid,'opened','Failure threshold reached. Cause unknown.',now=now)
                enqueue(c,iid,'opened',now,store)
                # HTTP/TCP outages may have a relationship, but are not proof of guest failure.
                others=c.execute('SELECT i.id,i.condition_key,c.kind FROM incidents i JOIN checks c ON c.id=i.check_id WHERE i.machine_id=? AND i.closed IS NULL AND i.id<>? AND i.last_seen>=?',(machine['id'],iid,now-300)).fetchall()
                for other in others:
                    uncertain = (check['kind'] in ('http','tcp') and other['condition_key'] in ('guest-down','agent-communication')) or (condition in ('guest-down','agent-communication') and other['kind'] in ('http','tcp'))
                    if uncertain:
                        left,right=sorted((iid,other['id']))
                        c.execute('INSERT OR IGNORE INTO incident_links VALUES(?,?,?)',(left,right,'Possible shared impact; separate conditions, cause unconfirmed'))
        if not incident:
            return
        iid=incident['id']
        c.execute('INSERT INTO incident_sources VALUES(?,?,?) ON CONFLICT(incident_id,check_id) DO UPDATE SET report=excluded.report',(iid,check_id,json.dumps(source)))
        c.execute('INSERT INTO incident_observations VALUES(?,?)',(iid,observation_id))
        sources=[]
        for row in c.execute('SELECT s.report,c.enabled,c.interval FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(iid,)):
            report=json.loads(row['report'])
            report['fresh']=row['enabled']==1 and now-report.get('observed_at',0)<=max(180,row['interval']*3)
            sources.append(report)
        recovered=all(r.get('observed')=='healthy' and r['fresh'] for r in sources)
        severity=max((r.get('severity','medium') for r in sources),key=SEVERITIES.index)
        aggregate=dict(source)
        aggregate.update(target=machine['name'],cause='Unknown',ai_status='disabled',sources=sources,
                         observed='healthy' if recovered else 'down' if any(r.get('observed')=='down' and r['fresh'] for r in sources) else 'unknown',
                         severity=severity,check='Multiple linked sources' if len(sources)>1 else check['name'])
        c.execute('UPDATE incidents SET last_seen=?,report=?,severity=? WHERE id=?',(now,json.dumps(aggregate),severity,iid))
        if SEVERITIES.index(severity) > SEVERITIES.index(incident['severity']):
            store.timeline(c,iid,'severity_changed','Additional source evidence raised severity to '+severity+'.',now=now)
            enqueue(c,iid,'severity-'+severity,now,store)
        if recovered:
            c.execute("UPDATE incidents SET status='Resolved',closed=? WHERE id=?",(now,iid))
            store.timeline(c,iid,'recovery','All attached sources independently confirmed recovery with fresh observations.',now=now)
            enqueue(c,iid,'recovery',now,store)


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
            row = c.execute('SELECT * FROM checks WHERE enabled=1 AND next_run<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_run LIMIT 1', (now, now)).fetchone()
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
