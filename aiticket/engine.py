import json
import time
from .db import uid

SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']


def source_condition(check, evidence):
    cfg = json.loads(check['config'])
    guest = check['kind'] in ('proxmox', 'proxmox_linked') and cfg.get('resource', '').startswith(('qemu/', 'lxc/'))
    if guest and cfg.get('expected', 'running') == 'running' and evidence.get('status') == 'stopped':
        return 'guest-down'
    if check['kind']=='agent_metric':
        return 'resource-pressure'
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
        from .host_presence import suppressed as presence_suppressed
        if presence_suppressed(c,check,now):
            c.execute('INSERT INTO observations VALUES(?,?,?,?,?)',(uid(),check_id,now,'unknown',json.dumps({'reason':'Expected offline; reachability monitoring paused','expected_offline':True})))
            c.execute("UPDATE checks SET health='unknown',failures=0,successes=0,first_failure_at=NULL,lease_token=NULL,lease_until=NULL,next_run=? WHERE id=?",(now+check['interval'],check_id))
            return
        if check['kind'] in ('agent_metric','unifi_device') and healthy is not None:
            previous=c.execute('SELECT evidence FROM observations WHERE check_id=? ORDER BY at DESC LIMIT 1',(check_id,)).fetchone()
            if previous and json.loads(previous[0]).get('sampled_at')==evidence.get('sampled_at'):
                c.execute('UPDATE checks SET lease_until=NULL,lease_token=NULL,next_run=? WHERE id=?',(now+check['interval'],check_id))
                return
        observation_id = uid()
        c.execute('INSERT INTO observations VALUES(?,?,?,?,?)', (observation_id, check_id, now, 'unknown' if healthy is None else 'healthy' if healthy else 'down', json.dumps(evidence)))
        failures = 0 if healthy is not False else check['failures'] + 1
        successes = check['successes'] + 1 if healthy else 0
        health = 'unknown' if healthy is None else check['health']
        first_failure_at = None if healthy is not False else (check['first_failure_at'] if check['failures'] and check['first_failure_at'] is not None else now)
        sustain = json.loads(check['config']).get('sustain_seconds',0)
        if failures >= check['fail_after'] and first_failure_at is not None and now-first_failure_at>=sustain:
            health = 'down'
        if successes >= check['recover_after']:
            health = 'healthy'
        c.execute('UPDATE checks SET failures=?,successes=?,health=?,first_failure_at=?,lease_until=NULL,lease_token=NULL,next_run=? WHERE id=?',
                  (failures, successes, health, first_failure_at, now + check['interval'], check_id))
        incident = c.execute('SELECT i.* FROM incidents i JOIN incident_sources s ON s.incident_id=i.id WHERE s.check_id=? AND i.closed IS NULL', (check_id,)).fetchone()
        machine = c.execute('SELECT * FROM machines WHERE id=?', (check['machine_id'],)).fetchone()
        from .policies import maintained
        suppressed = check['maintenance_until'] > now or maintained(c,machine['id'],now)
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
                  'latest_sample':'unknown' if healthy is None else 'healthy' if healthy else 'down', 'severity':check['severity'],
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
                others=c.execute('SELECT i.id,i.condition_key,i.report,c.kind FROM incidents i JOIN checks c ON c.id=i.check_id WHERE i.machine_id=? AND i.closed IS NULL AND i.id<>? AND i.last_seen>=?',(machine['id'],iid,now-300)).fetchall()
                for other in others:
                    other_report=json.loads(other['report'])
                    if not any(r.get('latest_sample')=='down' and r.get('observed_at',0)>=now-300 for r in other_report.get('sources',[other_report])):
                        continue
                    from .correlation import relationship
                    reason=relationship(check['kind'],condition,other['kind'],other['condition_key'])
                    if reason:
                        left,right=sorted((iid,other['id']))
                        c.execute('INSERT OR IGNORE INTO incident_links VALUES(?,?,?)',(left,right,reason))
        if not incident:
            return
        iid=incident['id']
        c.execute('INSERT INTO incident_sources VALUES(?,?,?) ON CONFLICT(incident_id,check_id) DO UPDATE SET report=excluded.report',(iid,check_id,json.dumps(source)))
        c.execute('INSERT OR IGNORE INTO incident_observations VALUES(?,?)',(iid,observation_id))
        if healthy is False:
            # Retain the threshold-building failure samples as incident evidence too.
            c.execute("INSERT OR IGNORE INTO incident_observations SELECT ?,id FROM observations WHERE check_id=? AND at>=? AND at<=? AND health='down'",(iid,check_id,first_failure,now))
        sources=[]
        for row in c.execute('SELECT s.report,c.enabled,c.interval FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(iid,)):
            report=json.loads(row['report'])
            report['fresh']=row['enabled']==1 and now-report.get('observed_at',0)<=max(180,row['interval']*3)
            sources.append(report)
        recovered=all(r.get('observed')=='healthy' and r['fresh'] for r in sources)
        severity=max([incident['severity_floor']]+[r.get('severity','medium') for r in sources],key=SEVERITIES.index)
        aggregate=dict(source)
        aggregate.update(target=machine['name'],cause='Unknown',ai_status='disabled',sources=sources,
                         observed='healthy' if recovered else 'down' if any(r.get('observed')=='down' and r['fresh'] for r in sources) else 'unknown',
                         severity=severity,check='Multiple linked sources' if len(sources)>1 else check['name'])
        c.execute('UPDATE incidents SET last_seen=?,report=?,severity=? WHERE id=?',(now,json.dumps(aggregate),severity,iid))
        if SEVERITIES.index(severity) > SEVERITIES.index(incident['severity']):
            store.timeline(c,iid,'severity_changed','Additional source evidence raised severity to '+severity+'.',now=now)
            enqueue(c,iid,'severity-'+severity,now,store)
        if recovered:
            repair=c.execute("SELECT resolution_summary FROM ai_jobs WHERE incident_id=? AND resolution_summary IS NOT NULL AND state IN ('running','completed') ORDER BY created DESC LIMIT 1",(iid,)).fetchone()
            summary=(repair['resolution_summary'][:700]+ ' Recovery confirmed by fresh monitoring.') if repair else 'Recovered: '+', '.join(r['check']+' is healthy' for r in sources)+'.'
            resolve_verified(c,store,iid,summary,now)


def enqueue(c, incident_id, event, now, store):
    incident=c.execute('SELECT severity,machine_id FROM incidents WHERE id=?',(incident_id,)).fetchone()
    severity=incident['severity']
    from .policies import effective
    policy=effective(c,incident['machine_id'])
    if not policy['enabled']:
        return
    minimum=policy['minimum']
    if SEVERITIES.index(severity) < SEVERITIES.index(minimum):
        return
    from .telegram import notification as telegram_notification
    telegram_notification(c,store,incident_id,event)
    if event.startswith('blocker:') and not store.setting('discord_blockers',True): return
    if event == 'recovery' and not policy['recovery']:
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
            row = c.execute('SELECT * FROM checks WHERE enabled=1 AND kind NOT IN ("process","smb","docker","network_problem","log_health") AND next_run<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_run LIMIT 1', (now, now)).fetchone()
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


def resolve_verified(c,store,incident_id,summary,now):
    row=c.execute('SELECT report,closed FROM incidents WHERE id=?',(incident_id,)).fetchone()
    if not row or row['closed'] is not None: return
    from .worklog import end,clear
    end(c,incident_id,'hermes','Resolved',now,summary)
    end(c,incident_id,'user','Resolved',now,summary)
    clear(c,incident_id,now)
    report=json.loads(row['report']);report['recovery_summary']=summary[:1000]
    report['recovered_at']=now;report['observed']='healthy'
    c.execute("UPDATE incidents SET status='Resolved',closed=?,last_seen=?,report=? WHERE id=?",(now,now,json.dumps(report),incident_id))
    from .knowledge_workflows import verified
    verified(c,incident_id,now)
    if report.get('workflow_test'):
        c.execute('UPDATE checks SET enabled=0 WHERE id=(SELECT check_id FROM incidents WHERE id=?)',(incident_id,))
    store.timeline(c,incident_id,'recovery',summary,actor='monitor',now=now)
    enqueue(c,incident_id,'recovery',now,store)


def resolution_tick(store,now=None):
    """AI can request closure; fresh independent monitoring decides recovery."""
    now=time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        jobs=c.execute("SELECT j.*,i.machine_id,i.report FROM ai_jobs j JOIN incidents i ON i.id=j.incident_id WHERE j.resolution_summary IS NOT NULL AND j.state='completed' AND i.closed IS NULL AND i.status!='Resolved' AND NOT EXISTS (SELECT 1 FROM ai_jobs newer WHERE newer.incident_id=j.incident_id AND newer.created>j.created) AND NOT EXISTS (SELECT 1 FROM incident_control ic WHERE ic.incident_id=j.incident_id AND ic.owner='user')").fetchall()
        for job in jobs:
            if c.execute("SELECT 1 FROM command_jobs WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(job['machine_id'],)).fetchone() or c.execute("SELECT 1 FROM proxmox_api_jobs WHERE machine_id=? AND state IN ('awaiting','dispatched','unknown')",(job['machine_id'],)).fetchone(): continue
            if c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(job['machine_id'],)).fetchone(): continue
            if c.execute("SELECT 1 FROM action_proposals WHERE incident_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(job['incident_id'],)).fetchone(): continue
            checks=c.execute("SELECT c.*,o.at AS observed_at,o.health AS latest_health FROM checks c LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=c.id ORDER BY at DESC LIMIT 1) WHERE c.machine_id=? AND c.enabled=1 AND (c.kind!='network_problem' OR c.health='down' OR c.id IN (SELECT check_id FROM incident_sources WHERE incident_id=?))",(job['machine_id'],job['incident_id'])).fetchall()
            if not checks or any(r['health']!='healthy' or r['latest_health']!='healthy' or r['observed_at'] is None or r['observed_at']<json.loads(job['report']).get('verification_requested_at',job['created']) or now-r['observed_at']>max(180,r['interval']*3) for r in checks): continue
            sources=c.execute('SELECT c.enabled,s.report FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(job['incident_id'],)).fetchall()
            if any(not r['enabled'] or json.loads(r['report']).get('observed')!='healthy' or now-json.loads(r['report']).get('observed_at',0)>180 for r in sources): continue
            summary=job['resolution_summary'][:700]+' Recovery confirmed by fresh monitoring.'
            resolve_verified(c,store,job['incident_id'],summary,now)
