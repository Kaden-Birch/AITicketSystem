"""Evidence relationships are hypotheses; only explicit user merging combines conditions."""
import json
import time
from .engine import SEVERITIES


def relationship(kind,condition,other_kind,other_condition):
    service={'http','tcp'}
    pressure=condition=='resource-pressure' or other_condition=='resource-pressure'
    communication=condition in ('guest-down','agent-communication') or other_condition in ('guest-down','agent-communication')
    if pressure and (kind in service or other_kind in service or communication or (kind==other_kind=='agent_metric')):
        return 'Concurrent resource pressure and outage on the same machine; possible shared impact, cause unconfirmed'
    if (kind in service or other_kind in service) and (communication or (kind in service and other_kind in service)):
        return 'Possible shared impact; separate conditions, cause unconfirmed'
    return None


def merge(store,source_id,target_id,reason,now=None):
    now=time.time() if now is None else now
    if source_id==target_id or not isinstance(reason,str) or not 1<=len(reason.strip())<=1000:
        raise ValueError('Select distinct incidents and explain the merge (1–1000 characters).')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        source=c.execute('SELECT * FROM incidents WHERE id=?',(source_id,)).fetchone()
        target=c.execute('SELECT * FROM incidents WHERE id=?',(target_id,)).fetchone()
        if not source or not target or source['machine_id']!=target['machine_id']:
            raise ValueError('Merge targets must belong to the same explicitly linked machine.')
        if any(i['closed'] is not None or i['status']=='Resolved' or i['merged_into'] for i in (source,target)):
            raise ValueError('Only active, unresolved, unmerged incidents can be merged.')
        if any(json.loads(i['report']).get('manual_ticket') for i in (source,target)):
            raise ValueError('Manual tickets retain independent user-reported evidence and cannot be merged with monitored conditions.')
        for identifier in (source_id,target_id):
            if c.execute("SELECT 1 FROM ai_jobs WHERE incident_id=? AND state IN ('pending','dispatching','running','unknown')",(identifier,)).fetchone() or c.execute("SELECT 1 FROM ai_calls a JOIN ai_jobs j ON j.id=a.job_id WHERE j.incident_id=? AND a.state!='known'",(identifier,)).fetchone():
                raise ValueError('Stop AI work and reconcile unknown usage before merging.')
            if c.execute("SELECT 1 FROM action_proposals WHERE incident_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(identifier,)).fetchone() or c.execute("SELECT 1 FROM diagnostic_jobs WHERE incident_id=? AND state IN ('pending','leased') AND expires>?",(identifier,now)).fetchone():
                raise ValueError('Complete or cancel outstanding diagnostics and recovery proposals before merging.')
        if c.execute('SELECT 1 FROM action_proposals WHERE incident_id=? AND dispatched IS NOT NULL',(source_id,)).fetchone():
            raise ValueError('An incident with a consumed recovery attempt must remain the merge target.')
        # Copy source membership/evidence, retaining all original incident records.
        c.execute('INSERT OR IGNORE INTO incident_sources SELECT ?,check_id,report FROM incident_sources WHERE incident_id=?',(target_id,source_id))
        c.execute('INSERT OR IGNORE INTO incident_observations SELECT ?,observation_id FROM incident_observations WHERE incident_id=?',(target_id,source_id))
        c.execute('INSERT INTO incident_merges VALUES(?,?,?,?)',(source_id,target_id,now,reason.strip()))
        c.execute("UPDATE incidents SET merged_into=?,closed=?,status='Resolved' WHERE id=?",(target_id,now,source_id))
        c.execute("UPDATE deliveries SET state='superseded',lease_token=NULL,lease_until=NULL WHERE incident_id=? AND state IN ('pending','leased')",(source_id,))
        reports=[json.loads(r[0]) for r in c.execute('SELECT report FROM incident_sources WHERE incident_id=?',(target_id,))]
        severity=max([target['severity_floor'],source['severity_floor']]+[r.get('severity','medium') for r in reports],key=SEVERITIES.index)
        report=json.loads(target['report'])
        report.update(sources=reports,check='Multiple manually grouped sources',cause='Unknown',severity=severity,observed='down')
        c.execute("UPDATE incidents SET first_seen=?,last_seen=?,severity=?,severity_floor=?,report=?,condition_key='manual-group' WHERE id=?",(min(source['first_seen'],target['first_seen']),max(source['last_seen'],target['last_seen']),severity,max((source['severity_floor'],target['severity_floor']),key=SEVERITIES.index),json.dumps(report),target_id))
        from .handoff import take_control
        take_control(c,store,target_id)
        take_control(c,store,source_id)
        store.timeline(c,target_id,'manual_merge','Incident '+source_id+' merged by user: '+reason.strip(),actor='user',now=now)
        store.timeline(c,source_id,'merged_into','Grouped into '+target_id+'. Original evidence retained; this is not verified recovery.',actor='user',now=now)
        if SEVERITIES.index(severity)>SEVERITIES.index(target['severity']):
            from .engine import enqueue
            enqueue(c,target_id,'severity-'+severity,now,store)
        store.audit(c,'incident.merged',target_id,{'source_id':source_id})
    return target_id
