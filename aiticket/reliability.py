"""Monitoring integrity, bounded repair attempts, and safe workflow exercises."""
import json
import time
from .db import uid

class RepairLimit(ValueError):
    pass

DEFAULTS={'repeat_limit':2,'operation_limit':20,'window_seconds':1800}


def limits(c):
    row=c.execute("SELECT value FROM settings WHERE key='repair_limits'").fetchone()
    return {**DEFAULTS,**(json.loads(row[0]) if row else {})}


def repair_budget(c,vault,job_id,command=None,api=None):
    if not job_id:return
    job=c.execute('SELECT incident_id,evidence FROM ai_jobs WHERE id=?',(job_id,)).fetchone()
    if not job:return
    if json.loads(job['evidence']).get('workflow_test'):raise ValueError('Workflow tests cannot run host commands or change infrastructure.')
    from .host_access import read_only
    if command is not None and read_only(command):return
    if api is not None and api['method']=='GET':return
    if c.execute("SELECT 1 FROM ticket_blockers WHERE incident_id=? AND cleared IS NULL AND reason LIKE 'Repair attempt limit reached.%'",(job['incident_id'],)).fetchone():
        raise RepairLimit('Repair attempt limit reached. Stop changing this host and ask the administrator to review the repeated attempts.')
    cfg=limits(c);since=time.time()-cfg['window_seconds'];attempts=[]
    for row in c.execute("SELECT command FROM command_jobs WHERE incident_id=? AND ai_job_id IS NOT NULL AND created>=? AND state NOT IN ('cancelled','expired','awaiting')",(job['incident_id'],since)):
        prior=vault.decrypt(row['command'])
        if not read_only(prior):attempts.append(('shell',prior.strip()))
    for row in c.execute("SELECT p.payload FROM proxmox_api_jobs p JOIN ai_jobs j ON j.id=p.ai_job_id WHERE j.incident_id=? AND p.created>=? AND p.state NOT IN ('cancelled','expired','awaiting')",(job['incident_id'],since)):
        prior=json.loads(vault.decrypt(row['payload']))
        if prior['method']!='GET':attempts.append(('api',json.dumps(prior,sort_keys=True)))
    key=('shell',command.strip()) if command is not None else ('api',json.dumps(api,sort_keys=True))
    if len(attempts)>=cfg['operation_limit'] or attempts.count(key)>=cfg['repeat_limit']:
        raise RepairLimit('Repair attempt limit reached. Stop changing this host and ask the administrator to review the repeated attempts.')


def issues(store,now=None):
    now=time.time() if now is None else now;result=[]
    for agent in store.rows('SELECT a.*,m.name FROM agents a JOIN machines m ON m.id=a.machine_id WHERE a.revoked=0 AND m.offline_expected=0'):
        if agent['last_seen'] is None or now-agent['last_seen']>180:continue # reachability already has its own check
        sampled=agent['sampled_at'];offset=sampled-agent['last_seen'] if sampled is not None else None
        if offset is not None and abs(offset)>300:
            result.append({'host':agent['name'],'machine_id':agent['machine_id'],'title':'Clock needs attention','detail':'The host clock differs from the server by about '+str(round(abs(offset)/60))+' minutes. Check its time synchronization.'})
        elif sampled is None or not -30<=now-sampled<=180:
            result.append({'host':agent['name'],'machine_id':agent['machine_id'],'title':'Metrics are not current','detail':'The agent is connected, but its metric sample is missing or stale. Check the collector and host clock.'})
    rows=store.rows("SELECT c.name,c.machine_id,c.interval,c.next_run,m.name AS host,o.at,o.evidence FROM checks c JOIN machines m ON m.id=c.machine_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=c.id ORDER BY at DESC LIMIT 1) WHERE c.enabled=1 AND c.kind NOT IN ('manual','agent','workflow_test') AND m.offline_expected=0")
    for row in rows:
        evidence=json.loads(row['evidence'] or '{}')
        stale=row['at'] is not None and now-row['at']>max(180,row['interval']*3)
        overdue=row['at'] is None and row['next_run'] and now-row['next_run']>max(180,row['interval']*3)
        unavailable=evidence.get('monitoring_issue') or ('unavailable' in evidence.get('reason','').lower()) or evidence.get('error_type')
        if stale or overdue or unavailable:
            result.append({'host':row['host'],'machine_id':row['machine_id'],'title':row['name']+' needs attention','detail':'No current result. Check the monitoring connection and permissions.' if stale or overdue else 'The monitor could not collect a valid result. Check API compatibility, permissions, and the agent configuration.'})
    for connection in store.rows('SELECT name,machine_id,snapshot FROM unifi_connections WHERE deleted IS NULL AND snapshot IS NOT NULL'):
        snapshot=json.loads(connection['snapshot']);errors=snapshot.get('errors',{})
        if errors:
            result.append({'host':connection['name'],'machine_id':connection['machine_id'],'title':'API coverage is incomplete','detail':str(len(errors))+' API readings are unavailable. Device availability and missing telemetry are separate findings.'})
    from .integrations import views
    for connection in views(store):
        if connection['data'].get('error') or connection['data'].get('warnings') or not connection['fresh']:
            result.append({'host':connection['host'],'machine_id':connection['machine_id'],'title':connection['name']+' API coverage','detail':connection['data'].get('error') or 'Some readings are unavailable or stale. Check API permissions and server availability.'})
    return result


def start_test(store,vault,machine):
    from .host_admin import open_ticket
    # Publish the test and its command fence in the same transaction.
    identifier=open_ticket(store,machine,'Workflow test','Check the supplied diagnostic context. Do not run commands or make changes. Call resolve with a short summary confirming this test reached the AI. This is a harmless workflow exercise.','low',workflow_test=True)
    from .ai import queue_manual
    queue_manual(store,vault,identifier)
    return identifier


def test_probe(store,check_id):
    rows=store.rows("SELECT j.id,j.state,j.resolution_summary,j.summary FROM ai_jobs j JOIN incidents i ON i.id=j.incident_id WHERE i.check_id=? ORDER BY j.created DESC LIMIT 1",(check_id,))
    success=bool(rows and rows[0]['state']=='completed' and (rows[0]['resolution_summary'] or rows[0]['summary']))
    return (True if success else None),{'reason':'AI dispatch and completion confirmed.' if success else 'Waiting for the AI to finish the workflow test.','sampled_at':time.time(),'workflow_test':True}
