"""Durable arbitrary shell jobs; local OS identity decides actual privileges."""
import hashlib,json,time,uuid
from .db import uid
from .diagnostics import redact

TERMINAL=('completed','failed','cancelled','expired','unknown')


def configure(store,machine,values):
    approval=values.get('approval','required')
    timeout=int(values.get('timeout',120));limit=int(values.get('output_limit',8192))
    if approval not in ('required','immediate','readonly','guarded') or not 5<=timeout<=3600 or not 1024<=limit<=65536:
        raise ValueError('Command timeout must be 5–3600s; output 1024–65536 bytes; choose a valid approval policy.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('SELECT 1 FROM machines WHERE id=?',(machine,)).fetchone(): raise ValueError('Unknown host.')
        old=c.execute('SELECT version FROM command_policies WHERE machine_id=?',(machine,)).fetchone()
        version=old[0]+1 if old else 1
        c.execute('INSERT OR REPLACE INTO command_policies VALUES(?,?,?,?,?,?,?,?)',(machine,int(values.get('enabled')=='yes'),approval,int(values.get('hermes')=='yes'),int(values.get('external')=='yes'),timeout,limit,version))
        c.execute("UPDATE command_jobs SET state=CASE WHEN state IN ('awaiting','pending') THEN 'cancelled' ELSE 'cancelling' END WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running')",(machine,))
        c.execute("UPDATE proxmox_api_jobs SET state='cancelled' WHERE machine_id=? AND state='awaiting'",(machine,))
        store.audit(c,'commands.policy',machine,{'approval':approval,'version':version,'enabled':values.get('enabled')=='yes'})


def ai_allowed(c,job_id):
    from .codex_mode import permission
    job=c.execute('SELECT * FROM ai_jobs WHERE id=?',(job_id,)).fetchone()
    return job if job and job['command_tools'] and permission(c,job) else None


def queue(store,vault,machine,command,identifier,incident=None,ai_job=None,external=False):
    try: uuid.UUID(identifier)
    except (ValueError,TypeError,AttributeError): raise ValueError('Use a stable UUID command ID.')
    if not isinstance(command,str) or not 1<=len(command.strip())<=16000 or '\0' in command: raise ValueError('Command must contain 1–16000 characters without NUL.')
    fingerprint=hashlib.sha256(json.dumps([machine,command,incident,ai_job,external]).encode()).hexdigest()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        policy=c.execute('SELECT * FROM command_policies WHERE machine_id=? AND enabled=1',(machine,)).fetchone()
        if not policy or (external and not policy['external']) or (ai_job and not policy['hermes']): raise ValueError('Remote commands are not enabled for this caller/host.')
        if ai_job:
            job=ai_allowed(c,ai_job)
            if not job or job['incident_id']!=incident: raise ValueError('AI command permission was revoked.')
        if incident:
            row=c.execute("SELECT * FROM incidents WHERE id=? AND machine_id=? AND closed IS NULL AND status<>'Resolved'",(incident,machine)).fetchone()
            if not row: raise ValueError('Command target must match an active ticket.')
        previous=c.execute('SELECT * FROM command_jobs WHERE id=?',(identifier,)).fetchone()
        if previous:
            if previous['fingerprint']!=fingerprint: raise ValueError('Command UUID already has different parameters.')
            return identifier
        agents=c.execute('SELECT * FROM agents WHERE machine_id=? AND revoked=0 ORDER BY last_seen DESC',(machine,)).fetchall()
        agent=next((a for a in agents if json.loads(a['capabilities']).get('shell_commands') is True and a['last_seen'] and time.time()-a['last_seen']<=180),None)
        if not agent: raise ValueError('A fresh agent with locally enabled shell capability is required.')
        if c.execute("SELECT 1 FROM proxmox_api_jobs WHERE machine_id=? AND state IN ('dispatched','unknown')",(machine,)).fetchone(): raise ValueError('Reconcile Proxmox API operations before shell commands.')
        if c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(machine,)).fetchone() or c.execute("SELECT 1 FROM action_proposals p JOIN agents a ON a.id=p.agent_id WHERE a.machine_id=? AND p.state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(machine,)).fetchone(): raise ValueError('Complete outstanding power/recovery work before shell commands.')
        if c.execute("SELECT 1 FROM command_jobs WHERE agent_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(agent['id'],)).fetchone(): raise ValueError('Complete or reconcile the existing command before sending another.')
        from .reliability import repair_budget
        repair_budget(c,vault,ai_job,command=command)
        from .host_access import requires_approval
        approval=requires_approval(policy['approval'],command=command)
        now=time.time();state='awaiting' if approval else 'pending'
        c.execute('INSERT INTO command_jobs(id,machine_id,agent_id,incident_id,ai_job_id,command,fingerprint,policy_version,timeout,output_limit,state,created,expires,requires_approval) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,machine,agent['id'],incident,ai_job,vault.encrypt(command),fingerprint,policy['version'],policy['timeout'],policy['output_limit'],state,now,now+policy['timeout']+600,int(approval)))
        store.audit(c,'command.queued',identifier,{'machine_id':machine,'fingerprint':fingerprint,'caller':'hermes' if ai_job else 'external' if external else 'administrator'})
        if incident: store.timeline(c,incident,'command_queued','Shell command '+identifier+' '+state+'; hash '+fingerprint,actor='hermes' if ai_job else 'user')
    return identifier


def admitted_execution(c,identifier):
    """Preapproved queued work can finish after success, but takeover/cancel fences it."""
    from .codex_mode import permission
    job=c.execute('SELECT * FROM ai_jobs WHERE id=?',(identifier,)).fetchone()
    return bool(job and job['command_tools'] and permission(c,job,admitted=True))


def permitted(c,job,now):
    policy=c.execute('SELECT * FROM command_policies WHERE machine_id=?',(job['machine_id'],)).fetchone()
    agent=c.execute('SELECT revoked,capabilities FROM agents WHERE id=?',(job['agent_id'],)).fetchone()
    incident=c.execute('SELECT closed,status FROM incidents WHERE id=?',(job['incident_id'],)).fetchone() if job['incident_id'] else None
    return bool(job['expires']>now and policy and policy['enabled'] and policy['version']==job['policy_version'] and agent and not agent['revoked'] and json.loads(agent['capabilities']).get('shell_commands') is True and (not job['incident_id'] or (incident and incident['closed'] is None and incident['status']!='Resolved')) and (not job['ai_job_id'] or (policy['hermes'] and ((policy['approval'] in ('required','guarded') and job['requires_approval']) or admitted_execution(c,job['ai_job_id'])))))


def poll(c,store,vault,agent_id,now):
    for job in c.execute("SELECT * FROM command_jobs WHERE agent_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling')",(agent_id,)).fetchall():
        if not permitted(c,job,now):
            c.execute('UPDATE command_jobs SET state=? WHERE id=?',('cancelled' if job['state'] in ('awaiting','pending') else 'unknown',job['id']))
        elif job['state'] in ('dispatched','running','cancelling') and job['dispatched']+job['timeout']+90<now:
            c.execute("UPDATE command_jobs SET state='unknown' WHERE id=?",(job['id'],))
    job=c.execute("SELECT * FROM command_jobs WHERE agent_id=? AND state='pending' ORDER BY created LIMIT 1",(agent_id,)).fetchone()
    if not job: return []
    token=uid()
    # Commit before delivery. Ambiguous dispatch is never repeated.
    c.execute("UPDATE command_jobs SET state='dispatched',dispatch_token=?,dispatched=? WHERE id=?",(token,now,job['id']))
    store.audit(c,'command.dispatched',job['id'],actor='monitor')
    return [{'id':job['id'],'command':vault.decrypt(job['command']),'timeout':job['timeout'],'output_limit':job['output_limit'],'dispatch_token':token,'expires':job['expires']}]


def permission(store,agent_id,payload):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job=c.execute('SELECT * FROM command_jobs WHERE id=? AND agent_id=?',(payload.get('id'),agent_id)).fetchone()
        allowed=bool(job and job['dispatch_token']==payload.get('dispatch_token') and job['state'] in ('dispatched','running') and permitted(c,job,time.time()))
        if allowed: c.execute("UPDATE command_jobs SET state='running' WHERE id=?",(job['id'],))
        return {'allowed':allowed}


def complete(store,agent_id,payload):
    result=payload.get('result')
    if not isinstance(result,dict) or set(result)!={'state','exit_code','stdout','stderr','truncated'} or result['state'] not in ('completed','failed','cancelled','unknown') or (result['exit_code'] is not None and type(result['exit_code']) is not int) or type(result['truncated']) is not bool or any(not isinstance(result[k],str) or len(result[k].encode())>65536 for k in ('stdout','stderr')):
        raise ValueError('Invalid bounded command result.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job=c.execute('SELECT * FROM command_jobs WHERE id=? AND agent_id=?',(payload.get('id'),agent_id)).fetchone()
        if not job or not job['dispatch_token'] or job['dispatch_token']!=payload.get('dispatch_token'): raise ValueError('Unknown command dispatch.')
        if job['result']: return {'status':'duplicate'}
        if job['state'] not in ('dispatched','running','cancelling','unknown'): raise ValueError('Command was not dispatched.')
        result['truncated']=result['truncated'] or any(len(result[k])>16000 for k in ('stdout','stderr'))
        result={**result,'stdout':redact(result['stdout'])[:job['output_limit']],'stderr':redact(result['stderr'])[:job['output_limit']]}
        c.execute('UPDATE command_jobs SET state=?,result=?,completed=? WHERE id=?',(result['state'],json.dumps(result),time.time(),job['id']))
        store.audit(c,'command.'+result['state'],job['id'],actor='agent')
        if job['incident_id']: store.timeline(c,job['incident_id'],'command_result',job['id']+' '+result['state']+' exit '+str(result['exit_code']),actor='agent')
        return {'status':'accepted'}


def decide(store,identifier,operation,fingerprint=None):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job=c.execute('SELECT * FROM command_jobs WHERE id=?',(identifier,)).fetchone()
        if not job: raise ValueError('Unknown command.')
        if operation=='approve':
            if job['state']!='awaiting' or job['fingerprint']!=fingerprint or not permitted(c,job,time.time()): raise ValueError('Command identity/policy has changed or expired.')
            state='pending'
        elif operation=='cancel':
            if job['state'] in TERMINAL: return
            state='cancelled' if job['state'] in ('pending','awaiting') else 'cancelling'
        elif operation=='reconcile':
            if job['state']!='unknown': raise ValueError('Only unknown commands require reconciliation.')
            state='cancelled'
        else: raise ValueError('Unknown command decision.')
        c.execute('UPDATE command_jobs SET state=? WHERE id=?',(state,identifier))
        store.audit(c,'command.'+operation,identifier,{'fingerprint':job['fingerprint']})


def view(store,vault,identifier):
    rows=store.rows('SELECT * FROM command_jobs WHERE id=?',(identifier,))
    if not rows: raise ValueError('Unknown command.')
    row=rows[0]
    return {'id':row['id'],'machine_id':row['machine_id'],'incident_id':row['incident_id'],'ai_job_id':row['ai_job_id'],'state':row['state'],'command':redact(vault.decrypt(row['command'])),'fingerprint':row['fingerprint'],'result':json.loads(row['result']) if row['result'] else None}
