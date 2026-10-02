"""Explicit manual power proposals. No autonomous power or replay of ambiguous writes."""
import hashlib
import json
import re
import secrets
import time
from urllib.parse import quote
import requests
from .db import uid
from .proxmox import Client,normalize

ACTIVE="('dispatched','authorized','verifying','unknown')"


def configure(store,vault,machine_id,backend,connection_id=None,token_id='',secret='',enabled=False,validated=False,confirm=False):
    if not confirm or backend not in ('agent','proxmox'):
        raise ValueError('Explicitly confirm an application target and choose a supported backend.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        machine=c.execute('SELECT * FROM machines WHERE id=?',(machine_id,)).fetchone()
        objects=c.execute('SELECT * FROM proxmox_objects WHERE machine_id=? AND present=1',(machine_id,)).fetchall()
        if not machine or any(o['kind'] in ('node','storage') for o in objects):
            raise ValueError('Proxmox nodes and storage are protected; only application guests/hosts are eligible.')
        obj=next((o for o in objects if o['kind'] in ('qemu','lxc') and not o['template']),None)
        if backend=='proxmox':
            connection=c.execute('SELECT * FROM proxmox_connections WHERE id=?',(connection_id,)).fetchone() if connection_id else c.execute('SELECT * FROM proxmox_connections WHERE cluster_id=? ORDER BY id LIMIT 1',(obj['cluster_id'],)).fetchone() if obj else None
            if not obj or not connection or connection['cluster_id']!=obj['cluster_id'] or not connection['token_id'] or not connection['token_secret']:
                raise ValueError('Choose a configured Proxmox connection in the linked guest cluster.')
            connection_id=connection['id'];token_id=None;secret=None
        else:
            if not c.execute('SELECT 1 FROM agents WHERE machine_id=? AND revoked=0',(machine_id,)).fetchone():
                raise ValueError('Enroll the host agent first.')
            connection_id=None;token_id=None;secret=None
        if c.execute('SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN '+ACTIVE,(machine_id,)).fetchone():
            raise ValueError('Reconcile the existing power execution before replacing its policy.')
        old=c.execute('SELECT version FROM power_policies WHERE machine_id=?',(machine_id,)).fetchone()
        version=old[0]+1 if old else 1
        c.execute('INSERT INTO power_policies VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(machine_id) DO UPDATE SET backend=excluded.backend,object_id=excluded.object_id,connection_id=excluded.connection_id,token_id=excluded.token_id,token_secret=excluded.token_secret,enabled=excluded.enabled,validated=excluded.validated,version=excluded.version',(machine_id,backend,obj['id'] if backend=='proxmox' else None,connection_id,token_id,vault.encrypt(secret) if secret else None,int(enabled),int(validated),version))
        c.execute("UPDATE machines SET recovery_role='application' WHERE id=?",(machine_id,))
        c.execute("UPDATE power_jobs SET state='cancelled' WHERE machine_id=? AND state IN ('awaiting','approved')",(machine_id,))
        store.audit(c,'power.policy_configured',machine_id,{'backend':backend,'enabled':bool(enabled),'validated':bool(validated)})


def eligible(c,machine_id,operation,now):
    policy=c.execute('SELECT * FROM power_policies WHERE machine_id=?',(machine_id,)).fetchone()
    machine=c.execute('SELECT * FROM machines WHERE id=?',(machine_id,)).fetchone()
    if not policy or not policy['enabled'] or not policy['validated'] or not machine or machine['recovery_role']!='application':
        raise ValueError('Power controls are disabled, protected or unvalidated.')
    if operation not in ('start','restart','shutdown') or c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND kind IN ('node','storage')",(machine_id,)).fetchone():
        raise ValueError('Unsupported operation or protected infrastructure.')
    if c.execute("SELECT 1 FROM ai_jobs j JOIN incidents i ON i.id=j.incident_id WHERE i.machine_id=? AND j.state IN ('pending','dispatching','running','unknown')",(machine_id,)).fetchone() or c.execute('SELECT 1 FROM action_proposals p JOIN agents a ON a.id=p.agent_id WHERE a.machine_id=? AND p.state IN '+ACTIVE,(machine_id,)).fetchone() or c.execute("SELECT 1 FROM diagnostic_jobs d JOIN agents a ON a.id=d.agent_id WHERE a.machine_id=? AND d.state IN ('pending','leased') AND d.expires>?",(machine_id,now)).fetchone():
        raise ValueError('Finish outstanding investigation, diagnostics and recovery before power operations.')
    obj=agent=None
    if policy['backend']=='proxmox':
        obj=c.execute('SELECT * FROM proxmox_objects WHERE id=? AND machine_id=? AND present=1 AND template=0',(policy['object_id'],machine_id)).fetchone()
        if not obj or obj['kind'] not in ('qemu','lxc') or obj['missing_since'] is not None or not 0<=now-obj['last_seen']<=180 or obj['status']!=('stopped' if operation=='start' else 'running'):
            raise ValueError('Refresh inventory: this exact guest must be fresh and in the expected power state.')
    else:
        if operation=='start': raise ValueError('Start requires a linked Proxmox guest.')
        agent=c.execute('SELECT * FROM agents WHERE machine_id=? AND revoked=0',(machine_id,)).fetchone()
        cap=json.loads(agent['capabilities']) if agent else {}
        if not agent or not agent['action_credential_digest'] or not agent['last_seen'] or not 0<=now-agent['last_seen']<=180 or 'host_'+operation not in cap.get('power_operations',[]):
            raise ValueError('A fresh agent must advertise locally validated power permission and a separate action credential.')
        telemetry=json.loads(agent['telemetry'] or '{}')
        if telemetry.get('uptime_seconds',0)<=0 or not agent['sampled_at'] or not 0<=now-agent['sampled_at']<=180:
            raise ValueError('A fresh host uptime sample is required.')
    return policy,obj,agent


def propose(store,machine_id,operation,reason,now=None):
    now=time.time() if now is None else now
    if not isinstance(reason,str) or not 1<=len(reason.strip())<=1000: raise ValueError('Explain the power operation (1–1000 characters).')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute("SELECT 1 FROM proxmox_api_jobs WHERE machine_id=? AND state IN ('dispatched','unknown')",(machine_id,)).fetchone(): raise ValueError('Reconcile Proxmox API operations before power controls.')
        if c.execute("SELECT 1 FROM command_jobs WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(machine_id,)).fetchone(): raise ValueError('Complete or reconcile remote commands before power operations.')
        policy,obj,agent=eligible(c,machine_id,operation,now)
        if c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(machine_id,)).fetchone(): raise ValueError('A power proposal or unresolved execution already exists.')
        if c.execute('SELECT 1 FROM power_jobs WHERE machine_id=? AND dispatched>?',(machine_id,now-300)).fetchone(): raise ValueError('Five-minute power cooldown is active.')
        data={'machine_id':machine_id,'backend':policy['backend'],'operation':operation,'reason':reason.strip(),'impact':'Host services and network sessions may be interrupted; shutdown removes availability.','verification':'Fresh guest power state and completed Proxmox task; agent restart requires independently observed new uptime. Agent shutdown requires manual confirmation.','expires':now+300,'target':{'object_id':obj['id'],'generation':obj['generation'],'cluster_id':obj['cluster_id'],'resource':obj['object_key'],'node':obj['node'],'baseline_uptime':json.loads(obj['metrics']).get('uptime')} if obj else {'agent_id':agent['id'],'baseline_uptime':json.loads(agent['telemetry'])['uptime_seconds']}}
        payload=json.dumps(data,sort_keys=True,separators=(',',':'));fingerprint=hashlib.sha256(payload.encode()).hexdigest();identifier=uid()
        c.execute("INSERT INTO power_jobs(id,machine_id,agent_id,payload,payload_hash,state,created,expires,policy_version) VALUES(?,?,?,?,?,'awaiting',?,?,?)",(identifier,machine_id,agent['id'] if agent else None,payload,fingerprint,now,now+300,policy['version']))
        store.audit(c,'power.proposed',identifier,{'machine_id':machine_id,'operation':operation,'payload_hash':fingerprint})
        return identifier


def revalidate(c,row,now):
    data=json.loads(row['payload']);policy,obj,agent=eligible(c,row['machine_id'],data['operation'],now)
    if policy['version']!=row['policy_version'] or row['expires']<=now: raise ValueError('Power policy changed or proposal expired.')
    if obj and any(obj[k]!=data['target'][v] for k,v in (('id','object_id'),('generation','generation'),('node','node'),('object_key','resource'),('cluster_id','cluster_id'))): raise ValueError('Guest migrated or identity changed; review a new proposal.')
    if agent and agent['id']!=row['agent_id']: raise ValueError('Agent identity changed.')
    return policy,data


def decide(store,identifier,fingerprint,decision,now=None):
    now=time.time() if now is None else now
    if decision not in ('approve','deny','cancel','reconcile'): raise ValueError('Unknown power decision.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT * FROM power_jobs WHERE id=?',(identifier,)).fetchone()
        if not row or not secrets.compare_digest(row['payload_hash'],str(fingerprint)): raise ValueError('Power proposal hash changed.')
        if decision=='reconcile':
            if row['state']!='unknown': raise ValueError('Only an unknown outcome can be acknowledged after independent manual checking.')
            state='reviewed_unknown'
        else:
            if row['state'] not in (('awaiting','approved') if decision=='cancel' else ('awaiting',)): raise ValueError('Power proposal is no longer awaiting this decision.')
            if decision=='approve': revalidate(c,row,now)
            state={'approve':'approved','deny':'denied','cancel':'cancelled'}[decision]
        c.execute('UPDATE power_jobs SET state=? WHERE id=?',(state,identifier));store.audit(c,'power.'+state,identifier,{'payload_hash':fingerprint})


def consume(c,store,row,now):
    revalidate(c,row,now)
    token=secrets.token_urlsafe(32)
    c.execute("UPDATE power_jobs SET state='dispatched',dispatch_token=?,dispatched=? WHERE id=?",(token,now,row['id']))
    store.audit(c,'power.dispatched',row['id'])
    return token


def poll(c,store,agent_id,now):
    row=c.execute("SELECT * FROM power_jobs WHERE agent_id=? AND state='approved' ORDER BY created LIMIT 1",(agent_id,)).fetchone()
    if not row: return []
    try: token=consume(c,store,row,now)
    except ValueError:
        c.execute("UPDATE power_jobs SET state='cancelled' WHERE id=?",(row['id'],));store.audit(c,'power.precondition_changed',row['id']);return []
    data=json.loads(row['payload'])
    return [{'id':row['id'],'proposal_hash':row['payload_hash'],'operation':'host_'+data['operation'],'parameters':{},'expires':min(row['expires'],now+60),'dispatch_token':token}]


def authorize(store,agent_id,payload,now=None):
    now=time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');row=c.execute("SELECT * FROM power_jobs WHERE id=? AND agent_id=? AND state='dispatched'",(payload.get('id'),agent_id)).fetchone()
        if not row or row['dispatch_token']!=payload.get('dispatch_token') or row['payload_hash']!=payload.get('proposal_hash') or now-row['dispatched']>=60: raise ValueError('Power delivery changed, expired or already authorized.')
        _,data=revalidate(c,row,now)
        c.execute("UPDATE power_jobs SET state='authorized' WHERE id=?",(row['id'],));store.audit(c,'power.authorized',row['id'],actor='agent')
        return {'status':'authorized','proposal_hash':row['payload_hash'],'operation':'host_'+data['operation'],'parameters':{}}


def complete(store,agent_id,payload,now=None):
    from .diagnostics import redact
    now=time.time() if now is None else now
    if not isinstance(payload,dict) or payload.get('status') not in ('completed','failed','unknown') or not isinstance(payload.get('output'),str) or len(payload['output'])>16000: raise ValueError('Invalid power result.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT * FROM power_jobs WHERE id=? AND agent_id=?',(payload.get('id'),agent_id)).fetchone()
        if not row or row['dispatch_token']!=payload.get('dispatch_token'): raise ValueError('Unknown power delivery.')
        if row['completed'] is not None: return 'duplicate'
        if row['state'] not in ('authorized','unknown') and not(row['state']=='dispatched' and payload['status']=='unknown'): raise ValueError('Power execution was not authorized.')
        state='verifying' if payload['status']=='completed' else payload['status']
        c.execute('UPDATE power_jobs SET state=?,result=?,completed=? WHERE id=?',(state,json.dumps({'status':payload['status'],'output':redact(payload['output'])}),now,row['id']));store.audit(c,'power.result',row['id'],{'status':payload['status']},actor='agent')
    return 'accepted'


def task_connection(policy,connection):
    return dict(connection)


def dispatch_proxmox(store,vault,now):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');row=c.execute("SELECT p.* FROM power_jobs p JOIN power_policies s ON s.machine_id=p.machine_id WHERE p.state='approved' AND s.backend='proxmox' ORDER BY p.created LIMIT 1").fetchone()
        if not row: return False
        try:
            policy,data=revalidate(c,row,now);connection=c.execute('SELECT * FROM proxmox_connections WHERE id=?',(policy['connection_id'],)).fetchone()
            if not connection: raise ValueError('Missing connection.')
            connection=task_connection(policy,connection);consume(c,store,row,now)
        except ValueError:
            c.execute("UPDATE power_jobs SET state='cancelled' WHERE id=?",(row['id'],));return True
        row=dict(row)
    state='unknown';result='Power request acceptance is unknown; never automatically retry.';task=None
    try:
        target=data['target'];client=Client(connection,vault)
        current=next((r for r in normalize(client.get('/cluster/resources')) if r['key']==target['resource'] and r['kind'] in ('qemu','lxc')),None)
        if not current or current['node']!=target['node'] or current['template'] or current['status']!=('stopped' if data['operation']=='start' else 'running'):
            state='cancelled';result='Fresh API precondition changed; no power request sent.'
        else:
            kind,vmid=target['resource'].split('/',1)
            if kind not in ('qemu','lxc') or not vmid.isdigit() or not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}',target['node']): raise ValueError('Invalid guest path.')
            operation='reboot' if data['operation']=='restart' else data['operation']
            response=requests.post(connection['url'].rstrip('/')+'/api2/json/nodes/'+quote(target['node'],safe='')+'/'+kind+'/'+vmid+'/status/'+operation,headers=client.headers,data={} if operation=='start' else {'timeout':60} if operation=='reboot' else {'timeout':60,'forceStop':0},timeout=(3,8),verify=connection['ca'] or True,allow_redirects=False,stream=True)
            try:
                if response.status_code!=200:
                    state='failed' if 400<=response.status_code<500 else 'unknown';result='Power API returned HTTP '+str(response.status_code)+'. No automatic retry.'
                else:
                    raw=response.raw.read(4097)
                    if len(raw)>4096: raise ValueError('Oversized task response.')
                    task=json.loads(raw)['data']
                    if not isinstance(task,str) or not task.startswith('UPID:') or len(task)>256: raise ValueError('Invalid task receipt.')
                    state='verifying';result='Proxmox accepted an asynchronous task; outcome is not yet verified.'
            finally: response.close()
    except Exception:
        pass # Ambiguous write is never replayed or sent via a fallback endpoint.
    with store.connect() as c:
        c.execute('UPDATE power_jobs SET state=?,task=?,result=? WHERE id=?',(state,task,result,row['id']));store.audit(c,'power.api_result',row['id'],{'state':state})
    return True


def tick(store,vault,now=None):
    now=time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute("UPDATE power_jobs SET state='expired' WHERE expires<=? AND state IN ('awaiting','approved')",(now,))
        c.execute("UPDATE power_jobs SET state='unknown',result='No execution result; independent verification required. Never replay automatically.' WHERE state IN ('dispatched','authorized') AND dispatched+90<=?",(now,))
        rows=[dict(r) for r in c.execute("SELECT * FROM power_jobs WHERE state IN ('authorized','verifying','unknown') ORDER BY created LIMIT 10")]
    for row in rows:
        data=json.loads(row['payload']);state=None;note=None
        if data['backend']=='agent':
            agent=store.rows('SELECT * FROM agents WHERE id=? AND revoked=0',(row['agent_id'],))
            if data['operation']=='restart' and agent:
                a=agent[0];uptime=json.loads(a['telemetry'] or '{}').get('uptime_seconds')
                if a['sampled_at'] and a['sampled_at']>row['dispatched'] and 0<=now-a['sampled_at']<=180 and type(uptime) in (int,float) and uptime<data['target']['baseline_uptime']:
                    state='verified';note='Fresh agent telemetry independently shows a new host uptime.'
        elif row['state']=='verifying' and row['task']:
            policy=store.rows('SELECT * FROM power_policies WHERE machine_id=?',(row['machine_id'],))
            connections=store.rows('SELECT * FROM proxmox_connections WHERE id=?',(policy[0]['connection_id'],)) if policy else []
            if connections:
                try:
                    client=Client(task_connection(policy[0],connections[0]),vault);target=data['target']
                    task=client.get('/nodes/'+quote(target['node'],safe='')+'/tasks/'+quote(row['task'],safe='')+'/status')
                    if task.get('status')=='stopped':
                        if task.get('exitstatus')!='OK': state='failed';note='Proxmox task failed; no automatic retry.'
                        else:
                            current=next((r for r in normalize(client.get('/cluster/resources')) if r['key']==target['resource']),None)
                            expected='stopped' if data['operation']=='shutdown' else 'running'
                            restart_proof=data['operation']!='restart' or (type(current['metrics'].get('uptime')) in (int,float) and type(target.get('baseline_uptime')) in (int,float) and current['metrics']['uptime']<target['baseline_uptime']) if current else False
                            if current and current['kind'] in ('qemu','lxc') and current['status']==expected and restart_proof: state='verified';note='Completed task and fresh Proxmox state independently confirm the requested state.'
                except Exception: pass
        if not state and row['dispatched']+600<=now and row['state']!='unknown': state='unknown';note='Verification timed out; independently check the host before acknowledging this outcome.'
        if state:
            with store.connect() as c:
                c.execute('UPDATE power_jobs SET state=?,result=?,completed=? WHERE id=? AND state IN (\'authorized\',\'verifying\',\'unknown\')',(state,note,now,row['id']));store.audit(c,'power.'+state,row['id'])
    return dispatch_proxmox(store,vault,now)
