"""Explicit manual power proposals. No autonomous power or replay of ambiguous writes."""
import hashlib
import json
import re
import secrets
import time
from urllib.parse import quote
import requests
from .db import uid
from .proxmox import Client,normalize,cluster_inventory

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


def automatic_policy(c,machine_id):
    machine=c.execute('SELECT id FROM machines WHERE id=?',(machine_id,)).fetchone()
    if not machine: raise ValueError('Unknown host.')
    obj=c.execute("SELECT * FROM proxmox_objects WHERE machine_id=? AND present=1 ORDER BY CASE kind WHEN 'node' THEN 0 ELSE 1 END LIMIT 1",(machine_id,)).fetchone()
    agent=c.execute('SELECT * FROM agents WHERE machine_id=? AND revoked=0',(machine_id,)).fetchone()
    connection=None
    if obj:
        if obj['kind'] not in ('node','qemu','lxc') or obj['template']: raise ValueError('This resource has no power controls.')
        connection=c.execute("SELECT * FROM proxmox_connections WHERE cluster_id=? AND token_id<>'' AND token_secret IS NOT NULL ORDER BY id LIMIT 1",(obj['cluster_id'],)).fetchone()
        if not connection: raise ValueError('No configured Proxmox connection is available.')
    elif not agent: raise ValueError('Link a Proxmox resource or enroll a host agent.')
    legacy=c.execute('SELECT version FROM power_policies WHERE machine_id=?',(machine_id,)).fetchone()
    namespace=[obj['id'],obj['generation'],obj['cluster_id']] if obj else [agent['id']]
    version=int.from_bytes(hashlib.sha256(json.dumps([namespace,legacy[0] if legacy else 0]).encode()).digest()[:7],'big')
    return {'backend':'proxmox' if obj else 'agent','connection_id':connection['id'] if connection else None,'version':version},obj,agent if not obj else None


def permitted_connection(store,vault,obj,cached=False):
    for connection in store.rows('SELECT * FROM proxmox_connections WHERE cluster_id=? ORDER BY id',(obj['cluster_id'],)):
        if not connection['token_id'] or not connection['token_secret']: continue
        fingerprint=hashlib.sha256(json.dumps([connection['url'],connection['token_id'],connection['token_secret'],connection['ca'],obj['node'],obj['object_key']]).encode()).hexdigest()
        key='power_permission:'+connection['id']+':'+obj['id']
        saved=store.setting(key,{}) if cached else {}
        if saved.get('fingerprint')==fingerprint and 0<=time.time()-saved.get('at',0)<60:
            allowed=saved.get('allowed',False)
        else:
            try: allowed=Client(connection,vault).power_allowed(obj)
            except Exception: allowed=False
            if cached: store.save(key,{'fingerprint':fingerprint,'at':time.time(),'allowed':allowed})
        if allowed: return connection
    raise ValueError('Proxmox power permission is unavailable for this resource.')


def availability(store,vault,machine_id):
    result={'start':False,'restart':False,'shutdown':False,'reason':None}
    try:
        with store.connect() as c: policy,obj,agent=automatic_policy(c,machine_id)
        if obj: permitted_connection(store,vault,obj,cached=True)
        with store.connect() as c:
            if c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND (state IN ('awaiting','approved','dispatched','authorized','verifying','unknown') OR dispatched>?)",(machine_id,time.time()-300)).fetchone():
                raise ValueError('A power request is pending, needs verification, or is cooling down.')
            if c.execute("SELECT 1 FROM command_jobs WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(machine_id,)).fetchone() or c.execute("SELECT 1 FROM proxmox_api_jobs WHERE machine_id=? AND state IN ('dispatched','unknown')",(machine_id,)).fetchone():
                raise ValueError('Finish or reconcile the current host operation first.')
        for operation in ('start','restart','shutdown'):
            try:
                with store.connect() as c: eligible(c,machine_id,operation,time.time())
                result[operation]=True
            except ValueError: pass
        if not any(result[k] for k in ('start','restart','shutdown')): result['reason']='Power controls are currently unavailable.'
    except ValueError as exc: result['reason']=str(exc)
    return result


def eligible(c,machine_id,operation,now):
    policy,obj,agent=automatic_policy(c,machine_id)
    if operation not in ('start','restart','shutdown'): raise ValueError('Unsupported power operation.')
    if c.execute("SELECT 1 FROM ai_jobs j JOIN incidents i ON i.id=j.incident_id WHERE i.machine_id=? AND j.state IN ('pending','dispatching','running','unknown')",(machine_id,)).fetchone() or c.execute('SELECT 1 FROM action_proposals p JOIN agents a ON a.id=p.agent_id WHERE a.machine_id=? AND p.state IN '+ACTIVE,(machine_id,)).fetchone() or c.execute("SELECT 1 FROM diagnostic_jobs d JOIN agents a ON a.id=d.agent_id WHERE a.machine_id=? AND d.state IN ('pending','leased') AND d.expires>?",(machine_id,now)).fetchone():
        raise ValueError('Finish outstanding investigation, diagnostics and recovery before power operations.')
    if policy['backend']=='proxmox':
        expected='stopped' if operation=='start' else 'online' if obj['kind']=='node' else 'running'
        if operation=='start' and obj['kind']=='node': raise ValueError('Start requires a linked Proxmox guest.')
        if obj['missing_since'] is not None or not 0<=now-obj['last_seen']<=180 or obj['status']!=expected:
            raise ValueError('Refresh inventory: this exact resource must be fresh and in the expected power state.')
    else:
        if operation=='start': raise ValueError('Start requires a linked Proxmox guest.')
        cap=json.loads(agent['capabilities']) if agent else {}
        if not agent or not agent['last_seen'] or not 0<=now-agent['last_seen']<=180 or 'host_'+operation not in cap.get('power_operations',[]):
            raise ValueError('A fresh agent must advertise locally validated power permission.')
        telemetry=json.loads(agent['telemetry'] or '{}')
        if telemetry.get('uptime_seconds',0)<=0 or not agent['sampled_at'] or not 0<=now-agent['sampled_at']<=180:
            raise ValueError('A fresh host uptime sample is required.')
    return policy,obj,agent


def propose(store,machine_id,operation,reason,now=None,vault=None):
    now=time.time() if now is None else now
    if not isinstance(reason,str) or not 1<=len(reason.strip())<=1000: raise ValueError('Explain the power operation (1–1000 characters).')
    connection=None;preflight=None
    if vault is not None:
        with store.connect() as c: _,preflight,_=automatic_policy(c,machine_id)
        if preflight: connection=permitted_connection(store,vault,preflight)
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute("SELECT 1 FROM proxmox_api_jobs WHERE machine_id=? AND state IN ('dispatched','unknown')",(machine_id,)).fetchone(): raise ValueError('Reconcile Proxmox API operations before power controls.')
        if c.execute("SELECT 1 FROM command_jobs WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(machine_id,)).fetchone(): raise ValueError('Complete or reconcile remote commands before power operations.')
        policy,obj,agent=eligible(c,machine_id,operation,now)
        if preflight and (not obj or any(obj[k]!=preflight[k] for k in ('id','generation','node','cluster_id'))): raise ValueError('Linked resource changed during permission checking.')
        if c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(machine_id,)).fetchone(): raise ValueError('A power proposal or unresolved execution already exists.')
        if c.execute('SELECT 1 FROM power_jobs WHERE machine_id=? AND dispatched>?',(machine_id,now-300)).fetchone(): raise ValueError('Five-minute power cooldown is active.')
        data={'connection_id':connection['id'] if connection else policy['connection_id'],'machine_id':machine_id,'backend':policy['backend'],'operation':operation,'reason':reason.strip(),'impact':'Host services and network sessions may be interrupted; shutdown removes availability.','verification':'Fresh guest power state and completed Proxmox task; agent restart requires independently observed new uptime. Agent shutdown requires manual confirmation.','expires':now+300,'target':{'object_id':obj['id'],'generation':obj['generation'],'cluster_id':obj['cluster_id'],'resource':obj['object_key'],'node':obj['node'],'kind':obj['kind'],'baseline_uptime':json.loads(obj['metrics']).get('uptime')} if obj else {'agent_id':agent['id'],'baseline_uptime':json.loads(agent['telemetry'])['uptime_seconds']}}
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
        c.execute('BEGIN IMMEDIATE');row=c.execute("SELECT * FROM power_jobs WHERE state='approved' AND json_extract(payload,'$.backend')='proxmox' ORDER BY created LIMIT 1").fetchone()
        if not row: return False
        try:
            policy,data=revalidate(c,row,now);connection=c.execute('SELECT * FROM proxmox_connections WHERE id=?',(data.get('connection_id') or policy['connection_id'],)).fetchone()
            if not connection or connection['cluster_id']!=data['target']['cluster_id']: raise ValueError('Missing or changed connection.')
            connection=task_connection(policy,connection);consume(c,store,row,now)
        except ValueError:
            c.execute("UPDATE power_jobs SET state='cancelled' WHERE id=?",(row['id'],));return True
        row=dict(row)
    state='failed';result='Preflight unavailable; no power request sent.';task=None
    try:
        target=data['target'];client=Client(connection,vault)
        if not client.power_allowed({'kind':target.get('kind',target['resource'].split('/')[0]),'object_key':target['resource'],'node':target['node']}):
            state='failed';result='Proxmox power permission denied; no power request sent.'
            raise ValueError(result)
        current=next((r for r in normalize(client.get('/cluster/resources')) if r['key']==target['resource'] and r['kind'] in ('node','qemu','lxc')),None)
        if not current or current['node']!=target['node'] or current['template'] or current['status']!=('stopped' if data['operation']=='start' else 'online' if current['kind']=='node' else 'running'):
            state='cancelled';result='Fresh API precondition changed; no power request sent.'
        else:
            kind,vmid=target['resource'].split('/',1)
            operation='reboot' if data['operation']=='restart' else data['operation']
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}',target['node']): raise ValueError('Invalid node path.')
            if kind=='node':
                path='/nodes/'+quote(target['node'],safe='')+'/status';parameters={'command':operation}
            else:
                if kind not in ('qemu','lxc') or not vmid.isdigit(): raise ValueError('Invalid guest path.')
                path='/nodes/'+quote(target['node'],safe='')+'/'+kind+'/'+vmid+'/status/'+operation
                parameters={} if operation=='start' else {'timeout':60} if operation=='reboot' else {'timeout':60,'forceStop':0}
            state='unknown';result='Power request acceptance is unknown; never automatically retry.'
            response=requests.post(connection['url'].rstrip('/')+'/api2/json'+path,headers=client.headers,data=parameters,timeout=(3,8),verify=connection['ca'] or True,allow_redirects=False,stream=True)
            try:
                if response.status_code!=200:
                    state='failed' if 400<=response.status_code<500 else 'unknown';result='Power API returned HTTP '+str(response.status_code)+'. No automatic retry.'
                else:
                    raw=response.raw.read(4097)
                    if len(raw)>4096: raise ValueError('Oversized task response.')
                    task=json.loads(raw)['data']
                    if not (kind=='node' and task is None) and (not isinstance(task,str) or not task.startswith('UPID:') or len(task)>256): raise ValueError('Invalid task receipt.')
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
        elif row['state']=='verifying' and (row['task'] or data['target'].get('kind')=='node'):
            legacy=store.rows('SELECT connection_id FROM power_policies WHERE machine_id=?',(row['machine_id'],))
            connection_id=data.get('connection_id') or (legacy[0]['connection_id'] if legacy else None)
            connections=store.rows('SELECT * FROM proxmox_connections WHERE id=? AND cluster_id=?',(connection_id,data['target']['cluster_id']))
            if connections:
                try:
                    client=Client(connections[0],vault);target=data['target']
                    task={'status':'stopped','exitstatus':'OK'} if target.get('kind')=='node' else client.get('/nodes/'+quote(target['node'],safe='')+'/tasks/'+quote(row['task'],safe='')+'/status')
                    if task.get('status')=='stopped':
                        if task.get('exitstatus')!='OK': state='failed';note='Proxmox task failed; no automatic retry.'
                        else:
                            current=next((r for r in cluster_inventory(store,vault,connections[0])[0] if r['key']==target['resource']),None)
                            expected=('offline' if data['target'].get('kind')=='node' else 'stopped') if data['operation']=='shutdown' else ('online' if data['target'].get('kind')=='node' else 'running')
                            restart_proof=data['operation']!='restart' or (type(current['metrics'].get('uptime')) in (int,float) and type(target.get('baseline_uptime')) in (int,float) and current['metrics']['uptime']<target['baseline_uptime']) if current else False
                            if current and current['node']==target['node'] and current['kind'] in ('node','qemu','lxc') and current['status']==expected and restart_proof:
                                if target.get('kind')=='node' and data['operation']=='shutdown':
                                    state='unknown';note='The cluster reports this node offline; independently confirm shutdown before acknowledging the outcome.'
                                else:
                                    state='verified';note='Fresh Proxmox state independently confirms the requested state.'
                except Exception: pass
        if not state and row['dispatched']+600<=now and row['state']!='unknown': state='unknown';note='Verification timed out; independently check the host before acknowledging this outcome.'
        if state:
            with store.connect() as c:
                c.execute('UPDATE power_jobs SET state=?,result=?,completed=? WHERE id=? AND state IN (\'authorized\',\'verifying\',\'unknown\')',(state,note,now,row['id']));store.audit(c,'power.'+state,row['id'])
    return dispatch_proxmox(store,vault,now)
