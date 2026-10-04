"""General token-authorized Proxmox requests, durable approval and no write replay."""
import hashlib,json,time,uuid
from urllib.parse import unquote
import requests
from .commands import ai_allowed
from .diagnostics import redact


def context(c,machine):
    objects=[dict(r) for r in c.execute('SELECT id,cluster_id,object_key,kind,node,status,generation,present,last_seen FROM proxmox_objects WHERE machine_id=?',(machine,))]
    clusters={r['cluster_id'] for r in objects}
    connections=[{'id':r['id'],'name':r['name']} for r in c.execute('SELECT id,name,cluster_id FROM proxmox_connections') if r['cluster_id'] in clusters]
    recent=[{'id':r['id'],'state':r['state'],'result':redact(r['result'] or '')[:2000]} for r in c.execute('SELECT id,state,result FROM proxmox_api_jobs WHERE machine_id=? ORDER BY created DESC LIMIT 3',(machine,))]
    return {'objects':objects,'connections':connections,'recent_requests':recent,'note':'Linked inventory may be stale. Query current Proxmox state before changes; token permissions govern API access.'}


def policy(c,machine,ai_job=None,external=False):
    p=c.execute('SELECT * FROM command_policies WHERE machine_id=? AND enabled=1',(machine,)).fetchone()
    if not p or (ai_job and (not p['hermes'] or not ai_allowed(c,ai_job))) or (external and not p['external']):
        raise ValueError('Host operational permission unavailable.')
    return p


def binding(objects):
    return json.dumps([{k:r[k] for k in ('id','cluster_id','object_key','kind','node','generation','present')} for r in sorted(objects,key=lambda r:r['id'])],sort_keys=True)


def safe(value):
    from .ai import evidence_snapshot
    if isinstance(value,str): return redact(value)
    if isinstance(value,dict): return {k:safe(v) for k,v in evidence_snapshot(value).items()}
    if isinstance(value,list): return [safe(v) for v in value]
    return value


def view(store,vault,identifier):
    with store.connect() as c:
        c.execute("UPDATE proxmox_api_jobs SET state='unknown' WHERE id=? AND state='dispatched' AND dispatched<?",(identifier,time.time()-60))
    rows=store.rows('SELECT * FROM proxmox_api_jobs WHERE id=?',(identifier,))
    if not rows: raise ValueError('Unknown Proxmox request.')
    r=rows[0]
    return {'id':r['id'],'machine_id':r['machine_id'],'ai_job_id':r['ai_job_id'],'state':r['state'],'fingerprint':r['fingerprint'],'request':safe(json.loads(vault.decrypt(r['payload']))),'result':json.loads(r['result']) if r['result'] else None}


def queue(store,vault,machine,payload,ai_job=None,external=False):
    identifier=payload.get('id') or str(uuid.uuid4());uuid.UUID(identifier)
    method=payload.get('method','GET');path=payload.get('path');params=payload.get('params',{})
    if method not in ('GET','POST','PUT','DELETE') or not isinstance(path,str) or not path.startswith('/') or len(path)>2000 or any(x in unquote(path) for x in ('..','?','#','\\','\x00')) or path.startswith('//'):
        raise ValueError('Use a relative Proxmox API path and GET/POST/PUT/DELETE.')
    if not isinstance(params,dict) or any(not isinstance(k,str) or not isinstance(v,(str,int,float,bool)) for k,v in params.items()) or len(json.dumps(params))>16000:
        raise ValueError('Supply bounded scalar Proxmox parameters.')
    data={'connection_id':payload.get('connection_id'),'method':method,'path':path,'params':params}
    fingerprint=hashlib.sha256(json.dumps([machine,ai_job,external,data],sort_keys=True).encode()).hexdigest()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');p=policy(c,machine,ai_job,external)
        linked=context(c,machine)
        if data['connection_id'] not in [r['id'] for r in linked['connections']]: raise ValueError('Choose a connection belonging to the host linked Proxmox namespace.')
        prior=c.execute('SELECT fingerprint FROM proxmox_api_jobs WHERE id=?',(identifier,)).fetchone()
        if prior:
            if prior['fingerprint']!=fingerprint: raise ValueError('Request UUID reused with different parameters.')
            return identifier
        if method!='GET' and (c.execute("SELECT 1 FROM command_jobs WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(machine,)).fetchone() or c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(machine,)).fetchone()): raise ValueError('Complete or reconcile other host operations before Proxmox writes.')
        if c.execute("SELECT 1 FROM proxmox_api_jobs WHERE machine_id=? AND state IN ('dispatched','unknown')",(machine,)).fetchone(): raise ValueError('Reconcile the outstanding Proxmox request first.')
        from .reliability import repair_budget
        repair_budget(c,vault,ai_job,api=data)
        from .host_access import requires_approval
        approval=requires_approval(p['approval'],method=method)
        c.execute('INSERT INTO proxmox_api_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,machine,ai_job,vault.encrypt(json.dumps(data)),fingerprint,p['version'],binding(linked['objects']),'awaiting',time.time(),time.time()+600,None,None,None))
        store.audit(c,'proxmox.api_proposed',identifier,{'machine_id':machine,'method':method,'fingerprint':fingerprint})
    if not approval: execute(store,vault,identifier,ai_job,external)
    return identifier


def execute(store,vault,identifier,ai_job=None,external=False):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT * FROM proxmox_api_jobs WHERE id=?',(identifier,)).fetchone()
        if not r or r['state']!='awaiting': return
        p=policy(c,r['machine_id'],ai_job,external)
        data=json.loads(vault.decrypt(r['payload']));linked=context(c,r['machine_id'])
        from .reliability import repair_budget
        repair_budget(c,vault,ai_job,api=data)
        from .host_access import requires_approval
        requires_approval(p['approval'],method=data['method'])
        if p['version']!=r['policy_version'] or r['expires']<=time.time() or binding(linked['objects'])!=r['binding']:
            raise ValueError('Policy or Proxmox binding changed; submit a new reviewed request.')
        if data['method']!='GET' and (c.execute("SELECT 1 FROM command_jobs WHERE machine_id=? AND state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",(r['machine_id'],)).fetchone() or c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",(r['machine_id'],)).fetchone()): raise ValueError('Other host operations are outstanding.')
        connection=c.execute('SELECT * FROM proxmox_connections WHERE id=?',(data['connection_id'],)).fetchone()
        if not connection or data['connection_id'] not in [x['id'] for x in linked['connections']]: raise ValueError('Proxmox connection no longer linked.')
        c.execute("UPDATE proxmox_api_jobs SET state='dispatched',dispatched=? WHERE id=?",(time.time(),identifier))
        store.audit(c,'proxmox.api_dispatched',identifier,{'fingerprint':r['fingerprint']})
    # The irreversible dispatch record commits before any network request.
    result={'note':'Delivery/outcome unknown; never replay automatically.'};state='unknown'
    try:
        with requests.request(data['method'],connection['url'].rstrip('/')+'/api2/json'+data['path'],headers={'Authorization':'PVEAPIToken='+connection['token_id']+'='+vault.decrypt(connection['token_secret'])},params=data['params'] if data['method']=='GET' else None,data=data['params'] if data['method']!='GET' else None,timeout=(3,15),verify=connection['ca'] or True,allow_redirects=False,stream=True) as response:
            raw=response.raw.read(65537)
            if len(raw)>65536: raise ValueError('Proxmox response too large; inspect outcome independently.')
            try: body=safe(json.loads(raw))
            except ValueError: body=redact(raw.decode('utf-8','replace'))
            result={'http_status':response.status_code,'body':body}
            state='completed' if 200<=response.status_code<300 else ('failed' if 400<=response.status_code<500 else 'unknown')
            result['note']='HTTP acceptance is not task completion. Query the returned UPID and fresh resource status to verify effects.' if state=='completed' else 'Proxmox rejected this request; inspect the HTTP status and response.' if state=='failed' else 'Proxmox returned a server error; inspect this UUID and resource state before another operation.'
    except Exception as exc:
        result['error_type']=type(exc).__name__
        result['note']='Proxmox request failed; inspect this UUID before issuing another operation. No automatic replay.'
    with store.connect() as c:
        c.execute('UPDATE proxmox_api_jobs SET state=?,result=?,completed=? WHERE id=?',(state,json.dumps(result),time.time(),identifier))
        store.audit(c,'proxmox.api_result',identifier,{'state':state})


def decide(store,vault,identifier,operation,fingerprint):
    rows=store.rows('SELECT * FROM proxmox_api_jobs WHERE id=?',(identifier,))
    if not rows or rows[0]['fingerprint']!=fingerprint: raise ValueError('Exact Proxmox request fingerprint required.')
    r=rows[0]
    if operation=='approve': execute(store,vault,identifier);return
    if (operation=='cancel' and r['state']=='awaiting') or (operation=='reconcile' and r['state']=='unknown'):
        with store.connect() as c:
            c.execute("UPDATE proxmox_api_jobs SET state='cancelled' WHERE id=? AND state=?",(identifier,r['state']))
            store.audit(c,'proxmox.api_'+operation,identifier,{})
    else: raise ValueError('Only queued requests can be cancelled; unknown effects require independent reconciliation.')
