"""Transactional, bounded telemetry history; the existing SMB worker exports it.

Only collected data columns are captured. Configuration, credentials, session
state and live database files are never exported.
"""
import gzip
import hashlib
import json
import math
import os
import re
import time
from pathlib import Path

MAX_RECORD=1024*1024
KINDS=('agent','discovery','network','metrics','integration','unifi','proxmox','check','diagnostic','command_result','power_result','change','ticket','audit','dashboard')
SECRET=re.compile(r'(?i)(password|passwd|secret|token|api.?key|authorization|cookie|credential|private.?key|environment|^env$)')


def sanitize(value,depth=0):
    if depth>24:return '[Depth limit]'
    if isinstance(value,dict):return {str(k):'[REDACTED]' if SECRET.search(str(k)) else sanitize(v,depth+1) for k,v in value.items()}
    if isinstance(value,list):return [sanitize(v,depth+1) for v in value]
    if isinstance(value,str):
        # Parse serialized JSON before text masking: a URL inside JSON must not
        # consume its closing quote and hide the remaining structured fields.
        if value.lstrip().startswith(('{','[')):
            try:return sanitize(json.loads(value),depth+1)
            except (ValueError,RecursionError):pass
        from .diagnostics import redact
        text=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----','[REDACTED PRIVATE KEY]',value,flags=re.S)
        text=re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~+/-]+',r'\1[REDACTED]',text)
        text=re.sub(r'(?i)([?&](?:[^=&\s]*(?:token|key|secret|password)[^=&\s]*)=)[^&\s]+',r'\1[REDACTED]',text)
        return redact(text,len(text))
    if type(value) is float and not math.isfinite(value):return None
    return value


def encode(value):
    try:
        result=json.dumps(sanitize(json.loads(value)),separators=(',',':'),allow_nan=False)
        if len(result.encode())>MAX_RECORD:return json.dumps({'truncated':True,'reason':'Collected record exceeds the 1 MiB archive limit.'})
        return result
    except (ValueError,TypeError,RecursionError):return json.dumps({'truncated':True,'reason':'Collected record could not be serialized.'})


# SQL expressions are application-owned, never user-supplied. Capture after the
# source write in the same transaction; a rolled-back heartbeat leaves no history.
SPECS=[
 ('agents','agent','NEW.machine_id','NEW.machine_id','coalesce(NEW.sampled_at,NEW.last_seen)',"json_object('agent_id',NEW.id,'version',NEW.version,'host_info',NEW.host_info,'capabilities',NEW.capabilities,'telemetry',NEW.telemetry)",'UPDATE OF telemetry,last_seen','NEW.last_seen IS NOT NULL'),
 ('agent_discovery','discovery','NEW.machine_id','NEW.machine_id','NEW.at',"json_object('inventory',NEW.data)",None,'1'),
 ('network_inventory','network','NEW.machine_id','NEW.machine_id','NEW.at',"json_object('interfaces',NEW.data)",None,'1'),
 ('metric_samples','metrics','NEW.entity_id',"coalesce((SELECT id FROM machines WHERE id=NEW.entity_id),(SELECT machine_id FROM proxmox_objects WHERE id=NEW.entity_id),(SELECT machine_id FROM integrations WHERE id=NEW.entity_id),(SELECT id FROM machines WHERE NEW.entity_id LIKE id||':container:%' LIMIT 1),(SELECT machine_id FROM integrations WHERE NEW.entity_id LIKE id||':%' LIMIT 1))",'NEW.at',"json_object('source',NEW.source,'metrics',NEW.metrics)",'INSERT','1'),
 ('integrations','integration','NEW.id','NEW.machine_id','NEW.at',"json_object('service_id',NEW.id,'name',NEW.name,'source',NEW.kind,'readings',NEW.snapshot)",None,'NEW.at IS NOT NULL'),
 ('unifi_devices','unifi','NEW.device_id','NEW.machine_id','NEW.last_seen',"json_object('connection_id',NEW.connection_id,'device_id',NEW.device_id,'readings',NEW.data)",None,'1'),
 ('unifi_connections','unifi','NEW.id','NEW.machine_id',"json_extract(NEW.snapshot,'$.sampled_at')","json_object('connection_id',NEW.id,'name',NEW.name,'source',NEW.kind,'readings',NEW.snapshot)",'UPDATE OF snapshot',"NEW.snapshot IS NOT NULL AND NEW.snapshot<>coalesce(OLD.snapshot,'')"),
 ('proxmox_objects','proxmox','NEW.id','NEW.machine_id','NEW.last_seen',"json_object('cluster_id',NEW.cluster_id,'kind',NEW.kind,'key',NEW.object_key,'generation',NEW.generation,'name',NEW.name,'node',NEW.node,'status',NEW.status,'present',NEW.present,'metrics',NEW.metrics)",None,'1'),
 ('observations','check','NEW.check_id',"(SELECT machine_id FROM checks WHERE id=NEW.check_id)",'NEW.at',"json_object('check_id',NEW.check_id,'health',NEW.health,'evidence',NEW.evidence)",'INSERT','1'),
 ('diagnostic_jobs','diagnostic','NEW.id',"(SELECT machine_id FROM agents WHERE id=NEW.agent_id)",'coalesce(NEW.completed,NEW.created)',"json_object('operation',NEW.operation,'state',NEW.state,'result',NEW.result)",'UPDATE OF result','NEW.result IS NOT NULL'),
 ('command_jobs','command_result','NEW.id','NEW.machine_id','coalesce(NEW.completed,NEW.created)',"json_object('incident_id',NEW.incident_id,'state',NEW.state,'result',NEW.result)",'UPDATE OF result','NEW.result IS NOT NULL'),
 ('power_jobs','power_result','NEW.id','NEW.machine_id','coalesce(NEW.completed,NEW.created)',"json_object('state',NEW.state,'result',NEW.result)",'UPDATE OF result','NEW.result IS NOT NULL'),
 ('change_events','change','NEW.id','NEW.machine_id','NEW.at',"json_object('entity',NEW.entity,'kind',NEW.kind,'summary',NEW.summary,'details',NEW.details)",'INSERT','1'),
 ('timeline','ticket','NEW.incident_id',"(SELECT machine_id FROM incidents WHERE id=NEW.incident_id)",'NEW.at',"json_object('incident_id',NEW.incident_id,'actor',NEW.actor,'kind',NEW.kind,'text',NEW.text)",'INSERT','1'),
 ('audit','audit','NEW.target',"(SELECT id FROM machines WHERE id=NEW.target)",'NEW.at',"json_object('actor',NEW.actor,'action',NEW.action,'target',NEW.target,'details',NEW.details)",'INSERT','1'),
]
SPECS.extend([
 ('network_proxmox','network','NEW.object_id',"(SELECT machine_id FROM proxmox_objects WHERE id=NEW.object_id)",'NEW.at',"json_object('interfaces',NEW.data)",None,'1'),
 ('network_samples','network','NEW.entity',"coalesce((SELECT machine_id FROM unifi_devices WHERE NEW.entity LIKE 'port:'||connection_id||':'||device_id||':%'),(SELECT id FROM machines WHERE NEW.entity LIKE 'interface:'||id||':%' LIMIT 1))",'NEW.at',"json_object('state',NEW.data)",'INSERT','1'),
 ('proxmox_api_jobs','diagnostic','NEW.id','NEW.machine_id','coalesce(NEW.completed,NEW.created)',"json_object('source','proxmox','state',NEW.state,'result',NEW.result)",'UPDATE OF result','NEW.result IS NOT NULL'),
 ('agent_updates','agent','NEW.agent_id',"(SELECT machine_id FROM agents WHERE id=NEW.agent_id)",'NEW.at',"json_object('update_status',NEW.status)",None,'1'),
])
ENABLED="(coalesce((SELECT json_extract(value,'$.enabled') FROM settings WHERE key='network_log_smb'),0)=1 OR coalesce((SELECT json_extract(value,'$') FROM settings WHERE key='telemetry_capture_enabled'),0)=1)"
BUDGET="max(16,min(16384,coalesce((SELECT json_extract(value,'$.buffer_mb') FROM settings WHERE key='network_log_smb'),256)))*1048576"


def insert_sql(kind,entity,machine,at,payload):
    safe=f'telemetry_json({payload})';size=f'length(cast({safe} AS BLOB))+128'
    return f"""INSERT INTO telemetry_records(id,kind,entity_id,machine_id,at,received,payload,size)
      SELECT lower(hex(randomblob(16))),'{kind}',{entity},{machine},coalesce({at},unixepoch('now')),unixepoch('now'),{safe},{size}
      WHERE (SELECT pending_bytes FROM telemetry_archive_meta WHERE id=1)+{size}<={BUDGET};
      UPDATE telemetry_archive_meta SET dropped=dropped+CASE WHEN changes()=0 THEN 1 ELSE 0 END WHERE id=1;"""


def migration():
    statements=["CREATE TABLE telemetry_records(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT,machine_id TEXT,at REAL NOT NULL,received REAL NOT NULL,payload TEXT NOT NULL,size INTEGER NOT NULL,uploaded INTEGER NOT NULL DEFAULT 0)",
      'CREATE INDEX telemetry_time ON telemetry_records(at DESC)',
      'CREATE INDEX telemetry_host ON telemetry_records(machine_id,at DESC)',
      'CREATE INDEX telemetry_pending ON telemetry_records(uploaded,received)',
      'CREATE INDEX telemetry_kind ON telemetry_records(kind)',
      'CREATE TABLE telemetry_archive_meta(id INTEGER PRIMARY KEY,pending_bytes INTEGER NOT NULL DEFAULT 0,dropped INTEGER NOT NULL DEFAULT 0)',
      'INSERT INTO telemetry_archive_meta(id) VALUES(1)',
      'CREATE TRIGGER telemetry_added AFTER INSERT ON telemetry_records WHEN NEW.uploaded=0 BEGIN UPDATE telemetry_archive_meta SET pending_bytes=pending_bytes+NEW.size WHERE id=1; END',
      'CREATE TRIGGER telemetry_uploaded AFTER UPDATE OF uploaded ON telemetry_records WHEN OLD.uploaded<>NEW.uploaded BEGIN UPDATE telemetry_archive_meta SET pending_bytes=pending_bytes+((NEW.uploaded=0)-(OLD.uploaded=0))*OLD.size WHERE id=1; END',
      'CREATE TRIGGER telemetry_removed AFTER DELETE ON telemetry_records WHEN OLD.uploaded=0 BEGIN UPDATE telemetry_archive_meta SET pending_bytes=pending_bytes-OLD.size WHERE id=1; END']
    for table,kind,entity,machine,at,payload,operation,condition in SPECS:
        updates={'integrations':'snapshot,at','unifi_devices':'data,last_seen','proxmox_objects':'metrics,status,node,present','agent_discovery':'data,at','network_inventory':'data,at','network_proxmox':'data,at','agent_updates':'status,at'}
        for action in ([operation] if operation else ['INSERT','UPDATE OF '+updates[table]]):
            name='telemetry_'+table+'_'+action.split()[0].lower()
            statements.append(f'CREATE TRIGGER {name} AFTER {action} ON {table} WHEN {ENABLED} AND ({condition}) BEGIN '+insert_sql(kind,entity,machine,at,payload)+' END')
    return tuple(statements)


def record(store,kind,entity,machine,payload,at=None,key=None):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('SELECT '+ENABLED).fetchone()[0]:return False
        if key and c.execute('SELECT 1 FROM telemetry_records WHERE id=?',(key,)).fetchone():return True
        body=encode(json.dumps(payload,default=str));size=len(body.encode())+128
        budget=c.execute('SELECT '+BUDGET).fetchone()[0]
        if c.execute('SELECT pending_bytes FROM telemetry_archive_meta WHERE id=1').fetchone()[0]+size>budget:
            c.execute('UPDATE telemetry_archive_meta SET dropped=dropped+1');return False
        from .db import uid
        c.execute('INSERT INTO telemetry_records(id,kind,entity_id,machine_id,at,received,payload,size) VALUES(?,?,?,?,?,?,?,?)',(key or uid(),kind,entity,machine,at if at is not None else time.time(),time.time(),body,size))
        return True


def status(store):
    with store.connect() as c:
        row=dict(c.execute('SELECT * FROM telemetry_archive_meta WHERE id=1').fetchone())
        row.update(dict(c.execute('SELECT count(*) records,sum(uploaded<>1) pending,min(CASE WHEN uploaded<>1 THEN received END) oldest FROM telemetry_records').fetchone()))
        row['kinds']=[dict(r) for r in c.execute('SELECT kind,count(*) count FROM telemetry_records GROUP BY kind ORDER BY kind')]
    return row


def local_search(store,params):
    clauses=['at>=?','at<=?'];args=[params['start'],params['end']]
    for key,col in [('machine','machine_id'),('kind','kind')]:
        if params.get(key):clauses.append(col+'=?');args.append(params[key])
    if params.get('q'):clauses.append("instr(lower(payload),lower(?))>0");args.append(params['q'])
    args.append(201)
    return [document(row) for row in store.rows('SELECT * FROM telemetry_records WHERE '+' AND '.join(clauses)+' ORDER BY at DESC,id DESC LIMIT ?',args)]


def validate_document(item):
    return (isinstance(item,dict) and isinstance(item.get('record_key'),str)
            and re.fullmatch(r'[A-Za-z0-9_-]{1,100}',item['record_key']) is not None
            and item.get('kind') in KINDS and isinstance(item.get('data'),dict)
            and all(item.get(k) is None or isinstance(item[k],str) and len(item[k])<=512 for k in ('machine_id','entity_id'))
            and all(type(item.get(k)) in (int,float) and math.isfinite(item[k]) for k in ('at','received')))


def document(row):
    return {'record_key':row['id'],'kind':row['kind'],'entity_id':row['entity_id'],'machine_id':row['machine_id'],'at':row['at'],'received':row['received'],'data':json.loads(row['payload'])}


class Exporter:
    def __init__(self,store,io,directory):
        self.store=store;self.io=io;self.directory=Path(directory)/'telemetry';self.directory.mkdir(exist_ok=True,mode=0o700)
        self.next_dashboard=0

    def backfill(self):
        cursors=self.store.setting('telemetry_backfill',{})
        for table,kind,entity,machine,at,payload,operation,condition in SPECS:
            if cursors.get(table)=='done':continue
            sql=f"SELECT NEW.rowid row_id,{entity} entity,{machine} machine,{at} at,{payload} payload FROM {table} NEW WHERE NEW.rowid>? AND ({at}) IS NOT NULL ORDER BY NEW.rowid LIMIT 20"
            rows=self.store.rows(sql,(cursors.get(table,0),))
            for row in rows:
                key='backfill-'+hashlib.sha256((table+':'+str(row['row_id'])+':'+str(row['at'])+row['payload']).encode()).hexdigest()[:32]
                if not record(self.store,kind,row['entity'],row['machine'],json.loads(row['payload']),row['at'],key):break
                cursors[table]=row['row_id']
            else:
                if len(rows)<20:cursors[table]='done'
            self.store.save('telemetry_backfill',cursors)
            return

    def capture_dashboard(self):
        if not self.store.setting('telemetry_capture_enabled',False):self.store.save('telemetry_capture_enabled',True)
        if time.monotonic()>=self.next_dashboard:
            from .dashboard_view import build
            from .overview_ui import dashboard_data
            record(self.store,'dashboard','workspace',None,build(self.store,dashboard_data(self.store)))
            self.next_dashboard=time.monotonic()+300

    def step(self,cfg,force=True):
        self.capture_dashboard()
        token=hashlib.sha256(json.dumps({k:cfg[k] for k in ('server','share','folder','namespace')},sort_keys=True).encode()).hexdigest()
        if self.store.setting('telemetry_archive_target')!=token:
            # Requeue retained local history on destination changes; immutable records keep their IDs.
            with self.store.connect() as c:
                c.execute('UPDATE telemetry_records SET uploaded=-1 WHERE uploaded=1')
                c.execute('UPDATE telemetry_archive_meta SET pending_bytes=(SELECT coalesce(sum(size),0) FROM telemetry_records WHERE uploaded=0) WHERE id=1')
            self.store.save('telemetry_archive_target',token)
            self.store.save('telemetry_archive_batch',{})
        with self.store.connect() as c:
            budget=c.execute('SELECT '+BUDGET).fetchone()[0]
            pending=c.execute('SELECT pending_bytes FROM telemetry_archive_meta WHERE id=1').fetchone()[0]
            for row in c.execute('SELECT id,size FROM telemetry_records WHERE uploaded=-1 ORDER BY received,id LIMIT 1000').fetchall():
                if pending+row['size']>budget:break
                c.execute('UPDATE telemetry_records SET uploaded=0 WHERE id=?',(row['id'],));pending+=row['size']
        batch=self.store.setting('telemetry_archive_batch',{})
        if batch:
            query='SELECT * FROM telemetry_records WHERE id IN ('+','.join('?' for _ in batch['ids'])+') ORDER BY received,id';args=batch['ids']
        else:query='SELECT * FROM telemetry_records WHERE uploaded=0 ORDER BY received,id LIMIT 1000';args=[]
        backlog=self.store.rows('SELECT count(*) pending,min(received) oldest FROM telemetry_records WHERE uploaded=0')[0]
        defer=not force and not batch and backlog['pending']<1000 and backlog['oldest'] and time.time()-backlog['oldest']<300 and self.store.setting('telemetry_archive_success')
        selected=[];size=0
        if not defer:
            # Stream the query; a large configured spool must not become a large
            # Python allocation merely to select an 8 MiB transfer batch.
            with self.store.connect() as c:
                for row in c.execute(query,args):
                    doc=document(row);line=json.dumps(doc,separators=(',',':'),allow_nan=False);size+=len(line.encode())+1
                    if size>8*1048576:break
                    selected.append((row,line))
        if selected:
            body=gzip.compress(('\n'.join(line for row,line in selected)+'\n').encode(),mtime=0)
            checksum=hashlib.sha256(body).hexdigest();key=hashlib.sha256(','.join(row['id'] for row,line in selected).encode()).hexdigest()[:32]
            name=f"telemetry-{int(max(r['received'] for r,l in selected))}-{int(min(r['at'] for r,l in selected))}-{int(max(r['at'] for r,l in selected))+1}-{key}-{checksum}.jsonl.gz"
            # Persist the exact batch before touching SMB; retries use the same immutable
            # IDs/filename even when new samples arrive or the worker restarts.
            self.store.save('telemetry_archive_batch',{'ids':[r['id'] for r,l in selected],'name':name})
            path=self.directory/'pending.jsonl.gz';path.write_bytes(body);os.chmod(path,0o600)
            result=self.io(cfg,'upload',dataset='telemetry',file=str(path),name=name)
            with self.store.connect() as c:c.executemany('UPDATE telemetry_records SET uploaded=1 WHERE id=?',[(r['id'],) for r,l in selected])
            self.store.save('telemetry_archive_batch',{})
            path.unlink(missing_ok=True)
            self.store.save('telemetry_archive_success',{'at':time.time(),'records':len(selected),'bytes':result['bytes']})
        # Local uploaded copies follow the chosen local retention/budget, independently of SMB.
        retention=self.store.setting('network_log_retention',{'days':7,'megabytes':200,'rows':100000})
        with self.store.connect() as c:
            if retention.get('days',7):c.execute('DELETE FROM telemetry_records WHERE id IN (SELECT id FROM telemetry_records WHERE uploaded=1 AND received<? ORDER BY received LIMIT 1000)',(time.time()-retention.get('days',7)*86400,))
            count,used=c.execute('SELECT count(*),coalesce(sum(size),0) FROM telemetry_records WHERE uploaded=1').fetchone()
            if count>retention.get('rows',100000) or used>retention.get('megabytes',200)*1048576:
                ids=c.execute('SELECT id FROM telemetry_records WHERE uploaded=1 ORDER BY received LIMIT 1000').fetchall()
                c.executemany('DELETE FROM telemetry_records WHERE id=?',ids)
        self.backfill()
        last=self.store.setting('telemetry_archive_retention',0)
        if cfg['days'] and time.time()-last>300:
            cutoff=time.time()-cfg['days']*86400;catalog=self.io(cfg,'catalog',dataset='telemetry',cutoff=cutoff)
            names=[f['name'] for f in catalog['files'] if f['received']<cutoff]
            if names:self.io(cfg,'delete',dataset='telemetry',names=names[:100])
            self.store.save('telemetry_archive_retention',time.time() if not catalog.get('truncated') else 0)
