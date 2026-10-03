"""Authenticated read-only jobs. No arbitrary commands or action operations."""
import json
import math
import re
import time
from .db import uid

OPERATIONS = ('process_summary','service_status','service_logs')
METRICS = ('cpu_percent','memory_used_percent','memory_pressure_percent','disk_used_percent','inode_used_percent')


def redact(text):
    text = str(text)[:16000]
    text = re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+',r'\1=[REDACTED]',text)
    text = re.sub(r'https?://[^\s/@]+:[^\s/@]+@','https://[REDACTED]@',text)
    return text


def request_job(store,agent_id,incident_id,operation,service=None,now=None):
    now=time.time() if now is None else now
    if operation not in OPERATIONS:
        raise ValueError('Unsupported read-only diagnostic')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        agent=c.execute('SELECT * FROM agents WHERE id=? AND revoked=0',(agent_id,)).fetchone()
        incident=c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not agent or not incident or agent['machine_id']!=incident['machine_id']:
            raise ValueError('Diagnostic target must belong to this incident')
        from .handoff import control
        if control(c, incident_id)['owner']=='ai':
            raise ValueError('AI owns this investigation; take control before requesting diagnostics.')
        capabilities=json.loads(agent['capabilities'])
        if operation not in capabilities.get('operations',[]):
            raise ValueError('Agent does not advertise this operation')
        parameters={}
        if operation!='process_summary':
            if service not in capabilities.get('services',[]):
                raise ValueError('Service is not in the agent allowlist')
            parameters={'service_id':service}
        if c.execute("SELECT count(*) FROM diagnostic_jobs WHERE agent_id=? AND state IN ('pending','leased')",(agent_id,)).fetchone()[0]>=10:
            raise ValueError('Agent queue is full')
        duplicate=c.execute("SELECT id FROM diagnostic_jobs WHERE agent_id=? AND incident_id=? AND operation=? AND parameters=? AND state IN ('pending','leased') AND expires>?",(agent_id,incident_id,operation,json.dumps(parameters),now)).fetchone()
        if duplicate:
            return duplicate['id']
        job=uid()
        c.execute('INSERT INTO diagnostic_jobs VALUES(?,?,?,?,?, ?,?,?,NULL,NULL,NULL,NULL)',(job,agent_id,incident_id,operation,json.dumps(parameters),'pending',now,now+600))
        store.audit(c,'diagnostic.requested',job,{'operation':operation,'incident_id':incident_id})
        store.timeline(c,incident_id,'diagnostic_requested',operation+' requested; read-only.',actor='user',now=now)
    return job


def poll(c,agent_id,now):
    c.execute("UPDATE diagnostic_jobs SET state='expired',lease_until=NULL,lease_token=NULL WHERE agent_id=? AND expires<=? AND state IN ('pending','leased')",(agent_id,now))
    job=c.execute("SELECT * FROM diagnostic_jobs WHERE agent_id=? AND expires>? AND (state='pending' OR (state='leased' AND lease_until<=?)) ORDER BY created LIMIT 1",(agent_id,now,now)).fetchone()
    if not job:
        return []
    token=uid()
    c.execute("UPDATE diagnostic_jobs SET state='leased',lease_until=?,lease_token=? WHERE id=?",(now+90,token,job['id']))
    return [{'id':job['id'],'operation':job['operation'],'parameters':json.loads(job['parameters']),'expires':job['expires'],'lease_token':token}]


def complete(store,agent_id,payload,now=None):
    now=time.time() if now is None else now
    if not isinstance(payload,dict) or payload.get('status') not in ('completed','failed') or not isinstance(payload.get('output'),str) or len(payload['output'])>16000:
        raise ValueError('Invalid bounded diagnostic result')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('SELECT 1 FROM agents WHERE id=? AND revoked=0',(agent_id,)).fetchone():
            raise ValueError('Agent is revoked')
        job=c.execute('SELECT * FROM diagnostic_jobs WHERE id=? AND agent_id=?',(payload.get('job_id'),agent_id)).fetchone()
        if not job:
            raise ValueError('Unknown diagnostic job')
        if job['state'] in ('completed','failed'):
            return 'duplicate'
        if job['state']!='leased' or job['expires']<=now or job['lease_token']!=payload.get('lease_token'):
            raise ValueError('Expired or superseded diagnostic lease')
        result=json.dumps({'status':payload['status'],'output':redact(payload['output'])})
        c.execute('UPDATE diagnostic_jobs SET state=?,result=?,completed=?,lease_until=NULL,lease_token=NULL WHERE id=?',(payload['status'],result,now,job['id']))
        store.timeline(c,job['incident_id'],'diagnostic_result',job['operation']+' '+payload['status']+'; execution '+job['id'],actor='agent',now=now)
        store.audit(c,'diagnostic.'+payload['status'],job['id'],actor='agent')
    return 'accepted'


def metric_probe(store,config):
    now=time.time()
    agent=store.rows('SELECT * FROM agents WHERE id=? AND revoked=0',(config['agent_id'],))
    if not agent or not agent[0]['sampled_at'] or not -30<=now-agent[0]['sampled_at']<=180 or not agent[0]['last_seen'] or now-agent[0]['last_seen']>180:
        return None,{'reason':'Metric unavailable or stale; not evidence of pressure'}
    telemetry=json.loads(agent[0]['telemetry'] or '{}')
    metric=config['metric'];value=None
    if 'threshold' in config:
        from .health_rules import METRICS as RULES
        if metric not in RULES:return None,{'reason':'Unsupported health metric'}
        if config.get('direction')=='below':
            total_key,free_key={'memory_used_percent':('memory_total_bytes','memory_available_bytes'),'disk_used_percent':('disk_total_bytes','disk_free_bytes'),'inode_used_percent':('inode_total','inode_free')}[metric]
            total,free=telemetry.get(total_key),telemetry.get(free_key)
            if type(free) in (int,float):
                value=free if config['unit']=='bytes' else 100*free/total if type(total) in (int,float) and total>0 else None
        else:value=telemetry.get(metric)
        rows=store.rows('SELECT health FROM checks WHERE id=?',(config.get('_check_id'),))
        threshold=config['recovery'] if rows and rows[0]['health']=='down' else config['threshold']
        if type(value) not in (int,float) or not math.isfinite(value) or value<0 or (config['unit']=='percent' and value>100):return None,{'reason':'Metric unavailable; not evidence of pressure','metric':metric}
        healthy=value>threshold if config['direction']=='below' else value<threshold
        return healthy,{'metric':metric,'value':round(value,2),'unit':config['unit'],'threshold':threshold,'sampled_at':agent[0]['sampled_at']}
    if metric=='memory_used_percent':
        total=telemetry.get('memory_total_bytes',0);free=telemetry.get('memory_available_bytes')
        value=100*(1-free/total) if total and free is not None else None
    elif metric in ('disk_used_percent','inode_used_percent'):
        prefix='disk' if metric.startswith('disk') else 'inode'
        total=telemetry.get(prefix+'_total_bytes' if prefix=='disk' else 'inode_total',0)
        free=telemetry.get(prefix+'_free_bytes' if prefix=='disk' else 'inode_free')
        value=100*(1-free/total) if total and free is not None else None
    else:value=telemetry.get(metric)
    if value is None:return None,{'reason':'Metric not supported by this agent','metric':metric}
    rows=store.rows('SELECT health FROM checks WHERE id=?',(config.get('_check_id'),))
    threshold=config['recover_below'] if rows and rows[0]['health']=='down' else config['fail_above']
    return value<threshold,{'metric':metric,'value_percent':round(value,2),'fail_above':config['fail_above'],'recover_below':config['recover_below'],'sustain_seconds':config['sustain_seconds'],'sampled_at':agent[0]['sampled_at'],'definition':'Memory uses MemAvailable (cache reclaimable); disk and inodes cover root filesystem; pressure uses PSI full avg10; CPU uses /proc/stat deltas.'}
