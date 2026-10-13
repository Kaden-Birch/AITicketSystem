"""Automatic read-only backup evidence. A completed run is not a restore test."""
import json
import time
import math
import re
from datetime import datetime,timedelta,timezone
from zoneinfo import ZoneInfo
from urllib.parse import urlencode,quote
from .db import uid

GRACE=3600


def stamp(value):
    if isinstance(value,dict):
        value=value.get('$date')
        if type(value) in (int,float):value/=1000
    if type(value) in (int,float):return float(value) if math.isfinite(value) and value>0 else None
    if isinstance(value,str):
        try:
            d=datetime.fromisoformat(value.replace('Z','+00:00'))
            return d.timestamp() if d.tzinfo else None
        except ValueError:pass
    return None


def cron_values(text,low,high):
    result=set()
    for part in str(text).split(','):
        base,_,step=part.partition('/');step=int(step or 1)
        if step<1:raise ValueError('Invalid cron step')
        if base=='*':a,b=low,high
        elif '-' in base:a,b=map(int,base.split('-',1))
        else:a=b=int(base)
        if not low<=a<=b<=high:raise ValueError('Invalid cron range')
        result.update(range(a,b+1,step))
    return sorted(result)


def cron_next(schedule,zone,now):
    if not isinstance(schedule,dict) or not zone:return None
    try:
        # Avoid guessing the OR/AND meaning of simultaneously restricted day fields.
        if schedule.get('dom','*')!='*' and schedule.get('dow','*')!='*':return None
        values={k:cron_values(schedule.get(k,'*'),a,b) for k,a,b in [('minute',0,59),('hour',0,23),('dom',1,31),('month',1,12),('dow',1,7)]}
        tz=ZoneInfo(zone);start=datetime.fromtimestamp(now,tz)
        begin=schedule.get('begin','00:00');end=schedule.get('end','23:59')
        for offset in range(367):
            day=start.date()+timedelta(days=offset)
            if day.day not in values['dom'] or day.month not in values['month'] or day.isoweekday() not in values['dow']:continue
            for hour in values['hour']:
                for minute in values['minute']:
                    clock=f'{hour:02}:{minute:02}'
                    if not begin<=clock<=end:continue
                    candidate=datetime(day.year,day.month,day.day,hour,minute,tzinfo=tz)
                    ts=candidate.timestamp()
                    # Nonexistent DST wall times cannot be treated as scheduled runs.
                    if datetime.fromtimestamp(ts,tz).replace(tzinfo=None)!=candidate.replace(tzinfo=None):continue
                    if ts>now:return ts
    except (ValueError,TypeError,KeyError):pass
    return None


def nas_jobs(snapshot,machine):
    jobs=[];zone=snapshot.get('backup_timezone')
    for kind,label in [('snapshot_tasks','Snapshot'),('replication_tasks','Replication')]:
        for task in snapshot.get(kind,[]):
            state=task.get('state') or {};state=state if isinstance(state,dict) else {'state':state}
            status=str(state.get('state','UNKNOWN')).upper()
            at=stamp(state.get('datetime'))
            jobs.append({'key':kind+':'+str(task['id']),'name':str(task.get('name') or task.get('dataset') or label+' '+str(task['id']))[:200],'kind':label,'machine_id':machine,'enabled':task.get('enabled',True) is not False,'schedule':task.get('schedule'),'next_due':cron_next(task.get('schedule'),zone,time.time()) if task.get('auto',True) is not False else None,'status':status,'last_run':at,'last_success':at if status in ('FINISHED','SUCCESS') else None,'duration':None,'reference':kind+':'+str(task['id']),'note':'Local snapshot; not an independent backup.' if kind=='snapshot_tasks' else 'Replication completion does not establish restore viability.','target':task.get('target_dataset',task.get('dataset')),'schedule_known':bool(zone and task.get('schedule'))})
    return jobs


def pve_collect(store,vault,connection,now):
    from .proxmox import Client
    client=Client(connection,vault);deadline=time.monotonic()+25;errors=[]
    def read(path):
        if time.monotonic()>deadline:raise ValueError('Backup collection time budget reached')
        data=client.get(path)
        if not isinstance(data,list) or len(data)>10000:raise ValueError('Invalid backup inventory')
        return data
    configs=read('/cluster/backup')
    if len(configs)>100:errors.append('Schedule inventory limited to first 100 jobs')
    configs=configs[:100]
    resources=store.rows("SELECT * FROM proxmox_objects WHERE cluster_id=? AND present=1 AND kind IN ('node','qemu','lxc')",(connection['cluster_id'],))
    node_names=sorted({r['node'] for r in resources if r['kind']=='node'})
    tasks=[];unreadable=set()
    for node in node_names[:16]:
        try:
            page=read('/nodes/'+quote(node,safe='')+'/tasks?'+urlencode({'typefilter':'vzdump','limit':100,'since':int(now-31*86400)}))
            tasks.extend({**r,'node':node} for r in page if r.get('type')=='vzdump')
            if len(page)>=100:errors.append(node+': showing latest 100 backup tasks')
        except Exception:errors.append(node+': backup task history unavailable');unreadable.add(node)
    if len(node_names)>16:errors.append('Task history limited to first 16 nodes')
    previous=store.rows('SELECT data FROM backup_inventory WHERE id=?',('proxmox:'+connection['cluster_id'],))
    prior_jobs={j['key']:j for j in json.loads(previous[0]['data'])} if previous else {}
    jobs=[]
    for guest in resources:
        if guest['kind'] not in ('qemu','lxc') or guest['template']:continue
        vmid=guest['object_key'].split('/')[-1]
        job_key='guest:'+guest['id'];first_observed=prior_jobs.get(job_key,{}).get('first_observed',now)
        matches=[]
        for cfg in configs:
            if cfg.get('enabled',1) in (False,0):continue
            if cfg.get('node') and cfg['node']!=guest['node']:continue
            if cfg.get('pool'):continue # Pool membership is not inferred.
            selected=set(re.split(r'[,;\s]+',str(cfg.get('vmid',''))));excluded=set(re.split(r'[,;\s]+',str(cfg.get('exclude',''))))
            if vmid not in excluded and (cfg.get('all') in (True,1) or vmid in selected):matches.append(cfg)
        runs=[r for r in tasks if str(r.get('id',''))==vmid and (guest['generation']==1 or (stamp(r.get('starttime')) or 0)>=first_observed)]
        runs.sort(key=lambda r:stamp(r.get('starttime')) or 0,reverse=True)
        latest=runs[0] if runs else {};finished=stamp(latest.get('endtime'))
        status='UNKNOWN' if not latest else 'RUNNING' if not finished else 'SUCCESS' if latest.get('status')=='OK' else 'FAILED'
        success=max((stamp(r.get('endtime')) or 0 for r in runs if r.get('status')=='OK'),default=0) or None
        cfg=matches[0] if len(matches)==1 else {}
        jobs.append({'key':job_key,'first_observed':first_observed,'generation':guest['generation'],'name':guest['name'],'kind':'Backup','machine_id':guest['machine_id'],'enabled':True,'schedule':cfg.get('schedule'),'next_due':stamp(cfg.get('next-run')),'status':'UNKNOWN' if guest['node'] in unreadable else status,'last_run':finished or stamp(latest.get('starttime')),'last_success':success,'duration':finished-stamp(latest['starttime']) if finished and stamp(latest.get('starttime')) else None,'reference':latest.get('upid'),'target':cfg.get('storage'),'note':'Observed guest backup tasks; '+('unique schedule matched.' if len(matches)==1 else 'schedule attribution unavailable or ambiguous.'),'node':guest['node'],'monitor':bool(matches),'visibility_error':guest['node'] in unreadable or guest['node'] not in node_names[:16]})
    # Cluster jobs without identifiable guest scope remain visible, without invented run attribution.
    for cfg in configs:
        if not any(j['schedule']==cfg.get('schedule') and j['target']==cfg.get('storage') for j in jobs):
            jobs.append({'key':'schedule:'+str(cfg.get('id')),'name':str(cfg.get('comment') or cfg.get('id') or 'Backup schedule'),'kind':'Backup schedule','machine_id':None,'enabled':cfg.get('enabled',1) not in (False,0),'schedule':cfg.get('schedule'),'next_due':None,'status':'UNKNOWN','last_run':None,'last_success':None,'duration':None,'reference':str(cfg.get('id')),'target':cfg.get('storage'),'note':'Guest scope or task attribution unavailable; no overdue alert is inferred.'})
    return jobs,errors


def save_inventory(store,source,connection,jobs,errors,now,token=None,fence=None):
    identifier=source+':'+connection;previous=store.rows('SELECT * FROM backup_inventory WHERE id=?',(identifier,))
    old=json.loads(previous[0]['data']) if previous else [];old={r['key']:r for r in old}
    for job in jobs:
        before=old.get(job['key'],{})
        job['last_success']=max(job.get('last_success') or 0,before.get('last_success') or 0) or None
        prior=(before.get('pending_due') or before.get('next_due')) if before.get('schedule')==job.get('schedule') and before.get('enabled')==job['enabled'] else None
        if job.get('schedule_known') is False or job.get('next_due') is None:prior=None
        # Start observing deadlines only after an actual future schedule was collected.
        job['pending_due']=prior if job['enabled'] and prior and prior<now and (job['last_success'] or 0)<prior else None
        if not job.get('pending_due') and job['enabled'] and job.get('next_due'):job['pending_due']=job['next_due']
        job['observed_at']=now;job['source']=source;job['connection_id']=connection
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        exists=c.execute('SELECT 1 FROM proxmox_connections WHERE cluster_id=?',(connection,)).fetchone() if source=='proxmox' else c.execute('SELECT 1 FROM integrations WHERE id=?',(connection,)).fetchone()
        if not exists and (token or fence):return
        if fence:
            valid=c.execute('SELECT id FROM integrations WHERE id=? AND config=? AND secret=?',(fence['id'],fence['config'],fence['secret'])).fetchone() if source=='truenas' else c.execute('SELECT id FROM proxmox_connections WHERE id=? AND token_id=? AND token_secret=? AND url=?',(fence['id'],fence['token_id'],fence['token_secret'],fence['url'])).fetchone()
            if not valid:return
        newer=c.execute('SELECT at FROM backup_inventory WHERE id=?',(identifier,)).fetchone()
        if newer and newer['at'] is not None and newer['at']>now:return
        if token and not c.execute('SELECT 1 FROM backup_inventory WHERE id=? AND lease_token=?',(identifier,token)).fetchone():return
        c.execute('INSERT INTO backup_inventory(id,source,connection_id,at,next_run,data,error) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET at=excluded.at,next_run=excluded.next_run,data=excluded.data,error=excluded.error,lease_token=NULL,lease_until=NULL',(identifier,source,connection,now,now+300,json.dumps(jobs),'; '.join(errors) or None))
        for job in jobs:
            if not job['machine_id'] or not job['enabled'] or not job.get('monitor',True):continue
            cfg={'inventory':identifier,'key':job['key']}
            check=c.execute("SELECT id FROM checks WHERE kind='backup_health' AND machine_id=? AND json_extract(config,'$.inventory')=? AND json_extract(config,'$.key')=?",(job['machine_id'],identifier,job['key'])).fetchone()
            if not check:
                check_id=uid()
                c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,severity,fail_after,recover_after) VALUES(?,?,?,'backup_health',?,300,'medium',2,2)",(check_id,job['machine_id'],job['kind']+' health · '+job['name'],json.dumps(cfg)))
                store.audit(c,'backup.job_discovered',check_id,{'machine_id':job['machine_id'],'inventory':identifier,'job_key':job['key']},actor='monitor')
        for job in jobs:
            if not job['enabled']:c.execute("UPDATE checks SET enabled=0,lease_token=NULL,lease_until=NULL WHERE kind='backup_health' AND json_extract(config,'$.inventory')=? AND json_extract(config,'$.key')=?",(identifier,job['key']))
        # Positive unlink/disable evidence is safe even when another node is unreadable.
        mapped={j['key']:j for j in jobs}
        for check in c.execute("SELECT id,machine_id,config FROM checks WHERE kind='backup_health' AND json_extract(config,'$.inventory')=?",(identifier,)).fetchall():
            key=json.loads(check['config'])['key'];current=mapped.get(key)
            if (current and (current['machine_id']!=check['machine_id'] or not current['enabled'] or not current.get('monitor',True))) or (not current and not errors):
                c.execute('UPDATE checks SET enabled=0,lease_token=NULL,lease_until=NULL WHERE id=?',(check['id'],))
    from .telemetry_archive import record
    for job in jobs:
        record(store,'backup',identifier,job['machine_id'],job,at=now)


def evaluate(job,now):
    if not job['enabled']:return None,'Job disabled'
    if job.get('visibility_error'):return None,'Task history unavailable for this host'
    if now-job['observed_at']>900:return None,'Backup evidence is stale'
    if job['status'] in ('FAILED','ERROR','ABORTED'):return False,'Latest observed run failed'
    if job['status'] in ('RUNNING','WAITING'):return None,'Job running or waiting'
    if job.get('pending_due') and now>job['pending_due']+GRACE and (job.get('last_success') or 0)<job['pending_due']:return False,'No successful run observed after the scheduled deadline and one-hour grace period'
    if job['status'] in ('SUCCESS','FINISHED'):return True,'Latest observed run completed successfully; restore not verified'
    return None,'No attributable completed run available'


def probe(store,cfg):
    rows=store.rows('SELECT * FROM backup_inventory WHERE id=?',(cfg['inventory'],))
    if not rows or (rows[0]['error'] or '').startswith('Collector unavailable:'):return None,{'reason':'Backup collection has incomplete visibility','monitoring_issue':True}
    job=next((r for r in json.loads(rows[0]['data']) if r['key']==cfg['key']),None)
    if not job:return None,{'reason':'Backup job no longer present in current inventory'}
    healthy,reason=evaluate(job,time.time())
    return healthy,{'reason':reason,'job':job['name'],'source':job['source'],'reference':job['reference'],'last_success':job['last_success'],'last_run':job['last_run'],'pending_due':job.get('pending_due'),'observed_at':job['observed_at'],'restore_verified':False}


def views(store,machine=None):
    check_map={}
    for check in store.rows("SELECT c.id,c.config,c.machine_id,i.id ticket FROM checks c LEFT JOIN incidents i ON i.check_id=c.id AND i.closed IS NULL AND i.status!='Resolved' WHERE c.kind='backup_health'"):
        cfg=json.loads(check['config']);check_map[(cfg['inventory'],cfg['key'],check['machine_id'])]=check
    result=[];now=time.time();names={r['id']:r['name'] for r in store.rows('SELECT id,name FROM machines')}
    for row in store.rows('SELECT * FROM backup_inventory ORDER BY source,connection_id'):
        exists=store.rows('SELECT id FROM proxmox_connections WHERE cluster_id=?',(row['connection_id'],)) if row['source']=='proxmox' else store.rows('SELECT id FROM integrations WHERE id=?',(row['connection_id'],))
        if not exists:continue
        for job in json.loads(row['data']):
            if machine and job['machine_id']!=machine:continue
            healthy,reason=evaluate(job,now)
            if (row['error'] or '').startswith('Collector unavailable:'):healthy=None;reason='Backup collector unavailable; latest results are historical'
            if row['error'] and healthy is None:reason+=' · Collection incomplete: '+row['error']
            check=check_map.get((row['id'],job['key'],job['machine_id']),{})
            result.append({**job,'check_id':check.get('id'),'ticket_id':check.get('ticket'),'health':'healthy' if healthy is True else 'down' if healthy is False else 'unknown','reason':reason,'host':names.get(job['machine_id'],'Unassigned'),'restore_verified':False})
    result.sort(key=lambda j:({'down':0,'unknown':1,'healthy':2}[j['health']],j['name'].casefold()))
    return result


def tick(store,vault):
    now=time.time()
    with store.connect() as c:
        for source in c.execute('SELECT id,source,connection_id FROM backup_inventory').fetchall():
            exists=c.execute('SELECT 1 FROM proxmox_connections WHERE cluster_id=?',(source['connection_id'],)).fetchone() if source['source']=='proxmox' else c.execute('SELECT 1 FROM integrations WHERE id=?',(source['connection_id'],)).fetchone()
            if not exists:c.execute("UPDATE checks SET enabled=0,lease_token=NULL,lease_until=NULL WHERE kind='backup_health' AND json_extract(config,'$.inventory')=?",(source['id'],))
        for r in c.execute('SELECT cluster_id,min(id) id FROM proxmox_connections GROUP BY cluster_id').fetchall():
            c.execute("INSERT OR IGNORE INTO backup_inventory(id,source,connection_id,next_run,data) VALUES(?,'proxmox',?,0,'[]')",('proxmox:'+r['cluster_id'],r['cluster_id']))
        row=c.execute("SELECT * FROM backup_inventory WHERE source='proxmox' AND next_run<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_run LIMIT 1",(now,now)).fetchone()
        if not row:return False
        row=dict(row);token=uid();changed=c.execute('UPDATE backup_inventory SET lease_token=?,lease_until=?,next_run=? WHERE id=? AND (lease_until IS NULL OR lease_until<=?)',(token,now+90,now+300,row['id'],now))
        if not changed.rowcount:return False
    endpoints=store.rows('SELECT * FROM proxmox_connections WHERE cluster_id=? ORDER BY id',(row['connection_id'],));error='Connection unavailable'
    for endpoint in endpoints:
        try:
            jobs,errors=pve_collect(store,vault,endpoint,now)
            # Fence removed/edited credentials before accepting results.
            if not store.rows('SELECT id FROM proxmox_connections WHERE id=? AND token_secret=? AND url=?',(endpoint['id'],endpoint['token_secret'],endpoint['url'])):break
            save_inventory(store,'proxmox',row['connection_id'],jobs,errors,now,token,fence=endpoint);return True
        except Exception as exc:error='Collector unavailable: '+type(exc).__name__
    with store.connect() as c:c.execute('UPDATE backup_inventory SET error=?,lease_token=NULL,lease_until=NULL WHERE id=? AND lease_token=?',(error,row['id'],token))
    return True
