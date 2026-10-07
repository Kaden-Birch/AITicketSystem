"""Source-separated host filesystem capacity; never confuse VM allocation with usage."""
import hashlib
import json
import time
from .capacity_forecasts import valid,record,forecast
from .archive_storage import human


def validate(values):
    if not isinstance(values,list) or len(values)>64:raise ValueError('Invalid filesystem inventory.')
    seen=set();mounts=set()
    for value in values:
        if not isinstance(value,dict) or set(value)!={'id','mount','filesystem','total_bytes','free_bytes'}:raise ValueError('Invalid filesystem fields.')
        for key,limit in (('id',160),('mount',512),('filesystem',32)):
            text=value[key]
            if not isinstance(text,str) or not 0<len(text)<=limit or any(ord(c)<32 for c in text):raise ValueError('Invalid filesystem identity.')
        total=value['total_bytes'];free=value['free_bytes']
        if not valid(total) or not valid(free) or not 0<total<=1e18 or not 0<=free<=total:raise ValueError('Invalid filesystem capacity.')
        if value['id'] in seen or value['mount'] in mounts:raise ValueError('Duplicate filesystem.')
        seen.add(value['id']);mounts.add(value['mount'])
    return values


def volumes(raw,info):
    if 'filesystems' in raw:return raw['filesystems']
    total=raw.get('disk_total_bytes');free=raw.get('disk_free_bytes')
    if not valid(total) or not valid(free) or not 0<total or not 0<=free<=total:return []
    windows=info.get('os','').lower().startswith('windows')
    return [{'id':'legacy-system','mount':'System drive' if windows else '/','filesystem':'Not reported','total_bytes':total,'free_bytes':free}]


def entity(machine,agent,volume):
    return 'host:'+machine+':'+agent+':'+hashlib.sha256(volume['id'].encode()).hexdigest()[:24]


def retain(c,machine,agent,raw,info,at):
    at=raw.get('filesystems_at',at) if 'filesystems' in raw else at
    for volume in volumes(raw,info):
        if not isinstance(volume,dict):continue
        total=volume.get('total_bytes');free=volume.get('free_bytes')
        if not valid(total) or not valid(free) or not 0<=free<=total:continue
        record(c,entity(machine,agent,volume),machine,'host_filesystem',volume['mount'],at,total-free,total)


def build(store,host,now=None):
    now=time.time() if now is None else now
    agent=host.get('agent');rows=[]
    if not agent:return {'volumes':[],'reason':'An agent is needed to forecast actual filesystem usage. Proxmox disk allocation is not guest free space.'}
    raw=json.loads(agent['telemetry'] or '{}');info=json.loads(agent['host_info'] or '{}')
    at=raw.get('filesystems_at',agent['sampled_at'] if agent['sampled_at'] is not None else agent['last_seen'])
    fresh=bool(not agent['revoked'] and at is not None and agent['last_seen'] is not None and 0<=now-at<=180 and 0<=now-agent['last_seen']<=180)
    for volume in volumes(raw,info):
        total=volume['total_bytes'];free=volume['free_bytes'];used=total-free;percent=used/total*100
        rows.append({'mount':volume['mount'],'filesystem':volume['filesystem'],'key':entity(host['id'],agent['id'],volume),'used':human(used),'total':human(total),'free':human(free),'percent':round(percent,1),'color':'high' if percent>=90 else 'moderate' if percent>=75 else 'good','fresh':fresh,'forecast':forecast(store,entity(host['id'],agent['id'],volume),now,fresh=fresh,expected_total=total)})
    return {'volumes':rows,'at':at,'reason':'No filesystem capacity was reported by this agent.' if not rows else '', 'legacy':'filesystems' not in raw}


def backfill(store):
    # Separate cursor: older installs have already advanced the NAS backfill cursor.
    cursor=store.setting('host_capacity_backfill',0);now=time.time()
    rows=store.rows("SELECT rowid sequence,machine_id,at,payload FROM telemetry_records WHERE rowid>? AND kind='agent' AND at>=? ORDER BY rowid LIMIT 100",(cursor,now-30*86400))
    with store.connect() as c:
        for row in rows:
            agent=c.execute('SELECT id FROM agents WHERE machine_id=? AND revoked=0',(row['machine_id'],)).fetchone()
            if not agent:continue
            try:
                data=json.loads(row['payload']);raw=data.get('telemetry',{});info=data.get('host_info',{})
                if isinstance(raw,str):raw=json.loads(raw)
                if isinstance(info,str):info=json.loads(info)
                if data.get('agent_id')!=agent['id'] or not isinstance(raw,dict) or not isinstance(info,dict):continue
                if 'filesystems' in raw:validate(raw['filesystems'])
                retain(c,row['machine_id'],agent['id'],raw,info,row['at'])
            except (ValueError,TypeError,KeyError,AttributeError):continue
    if rows:store.save('host_capacity_backfill',rows[-1]['sequence'])
