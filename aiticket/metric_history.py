"""Retained, source-separated telemetry and bounded SVG chart data."""
import json,math,time
from .hostview import percent

WINDOWS={'1h':3600,'6h':21600,'24h':86400,'7d':604800}
METRICS=[('cpu_percent','CPU','%',100),('ram_percent','Memory','%',100),('disk_percent','Storage','%',100),('load_1','Load · 1 minute','',None),('load_5','Load · 5 minutes','',None),('load_15','Load · 15 minutes','',None),('swap_percent','Swap','%',100),('inode_percent','Inodes','%',100),('memory_pressure_percent','Memory pressure','%',100),('uptime_hours','Uptime','h',None)]


def normalized(raw,source):
    if source=='proxmox':
        raw={'cpu_percent':raw.get('cpu',0)*100 if 'cpu' in raw else None,'memory_total_bytes':raw.get('maxmem'),'memory_available_bytes':raw['maxmem']-raw['mem'] if 'maxmem' in raw and 'mem' in raw else None,'disk_total_bytes':raw.get('maxdisk'),'disk_free_bytes':raw['maxdisk']-raw['disk'] if 'maxdisk' in raw and 'disk' in raw else None,'uptime_seconds':raw.get('uptime')}
    values=dict(raw)
    for prefix,out in [('memory','ram_percent'),('disk','disk_percent'),('swap','swap_percent')]:
        total=raw.get(prefix+'_total_bytes');free=raw.get(prefix+('_available_bytes' if prefix=='memory' else '_free_bytes'))
        values[out]=percent(total-free,total) if total is not None and free is not None else None
    values['inode_percent']=percent(raw['inode_total']-raw['inode_free'],raw['inode_total']) if 'inode_total' in raw and 'inode_free' in raw else None
    values['uptime_hours']=raw['uptime_seconds']/3600 if raw.get('uptime_seconds') is not None else None
    return {k:v for k,_,_,_ in METRICS if type(v:=values.get(k)) in (int,float) and math.isfinite(v)}


def record(c,entity,source,at,metrics):
    if entity and metrics:
        c.execute('INSERT OR IGNORE INTO metric_samples(entity_id,source,at,metrics) VALUES(?,?,?,?)',(entity,source,at,json.dumps(normalized(metrics,source))))


def charts(store,host,window='6h',now=None):
    now=time.time() if now is None else now
    window=window if window in WINDOWS else '6h';start=now-WINDOWS[window]
    source='agent' if host.get('agent') else 'proxmox'
    entity=host['id'] if source=='agent' else host['object']['id'] if host.get('object') else None
    return series(store,entity,source,window,now)


def series(store,entity,source,window='6h',now=None,definitions=None):
    now=time.time() if now is None else now
    window=window if window in WINDOWS else '6h';start=now-WINDOWS[window]
    rows=store.rows('SELECT at,metrics FROM metric_samples WHERE entity_id=? AND source=? AND at>=? AND at<=? ORDER BY at',(entity,source,start,now)) if entity else []
    buckets=[[] for _ in range(120)]
    for row in rows:buckets[min(119,int((row['at']-start)/WINDOWS[window]*120))].append(json.loads(row['metrics']))
    result=[]
    for key,label,unit,fixed in (definitions if definitions is not None else METRICS):
        available=[r[key] for b in buckets for r in b if key in r]
        if not available:continue
        ceiling=fixed or max(1,max(available)*1.1)
        segments=[];points=[]
        for i,b in enumerate(buckets):
            vals=[r[key] for r in b if key in r]
            if not vals:
                if points:segments.append(' '.join(points));points=[]
                continue
            mean=sum(vals)/len(vals)
            points.append(f'{35+(i+.5)/120*530:.1f},{140-min(ceiling,max(0,mean))/ceiling*115:.1f}')
        if points:segments.append(' '.join(points))
        result.append({'key':key,'label':label,'unit':unit,'max':round(max(available),2),'min':round(min(available),2),'latest':round(available[-1],2),'ceiling':round(ceiling,1),'segments':segments})
    return {'charts':result,'window':window,'start':start,'end':now,'count':len(rows),'source':source,'windows':WINDOWS}
