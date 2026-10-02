"""Bounded host views; stale samples are shown explicitly, never as live facts."""
import json
import time


def percent(used,total):
    return round(min(100,max(0,100*used/total)),1) if type(used) in (int,float) and type(total) in (int,float) and total>0 else None


def bytes_label(value):
    if value is None: return 'Unavailable'
    for unit in ('B','KiB','MiB','GiB','TiB'):
        if value<1024 or unit=='TiB': return f'{value:.1f} {unit}'
        value/=1024


def duration(value):
    if value is None: return 'Unavailable'
    value=int(value)
    return f'{value//86400}d {(value%86400)//3600}h {(value%3600)//60}m'


def sample(agent,obj,now):
    metrics={}; source='No telemetry';at=None;fresh=False;info={}
    if agent and agent['last_seen'] is not None:
        metrics=json.loads(agent['telemetry'] or '{}');info=json.loads(agent['host_info'])
        source='Linux agent';at=agent['sampled_at'] or agent['last_seen']
        fresh=not agent['revoked'] and 0<=now-at<=180 and 0<=now-agent['last_seen']<=180
    elif obj:
        raw=json.loads(obj['metrics']); source='Proxmox inventory';at=obj['last_seen']
        metrics={k:v for k,v in {'cpu_percent':raw.get('cpu',0)*100 if 'cpu' in raw else None,'cpu_cores':raw.get('maxcpu'),'memory_total_bytes':raw.get('maxmem'),'memory_available_bytes':raw['maxmem']-raw['mem'] if 'maxmem' in raw and 'mem' in raw else None,'disk_total_bytes':raw.get('maxdisk'),'disk_free_bytes':raw['maxdisk']-raw['disk'] if 'maxdisk' in raw and 'disk' in raw else None,'uptime_seconds':raw.get('uptime')}.items() if v is not None}
        fresh=obj['present'] and obj['missing_since'] is None and 0<=now-at<=180
    ram_total=metrics.get('memory_total_bytes');ram_free=metrics.get('memory_available_bytes')
    disk_total=metrics.get('disk_total_bytes');disk_free=metrics.get('disk_free_bytes')
    ram_used=ram_total-ram_free if ram_total is not None and ram_free is not None else None
    disk_used=disk_total-disk_free if disk_total is not None and disk_free is not None else None
    return {'source':source,'at':at,'fresh':bool(fresh),'raw':metrics,'info':info,'cpu':round(metrics['cpu_percent'],1) if 'cpu_percent' in metrics else None,'ram':percent(ram_used,ram_total),'disk':percent(disk_used,disk_total),'ram_used':bytes_label(ram_used),'ram_total':bytes_label(ram_total),'disk_used':bytes_label(disk_used),'disk_total':bytes_label(disk_total),'load': ' / '.join(str(metrics.get('load_'+str(n),'—')) for n in (1,5,15)), 'pressure':metrics.get('memory_pressure_percent'), 'inodes':percent(metrics.get('inode_total',0)-metrics.get('inode_free',0),metrics.get('inode_total')), 'swap_used':bytes_label(metrics['swap_total_bytes']-metrics['swap_free_bytes']) if 'swap_total_bytes' in metrics and 'swap_free_bytes' in metrics else 'Unavailable', 'swap_total':bytes_label(metrics.get('swap_total_bytes')), 'uptime':duration(metrics.get('uptime_seconds')),'storage_scope':'Root filesystem /' if source=='Linux agent' else 'Proxmox reported allocation (guest disk usage may be unavailable)'}


def overview(store,now=None):
    now=time.time() if now is None else now
    with store.connect() as c:
        machines=[dict(r) for r in c.execute("SELECT * FROM machines WHERE id NOT LIKE 'unifi:%' AND id NOT LIKE 'unifi-device:%' ORDER BY name")]
        agents={r['machine_id']:dict(r) for r in c.execute('SELECT * FROM agents')}
        objects={}
        for r in c.execute("SELECT * FROM proxmox_objects WHERE machine_id IS NOT NULL AND present=1 ORDER BY CASE kind WHEN 'node' THEN 0 WHEN 'qemu' THEN 1 WHEN 'lxc' THEN 2 ELSE 3 END"):
            objects.setdefault(r['machine_id'],dict(r))
        checks={}
        for r in c.execute('SELECT machine_id,health FROM checks WHERE enabled=1'):
            checks.setdefault(r['machine_id'],[]).append(r['health'])
        counts={r['machine_id']:r['n'] for r in c.execute("SELECT machine_id,count(*) n FROM incidents WHERE closed IS NULL AND status<>'Resolved' GROUP BY machine_id")}
    for m in machines:
        m['agent']=agents.get(m['id']);m['object']=objects.get(m['id'])
        m['sample']=sample(m['agent'],m['object'],now)
        states=checks.get(m['id'],[])
        m['health']='down' if 'down' in states else 'unknown' if 'unknown' in states else 'healthy' if states else 'unmonitored'
        m['active_incidents']=counts.get(m['id'],0)
        m['type']=m['object']['kind'] if m['object'] else 'Linux host' if m['agent'] else 'Machine'
    for obj in store.rows("SELECT * FROM proxmox_objects WHERE machine_id IS NULL AND present=1 AND template=0 AND kind IN ('node','qemu','lxc') ORDER BY kind,name"):
        machines.append({'id':None,'name':obj['name'],'type':obj['kind'],'object':obj,'agent':None,'sample':sample(None,obj,now),'health':'unassigned','active_incidents':0})
    return machines


def tickets(store,machine_id):
    return [{**r,'title':json.loads(r['report']).get('check','Ticket')} for r in store.rows('SELECT * FROM incidents WHERE machine_id=? ORDER BY first_seen DESC LIMIT 100',(machine_id,))]


def host_checks(store,machine_id):
    checks=store.rows("SELECT checks.*, (SELECT at FROM observations WHERE check_id=checks.id ORDER BY at DESC LIMIT 1) AS last_checked, (SELECT evidence FROM observations WHERE check_id=checks.id ORDER BY at DESC LIMIT 1) AS latest_evidence FROM checks WHERE machine_id=? AND kind<>'manual' ORDER BY name",(machine_id,))
    for check in checks:
        if check['last_checked'] and check['last_checked']<json.loads(check['config']).get('_edited_at',0):
            check['last_checked']=None;check['latest_evidence']=None
    return checks


def detail(store,machine_id):
    host=next((m for m in overview(store) if m['id']==machine_id),None)
    if not host: return None
    obj=host['object']; guests=[]
    if obj and obj['kind']=='node':
        guests=store.rows("SELECT o.*,m.name AS machine FROM proxmox_objects o LEFT JOIN machines m ON m.id=o.machine_id WHERE o.cluster_id=? AND o.node=? AND o.kind IN ('qemu','lxc') AND o.present=1 ORDER BY o.kind,o.object_key",(obj['cluster_id'],obj['node']))
    for guest in guests:
        guest['sample']=sample(None,guest,time.time())
    return {'machines':store.rows('SELECT id,name FROM machines ORDER BY name'),'proxmox_sample':sample(None,obj,time.time()) if obj else None,'link_candidates':store.rows("SELECT o.*,p.name AS cluster FROM proxmox_objects o JOIN proxmox_clusters p ON p.id=o.cluster_id WHERE o.machine_id IS NULL AND o.present=1 AND o.template=0 AND o.kind IN ('node','qemu','lxc') ORDER BY p.name,o.kind,o.name"),'host':host,'guests':guests,'checks':host_checks(store,machine_id),'incidents':tickets(store,machine_id),'parent':store.rows('SELECT id,name FROM machines WHERE id=?',(host['parent_id'],)),'lifecycle':[{**r,'data':json.loads(r['payload'])} for r in store.rows('SELECT * FROM power_jobs WHERE machine_id=? ORDER BY created DESC LIMIT 50',(machine_id,))], 'power_policy':next(iter(store.rows('SELECT machine_id,backend,enabled,validated,version FROM power_policies WHERE machine_id=?',(machine_id,))),None),'power_connections':store.rows('SELECT id,name FROM proxmox_connections WHERE cluster_id=?',(obj['cluster_id'],)) if obj else []}


def object_detail(store,object_id):
    objects=store.rows('SELECT * FROM proxmox_objects WHERE id=?',(object_id,))
    if not objects: return None
    obj=objects[0]
    if obj['machine_id']: return detail(store,obj['machine_id'])
    host={'id':None,'name':obj['name'],'type':obj['kind'],'object':obj,'agent':None,'sample':sample(None,obj,time.time()),'health':'unmonitored','active_incidents':0}
    guests=store.rows("SELECT * FROM proxmox_objects WHERE cluster_id=? AND node=? AND present=1 AND kind IN ('qemu','lxc') ORDER BY name",(obj['cluster_id'],obj['node'])) if obj['kind']=='node' else []
    for g in guests: g['sample']=sample(None,g,time.time())
    return {'machines':store.rows('SELECT id,name FROM machines ORDER BY name'),'host':host,'guests':guests,'checks':[],'incidents':[],'parent':[],'lifecycle':[],'power_policy':None}
