"""Validate bounded inventories and create checks only for explicit user choices."""
import json,math,time,re
from .db import uid


def validate(data):
    if not isinstance(data,dict) or len(json.dumps(data))>100000:raise ValueError('Discovery inventory exceeds the supported size.')
    warnings=data.get('warnings',[])
    if not isinstance(warnings,list):raise ValueError('Invalid discovery warnings.')
    result={'docker_installed':data.get('docker_installed') is True,'warnings':[str(x)[:200] for x in warnings[:5]],'containers_truncated':data.get('containers_truncated') is True,'processes_truncated':data.get('processes_truncated') is True}
    for kind,limit,keys in [('containers',100,('name','target','image','state','status','ports','cpu_percent','memory_percent')),('processes',200,('name','target','pid','memory_bytes','cpu_percent'))]:
        rows=data.get(kind,[])
        if not isinstance(rows,list) or len(rows)>limit:raise ValueError('Invalid discovery inventory.')
        result[kind]=[]
        for row in rows:
            if not isinstance(row,dict):raise ValueError('Invalid discovery row.')
            clean={}
            for key in keys:
                v=row.get(key)
                if v is None:continue
                if key in ('pid','memory_bytes','cpu_percent','memory_percent'):
                    if type(v) not in (int,float) or not math.isfinite(v) or v<0:raise ValueError('Invalid discovery counter.')
                elif not isinstance(v,str) or len(v)>500:raise ValueError('Invalid discovery label.')
                clean[key]=v
            if not clean.get('target') or not clean.get('name'):raise ValueError('Discovery item needs a name.')
            result[kind].append(clean)
    return result


def view(store,machine):
    rows=store.rows('SELECT d.* FROM agent_discovery d JOIN agents a ON a.machine_id=d.machine_id WHERE d.machine_id=? AND a.revoked=0 AND a.last_seen>=?',(machine,time.time()-180))
    if not rows:return None
    data=json.loads(rows[0]['data'])
    from .windows import is_windows,valid_target
    windows=is_windows(store,machine)
    for kind,key in [('docker','containers'),('process','processes')]:
        for item in data.get(key,[]):item['monitorable']=valid_target(kind,item['target'],windows)
    return {'data':data,'at':rows[0]['at'],'fresh':0<=time.time()-rows[0]['at']<=180}


def add_check(store,machine,kind,target):
    inventory=view(store,machine)
    if not inventory or not inventory['fresh']:raise ValueError('Wait for a current agent inventory before adding a check.')
    if kind not in ('docker','process'):raise ValueError('Choose a container or process.')
    if not any(x['target']==target for x in inventory['data']['containers' if kind=='docker' else 'processes']):raise ValueError('This item is no longer in the current inventory.')
    from .windows import is_windows,valid_target
    if not valid_target(kind,target,is_windows(store,machine)):raise ValueError('This process name cannot be monitored by an exact-name check.')
    cfg=json.dumps({'target':target})
    with store.connect() as c:
        old=c.execute('SELECT id FROM checks WHERE machine_id=? AND kind=? AND json_extract(config,\'$.target\')=?',(machine,kind,target)).fetchone()
        if old:return old['id']
        identifier=uid();c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,severity) VALUES(?,?,?,?,?,60,'medium')",(identifier,machine,target,kind,cfg));store.audit(c,'check.created',identifier,{'kind':kind})
    return identifier
