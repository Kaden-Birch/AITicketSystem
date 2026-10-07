"""TrueNAS presentation only; missing telemetry never becomes a health claim."""
import json
import hashlib
import math
import time

WINDOWS={'10m':600,'30m':1800,'1h':3600,'6h':21600,'24h':86400,'7d':604800,'30d':2592000}


def number(v):return v if type(v) in (int,float) and math.isfinite(v) else None


def size(v):
    v=number(v)
    if v is None or v<0:return 'Not reported'
    for divisor,unit in [(1024**4,'TiB'),(1024**3,'GiB'),(1024**2,'MiB'),(1024,'KiB')]:
        if v>=divisor:return f'{v/divisor:,.1f} {unit}'
    return f'{v:,.0f} B'


def text(v):return str(v) if v is not None and v!='' else 'Not reported'


def state(v,fresh=True):
    if not fresh:return 'unknown'
    v=str(v or '').upper()
    if v in ('ONLINE','RUNNING','LINK_STATE_UP'):return 'healthy'
    if v in ('FAULTED','UNAVAIL','REMOVED','DEAD','ERROR'):return 'failed'
    if v in ('DEGRADED','OFFLINE','STOPPED','EXITED','RESTARTING','SUSPENDED'):return 'warning'
    return 'unknown'


def build(store,host,connection,window='1h',now=None):
    d=connection['data'];fresh=connection['fresh'] and not d.get('error');m=d.get('metrics',{});entries=[]
    def entry(kind,title,reported,fields,subtitle='',reading='',monitor=None,children=None,identity=None):
        item={'key':hashlib.sha256((kind+':'+str(identity if identity is not None else title)).encode()).hexdigest()[:20],'kind':kind,'title':text(title),'reported':text(reported),'state':state(reported,fresh),'fields':[(k,text(v)) for k,v in fields], 'subtitle':subtitle,'reading':reading,'monitor':monitor,'children':children if children is not None else []}
        entries.append(item);return item
    def metric(label,value,unit,minimum=0,maximum=100,warning=70,danger=90,note=''):
        v=number(value) if fresh else None
        return {'label':label,'value':round(v,1) if v is not None else None,'unit':unit,'fill':max(0,min(100,(v-minimum)/(maximum-minimum)*100)) if v is not None and maximum>minimum else 0,'state':'unknown' if v is None else 'failed' if v>=danger else 'warning' if v>=warning else 'healthy','scale':f'{minimum}–{maximum} {unit}','note':note}
    total=number(m.get('memory_total_bytes'));available=number(m.get('memory_available_bytes'));ram=(total-available)/total*100 if total and available is not None and 0<=available<=total else None
    metrics=[metric('CPU usage',m.get('cpu_percent'),'%',note=f"{m['cpu_cores']} CPU cores" if number(m.get('cpu_cores')) is not None else ''),metric('CPU temperature',m.get('cpu_temperature'),'°C',20,100,70,85),metric('RAM usage',ram,'%',note=size(total-available)+' / '+size(total) if ram is not None else 'Used / total not reported'),metric('ZFS read cache',m.get('arc_gib'),'GiB',maximum=total/1024**3 if total else 0,warning=float('inf'),danger=float('inf'),note='Reclaimable cache (ARC)')]
    metrics[-1]['scale']='Share of system RAM' if total else 'Total RAM not reported'
    pools=[];disks=[];inventory={x['name']:x for x in d.get('disks',[]) if isinstance(x,dict) and x.get('name')};matched=set()
    def members(nodes,depth=0):
        if depth>12:return
        for node in nodes[:256] if isinstance(nodes,list) else []:
            if not isinstance(node,dict):continue
            if node.get('type')=='DISK':yield node
            else:yield from members(node.get('children',[]),depth+1)
    for index,p in enumerate(d.get('pools',[])):
        used=number(p.get('used_bytes'));free=number(p.get('available_bytes'));capacity=used+free if used is not None and free is not None else None
        e=entry('pool',p.get('name'),p.get('status'),[('RAID layout',p.get('raid')),('Used',size(used)),('Free',size(free)),('Capacity',size(capacity)),('Details',p.get('status_detail'))],monitor={'scope':'pool','target':str(p['id'])})
        if fresh and e['state']=='healthy' and (p.get('healthy') is False or p.get('warning')):e['state']='warning'
        e.update(percent=p.get('used_percent'),free=size(free),raid=p.get('raid'),color=index%5,count=0)
        scan=p.get('scan') or {}
        if isinstance(scan,dict):e['fields'] += [(k.replace('_',' ').capitalize(),text(v)) for k,v in scan.items() if k in ('function','state','errors','percentage')]
        topology=p.get('topology') or {}
        for role,nodes in topology.items() if isinstance(topology,dict) else []:
            for leaf in members(nodes):
                name=str(leaf.get('disk') or leaf.get('path') or leaf.get('name') or 'Unidentified device').removeprefix('/dev/')
                disk=inventory.get(name,{}) # Exact API identity only; never guess a partition's physical parent.
                if disk:matched.add(name)
                drive=entry('drive',name,leaf.get('status'),[('Pool',p.get('name')),('Role',role),('Media type',disk.get('type')),('Model',disk.get('model')),('Serial',disk.get('serial')),('Capacity',size(disk.get('size'))),('Bus',disk.get('bus')),('Rotation rate',disk.get('rotationrate')),('Read errors',leaf.get('stats',{}).get('read_errors')),('Write errors',leaf.get('stats',{}).get('write_errors')),('Checksum errors',leaf.get('stats',{}).get('checksum_errors')),('SMART health','Not collected'),('Temperature','Not collected')],identity=str(p['id'])+':'+name)
                stats=leaf.get('stats') or {}
                if fresh and drive['state']=='healthy' and any((number(stats.get(k)) or 0)>0 for k in ('read_errors','write_errors','checksum_errors')):
                    drive['state']='warning';drive['indicator']='I/O errors'
                drive.update(pool=e['key'],pool_name=e['title'],color=index%5,media=disk.get('type') if disk.get('type') in ('HDD','SSD') else '?',capacity=size(disk.get('size')))
                disks.append(drive);e['count']+=1
        from .capacity_forecasts import forecast,pool_entity
        e['forecast']=forecast(store,pool_entity('truenas',connection,p),now,max_age=max(180,connection['config']['interval']*3),fresh=fresh and used is not None and free is not None and used>=0 and free>=0)
        pools.append(e)
    for name,disk in inventory.items():
        if name in matched:continue
        drive=entry('drive',name,None,[('Pool','No exact pool association reported'),('Media type',disk.get('type')),('Capacity',size(disk.get('size'))),('Model',disk.get('model')),('Serial',disk.get('serial')),('SMART health','Not collected')])
        drive.update(pool='',pool_name='Unmapped',color=4,media=disk.get('type') if disk.get('type') in ('HDD','SSD') else '?',capacity=size(disk.get('size')));disks.append(drive)
    ports=[]
    for name,interface in d.get('interfaces',{}).items():
        speed=number(interface.get('speed'));link=interface.get('link_state')
        e=entry('interface',name,link,[('Link','Up' if link=='LINK_STATE_UP' else 'Down' if link=='LINK_STATE_DOWN' else None),('Speed',f'{speed:,.0f} Mb/s' if speed is not None and speed>0 else None),('Received',size(interface.get('received_bytes_rate'))+'/s'),('Sent',size(interface.get('sent_bytes_rate'))+'/s')],subtitle='Network interface',reading=f'{speed/1000:g} Gb/s' if speed and speed>=1000 else f'{speed:g} Mb/s' if speed and speed>0 else '—')
        e['reported']='Up' if link=='LINK_STATE_UP' else 'Down' if link=='LINK_STATE_DOWN' else 'Not reported'
        ports.append(e)
    apps=[];containers=[];vms=[]
    for app in d.get('apps',[]):
        am=app.get('metrics',{});children=[]
        e=entry('app',app['name'],app.get('state'),[('Version',app.get('version')),('Update','Available' if app.get('upgrade_available') else 'No update reported'),('CPU',f"{am['cpu_percent']:.1f}%" if number(am.get('cpu_percent')) is not None else None),('RAM',f"{am['memory_gib']:.2f} GiB" if number(am.get('memory_gib')) is not None else None)],subtitle=f"{len(app.get('containers',[]))} containers · {text(app.get('version'))}",reading=f"{am['cpu_percent']:.1f}% CPU" if fresh and number(am.get('cpu_percent')) is not None else 'CPU not reported',monitor={'scope':'app','target':app['name']},children=children)
        for key,label in [('receive_kib_s','Network received'),('transmit_kib_s','Network sent'),('read_mib','Disk read total'),('write_mib','Disk write total')]:
            if number(am.get(key)) is not None:e['fields'].append((label,f"{am[key]:,.2f} "+('KiB/s' if key.endswith('kib_s') else 'MiB')))
        for v in app.get('volumes',[]):
            e['fields'].append(('Storage mount',text(v.get('source'))+' → '+text(v.get('destination')) if isinstance(v,dict) else text(v)))
        for p in app.get('ports',[]):e['fields'].append(('Exposed port',port_text(p)))
        for c in app.get('containers',[]):
            ce=entry('container',c.get('service_name'),c.get('state'),[('Application',app['name']),('Image',c.get('image')),('CPU / RAM','Separate container usage not reported')],subtitle=app['name'],reading=text(c.get('image')),children=[{'key':e['key'],'title':'View '+app['name']}],identity=app['name']+':'+str(c.get('id') or c.get('service_name')));containers.append(ce);children.append({'key':ce['key'],'title':ce['title']})
            for v in c.get('volume_mounts',[]):ce['fields'].append(('Storage mount',text(v.get('source'))+' → '+text(v.get('destination')) if isinstance(v,dict) else text(v)))
            for p in c.get('port_config',[]):ce['fields'].append(('Exposed port',port_text(p)))
        apps.append(e)
    for vm in d.get('vms',[]):
        memory=number(vm.get('memory'));vcpu=number(vm.get('vcpus'));cores=number(vm.get('cores'));threads=number(vm.get('threads'));allocated=vcpu*cores*threads if vcpu is not None and cores is not None and threads is not None else None
        e=entry('vm',vm.get('name'),vm.get('state'),[('Allocated vCPUs',allocated),('Allocated memory',size(memory*1024**2) if memory is not None else None),('Autostart','Yes' if vm.get('autostart') is True else 'No' if vm.get('autostart') is False else None),('Guest metrics','Not collected by the NAS API')],subtitle='Virtual machine · allocated resources',reading=f'{text(allocated)} vCPUs · '+(size(memory*1024**2) if memory is not None else 'RAM not reported'),identity=vm.get('id',vm.get('name')))
        for device in vm.get('devices',[]):e['fields'].append((text(device.get('dtype')),device.get('path') or device.get('nic_attach') or 'No path reported'))
        vms.append(e)
    states=[x['state'] for x in disks+pools];alerts=d.get('alerts',[])
    health='unknown' if not fresh else 'failed' if 'failed' in states or any(a.get('level') in ('ERROR','CRITICAL','ALERT','EMERGENCY') for a in alerts) else 'warning' if 'warning' in states or alerts else 'unknown' if not pools or 'unknown' in states or d.get('warnings') else 'healthy'
    title={'healthy':'Storage looks good','warning':'Review storage health','failed':'Storage needs attention','unknown':'Visibility is incomplete'}[health]
    description={'healthy':'Reported pool members are online. SMART health and file access are separate checks.','warning':'Review the reported warnings and affected components.','failed':'A failure or serious NAS alert was reported. Select the affected component.','unknown':'Some readings are unavailable or stale. Review API visibility before drawing conclusions.'}[health]
    window=window if window in WINDOWS else '1h';now=time.time() if now is None else now;start=now-WINDOWS[window]
    rows=store.rows("SELECT at,metrics FROM metric_samples WHERE entity_id=? AND source='truenas' AND at>=? AND at<=? ORDER BY at DESC LIMIT 10001",(host['id'],start,now));capped=len(rows)>10000;samples=[]
    for row in reversed(rows[:10000]):
        values=json.loads(row['metrics']);point={'at':row['at']*1000}
        for key,source,scale in [('read','disk_read_bytes',1e6),('write','disk_write_bytes',1e6),('receive','receive_kib_s',1e6/1024),('send','transmit_kib_s',1e6/1024)]:
            v=number(values.get(source));point[key]=v/scale if v is not None and v>=0 else None
        samples.append(point)
    return {'connection':connection,'fresh':fresh,'metrics':metrics,'entries':entries,'disks':disks,'pools':pools,'ports':ports,'apps':apps,'containers':containers,'vms':vms,'vm_available':'vms' in d,'disk_available':'disks' in d,'health':health,'title':title,'description':description,'samples':samples,'window':window,'windows':WINDOWS,'start':start*1000,'end':now*1000,'gap':max(180,connection['config']['interval']*3)*1000,'capped':capped}


def port_text(p):
    if not isinstance(p,dict):return text(p)
    return ' · '.join(f'{k.replace("_"," ")}: {text(p[k])}' for k in ('host_ip','host_port','container_port','protocol') if k in p) or 'Not reported'
