"""Read-only presentation data for the approved host design."""
import copy
import json


def activity(charts,key,label,definitions):
    traces=[]
    reference=next((chart for metric,_ in definitions for chart in charts if chart['key']==metric),None)
    for metric,name in definitions:
        source=next((chart for chart in charts if chart['key']==metric),None)
        if not reference:continue
        samples=[{'at':sample['at'],'value':sample['value']/1e6 if source and sample['value'] is not None else None} for sample in (source or reference)['samples']]
        traces.append({'label':name,'samples':samples,'latest':source['latest']/1e6 if source else None})
    values=[sample['value'] for trace in traces for sample in trace['samples'] if sample['value'] is not None]
    ceiling=max(values)*1.1 if values and max(values)>0 else 1
    for trace in traces:
        segments=[];points=[]
        for i,sample in enumerate(trace['samples']):
            if sample['value'] is None:
                if points:segments.append(' '.join(points));points=[]
            else:points.append(f"{35+(i+.5)/120*530:.1f},{140-min(ceiling,max(0,sample['value']))/ceiling*115:.1f}")
        if points:segments.append(' '.join(points))
        trace['segments']=segments
    return {'key':key,'label':label,'unit':' MB/s','latest':traces[0]['latest'] if traces else None,'ceiling':max(.000001,round(ceiling,6)),'segments':[],'samples':traces[0]['samples'] if traces else [],'traces':traces,'unavailable':not traces}


def prepare(data):
    inventory = data.get('discovery')
    processes = inventory['data']['processes'] if inventory else []
    monitored = {}
    for check in data['checks']:
        try: target=json.loads(check.get('config','{}')).get('target')
        except (ValueError,TypeError): target=None
        if target and check['enabled']:monitored[(check['kind'],target)]=check['id']
    if inventory:
        for key,kind in [('containers','docker'),('processes','process')]:
            for item in inventory['data'].get(key,[]):item['check_id']=monitored.get((kind,item.get('target')))
    data['top_processes'] = sorted(processes, key=lambda row: (row.get('cpu_percent', -1), row.get('memory_bytes', -1)), reverse=True)[:3]
    def priority(row):
        return (not row['enabled'], 0 if row['health'] == 'down' else 1 if row['failures'] else 2 if row['health'] != 'healthy' else 3, row['name'].casefold())
    data['overview_checks'] = sorted(data['checks'], key=priority)
    charts=copy.deepcopy(data.get('history',{}).get('charts',[]))
    raw=data.get('host',{}).get('sample',{}).get('raw',{})
    total=raw.get('memory_total_bytes',raw.get('maxmem'))
    memory=next((c for c in charts if c['key']=='ram_percent'),None)
    if memory:
        memory['label']='RAM'
        if isinstance(total,(int,float)) and total>0:
            factor=total/1e9/100
            memory['unit']=' GB'
            for key in ('latest','min','max','ceiling'):memory[key]=round(memory[key]*factor,2)
            for sample in memory['samples']:
                if sample['value'] is not None:sample['value']*=factor
    primary=[]
    for key,label,unit in [('cpu_percent','CPU','%'),('ram_percent','RAM',' GB'),('network_activity','Network activity',' MB/s'),('disk_activity','Disk activity',' MB/s')]:
        primary.append(next((c for c in charts if c['key']==key),{'key':key,'label':label,'unit':unit,'latest':None,'min':None,'max':None,'ceiling':1,'segments':[],'samples':[],'unavailable':True}))
    primary[2]=activity(charts,'network_activity','Network activity',[('network_rx_bytes_per_second','Received'),('network_tx_bytes_per_second','Sent')])
    primary[3]=activity(charts,'disk_activity','Disk activity',[('disk_read_bytes_per_second','Read'),('disk_write_bytes_per_second','Write')])
    data['overview_charts']=primary
    data['display_charts']=charts
    data['additional_charts']=[c for c in charts if c['key'] not in ('cpu_percent','ram_percent','network_rx_bytes_per_second','network_tx_bytes_per_second','disk_read_bytes_per_second','disk_write_bytes_per_second')]
    at=data.get('host',{}).get('sample',{}).get('at')
    uptime=raw.get('uptime_seconds',raw.get('uptime'))
    data['overview_boot']=at-uptime if isinstance(at,(int,float)) and isinstance(uptime,(int,float)) else None
    def size(value):
        if not isinstance(value,(int,float)):return 'Unavailable'
        return f'{value/1e9:.1f} GB' if value>=1e9 else f'{value/1e6:.0f} MB'
    data['overview_sizes']={}
    for kind,free_key in [('memory','memory_available_bytes'),('disk','disk_free_bytes')]:
        amount=raw.get(kind+'_total_bytes');free=raw.get(free_key)
        data['overview_sizes'][kind+'_total']=size(amount)
        data['overview_sizes'][kind+'_used']=size(amount-free) if isinstance(amount,(int,float)) and isinstance(free,(int,float)) else 'Unavailable'
    data['overview_uptime']=({'value':round(uptime/86400,1),'unit':' days'} if uptime>=86400 else {'value':round(uptime/3600,1),'unit':' hours'} if uptime>=3600 else {'value':round(uptime/60),'unit':' min'}) if isinstance(uptime,(int,float)) else {'value':'—','unit':''}
    obj=data.get('host',{}).get('object')
    data['overview_ha']=bool(obj and json.loads(obj.get('metrics','{}')).get('_ha_managed') is True)

    data['overview_load']=' / '.join(f'{raw[key]:.2f}' if isinstance(raw.get(key),(int,float)) else '—' for key in ('load_1','load_5','load_15'))
    links=data.get('host',{}).get('topology',{}).get('links',[])
    data['overview_link']=next((link for link in links if link.get('fresh') and link.get('confidence') in ('confirmed','corroborated')),None)
    interfaces=data.get('host',{}).get('topology',{}).get('interfaces',[])
    data['overview_interface']=next((item for item in interfaces if item.get('name')==(data['overview_link'] or {}).get('interface')),None) or next((item for item in interfaces if item.get('carrier') is True and not item.get('master')),None)
    data['overview_io']={key:raw.get(key) for key in ('disk_busy_percent','disk_latency_ms','disk_devices_sampled','network_interfaces_sampled','network_rx_errors_per_second','network_tx_errors_per_second','network_rx_dropped_per_second','network_tx_dropped_per_second')}
    access=next((p for p in data.get('access_paths',[]) if p['fresh']),None)
    reading=access['data'].get('internal',{}) if access else {}
    certificate=reading.get('certificate',{})
    data['overview_access']={'host':reading.get('host','Not reported'),'state':access['health'].capitalize() if access else 'Not reported','certificate':str(certificate['days_remaining'])+' days remaining' if 'days_remaining' in certificate else certificate.get('state','Not reported').replace('_',' ')}
    containers=inventory['data'].get('containers',[]) if inventory else []
    running=sum(c.get('state')=='running' for c in containers)
    unhealthy=sum(c.get('health')=='unhealthy' for c in containers)
    data['overview_container_summary']=(('Current' if inventory.get('fresh',False) else 'Last reported')+' · '+str(running)+' running · '+str(len(containers)-running)+' stopped'+(' · '+str(unhealthy)+' unhealthy' if unhealthy else '')) if inventory else 'No current container inventory reported'
    return data
