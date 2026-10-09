"""Compact dashboard projections from existing read-only inventories."""
import json
import time
from .overview_ui import ticket_rows, host_list


def build(store, summary, now=None):
    now=time.time() if now is None else now
    tickets=[r for r in ticket_rows(store,now) if not r['resolved']]
    updated={r['incident_id']:r['at'] for r in store.rows('SELECT incident_id,max(at) at FROM timeline GROUP BY incident_id')}
    priorities={'critical':0,'high':1,'medium':2,'low':3}
    tickets.sort(key=lambda r:(priorities.get(r['severity'],4),-max(r['first_seen'],updated.get(r['id'],0) or 0),r['id']))
    compact=[{'id':r['id'],'title':r['title'],'host':r['machine'],'severity':r['severity'],'status':r['status'],'label':r['label'],'category':r['category'],'updated':max(r['first_seen'],updated.get(r['id'],0) or 0)} for r in tickets]
    hosts=host_list(store,now);nodes=[];seen=set()
    from .proxmox_view import build as cluster_view
    for host in hosts:
        obj=host.get('object')
        if not obj or obj['kind']!='node' or obj['cluster_id'] in seen:continue
        seen.add(obj['cluster_id']);cluster=cluster_view(store,host)
        for node in cluster['nodes']:
            node['key']=obj['cluster_id']+':'+node['id'];node['cluster']=cluster['cluster'];nodes.append(node)
    from .integrations import views
    from .truenas_view import build as nas_view
    nas=[];services=[]
    for connection in views(store):
        if connection['kind']=='truenas':
            host=next((h for h in hosts if h['id']==connection['machine_id']),None)
            if not host:continue
            view=nas_view(store,host,connection,now=now)
            nas.append({'name':host['name'],'id':host['id'],'href':'/hosts/'+host['id'],'fresh':view['fresh'],'state':view['health'],'metrics':view['metrics'][:3],'drives':view['disks'],'pools':view['pools'],'apps':view['apps'] if 'apps' in connection['data'] else None,'containers':view['containers'] if 'apps' in connection['data'] else None,'vms':view['vms'] if view['vm_available'] else None,'version':connection['data'].get('version','TrueNAS')})
        elif connection['kind']=='plex':
            current=connection['fresh'] and not connection['data'].get('error')
            locations=connection['data'].get('media_locations',[]) if current else []
            label=('Responding · '+str(sum(x.get('readable') is True for x in locations))+'/'+str(len(locations))+' location samples readable') if current and locations else 'Responding' if current and connection['data'].get('responsive') else 'Awaiting current results'
            services.append({'kind':'plex','name':connection['name'],'host':connection['host'],'href':'/services/'+connection['id'],'state':'warning' if current and connection['data'].get('media_access') is False else 'healthy' if current and connection['data'].get('responsive') else 'unknown','label':label})
    from .applications import view as application_view
    for app in application_view(store):
        services.append({'name':app['name'],'host':str(len(app['checks']))+' checks · '+str(len(app['dependencies']))+' dependencies','href':'/applications','state':app['health'],'label':'Healthy' if app['health']=='healthy' else 'Needs attention' if app['health']=='down' else 'Awaiting current results'})
    docker=store.rows('SELECT d.machine_id,d.at,d.data,m.name FROM agent_discovery d JOIN machines m ON m.id=d.machine_id JOIN agents a ON a.machine_id=d.machine_id WHERE a.revoked=0 AND a.last_seen>=?',(now-180,))
    for item in docker:
        inventory=json.loads(item['data'])
        if not inventory.get('docker_installed'):continue
        containers=inventory.get('containers',[]);current=0<=now-item['at']<=180
        unhealthy=sum(x.get('health')=='unhealthy' for x in containers)
        services.append({'name':item['name']+' · Docker','host':str(len(containers))+' discovered containers'+(' · limited inventory' if inventory.get('containers_truncated') else ''),'href':'/hosts/'+item['machine_id'],'state':'warning' if current and unhealthy else 'unknown','label':str(unhealthy)+' unhealthy' if current and unhealthy else str(sum(x.get('state')=='running' for x in containers))+' running' if current else 'Awaiting current inventory'})
    from .unifi_network_view import build as network_view
    from .unifi_nas_view import build as drive_view
    network=[];camera_inventory=[];camera_groups=[]
    for connection in store.rows('SELECT u.id,u.name,u.kind,u.machine_id,u.snapshot,c.interval FROM unifi_connections u LEFT JOIN checks c ON c.id=u.check_id WHERE u.deleted IS NULL ORDER BY u.name'):
        snapshot=json.loads(connection['snapshot'] or '{}');entries=[]
        from .unifi_enrichment import cameras
        items=cameras(snapshot,connection['id'],bool(snapshot.get('sampled_at') and 0<=now-snapshot['sampled_at']<=max(180,3*(connection['interval'] or 60))))
        camera_inventory.extend(items)
        if items:camera_groups.append({'id':connection['id'],'name':connection['name'],'cameras':items})
        device_names={r['device_id']:json.loads(r['data']).get('device',{}).get('name',r['device_id']) for r in store.rows('SELECT device_id,data FROM unifi_devices WHERE connection_id=? AND deleted IS NULL',(connection['id'],))}
        if connection['kind']=='drive':entries.append((connection['name'],connection['machine_id'],snapshot.get('sampled_at'),snapshot.get('readings',{}),'/network-devices/'+connection['id'],True))
        else:
            for device in store.rows('SELECT * FROM unifi_devices WHERE connection_id=? AND deleted IS NULL ORDER BY device_id',(connection['id'],)):
                readings=json.loads(device['data']);entries.append((readings.get('device',{}).get('name',device['device_id']),device['machine_id'],device['last_seen'],readings,'/network-devices/'+connection['id']+'/devices/'+device['device_id'],False))
        for name,machine,at,readings,href,is_nas in entries:
            fresh=bool(at and 0<=now-at<=max(180,3*(connection['interval'] or 60)))
            view=drive_view(store,machine,readings,fresh,snapshot.get('errors',{})) if is_nas else network_view(store,machine,readings,fresh,snapshot.get('errors',{}),{})
            device=view['device'];ports=view.get('ports',[])
            drives=[]
            rawdisks=readings.get('storage',device.get('storage',{}));rawdisks=rawdisks.get('disks',[]) if isinstance(rawdisks,dict) else []
            for disk in view['disks']:
                raw=next((d for d in rawdisks if isinstance(d,dict) and str(d.get('slotId'))==disk['slot']),{})
                media=str(raw.get('mediaType',raw.get('type',''))).upper()
                drives.append({**disk,'media':media if media in ('HDD','SSD') else '?','title':'Drive '+disk['slot']})
            radios=view.get('radios',[])
            network.append({'id':machine,'name':name,'href':href,'model':view['model'],'fresh':fresh,'state':view['state'],'metrics':view['metrics'],'ports':ports,'connected':view.get('connected') if fresh and any(p['state']!='unknown' for p in ports) else None,'uplink':view.get('uplink',{}),'uplink_href':readings.get('device',{}).get('resolved_uplink',{}).get('href'),'uplink_name':device_names.get(view.get('uplink',{}).get('deviceId')),'drives':drives,'pools':view['pools'],'radios':radios,'kind':str(device.get('type','')).lower(),'clients':readings.get('statistics',{}).get('clientCount') if fresh else None})
    return {'summary':summary,'tickets':compact[:5],'attention':sorted([r for r in compact if r['category']=='manual'],key=lambda r:-r['updated'])[:3],'nodes':nodes,'nas':nas,'network':network,'services':services,'cameras':camera_inventory,'camera_groups':camera_groups,'nvrs':[d for d in network if d['drives'] and d['kind'] in ('gateway','udm','nvr','unvr')],'monitoring_attention':0}
