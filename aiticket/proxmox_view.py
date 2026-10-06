"""Cluster workspace projections; never infer guest filesystem usage or HA readiness."""
import ipaddress
import json
import time
from .hostview import sample


def build(store, host):
    obj=host.get('object')
    if not obj or obj['kind']!='node': return None
    now=time.time()
    agents={a['machine_id']:a for a in store.rows('SELECT * FROM agents')}
    networks={r['machine_id']:r for r in store.rows('SELECT * FROM network_inventory')}
    objects=store.rows('SELECT * FROM proxmox_objects WHERE cluster_id=? AND present=1 ORDER BY name,object_key',(obj['cluster_id'],))
    cluster=store.rows('SELECT name FROM proxmox_clusters WHERE id=?',(obj['cluster_id'],))[0]
    def address_list(machine):
        record=networks.get(machine);agent=agents.get(machine)
        if not record or not agent or agent['revoked'] or not record['at'] or not 0<=now-record['at']<=180:return []
        addresses=[]
        for interface in json.loads(record['data']).get('interfaces',[]):
            for address in interface.get('addresses',[]):
                try:ip=ipaddress.ip_address(address.split('%')[0])
                except ValueError:continue
                if not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified:addresses.append(address)
        return list(dict.fromkeys(addresses))[:16]
    nodes=[]
    for node in objects:
        if node['kind']!='node':continue
        raw=json.loads(node['metrics']);ns=sample(None,node,now)
        n={'id':node['node'],'name':node['name'],'href':'/hosts/'+node['machine_id'] if node['machine_id'] else '/proxmox/resources/'+node['id'],'online':node['status']=='online','fresh':ns['fresh'],'cpu':ns['cpu'],'ram':ns['ram'],'cores':raw.get('maxcpu'),'memory':raw.get('maxmem',0)/1024**3,'uptime':ns['uptime'],'guests':[]}
        for guest in objects:
            if guest['kind'] not in ('qemu','lxc') or guest['node']!=node['node']:continue
            gr=json.loads(guest['metrics']);agent=agents.get(guest['machine_id']);gs=sample(agent,guest,now) if agent and not agent['revoked'] else sample(None,guest,now)
            ps=sample(None,guest,now)
            # Prefer fresh agent metrics. A stale agent does not hide a fresh API CPU/RAM sample.
            if not gs['fresh']:gs=ps
            disk_ok=gs['fresh'] and (gs['source'].endswith('agent') or guest['kind']=='lxc')
            total=gs['raw'].get('disk_total_bytes') if disk_ok else None;free=gs['raw'].get('disk_free_bytes') if disk_ok else None
            n['guests'].append({'id':guest['object_key'].split('/')[-1],'object_id':guest['id'],'machine_id':guest['machine_id'],'name':guest['name'],'href':'/hosts/'+guest['machine_id'] if guest['machine_id'] else '/proxmox/resources/'+guest['id'],'type':'vm' if guest['kind']=='qemu' else 'ct','template':bool(guest['template']),'running':guest['status']=='running','status':guest['status'],'fresh':ps['fresh'],'linked':bool(guest['machine_id']),'agent':bool(agent and not agent['revoked']),'cpu':gs['cpu'] if gs['fresh'] else None,'mem':(gs['raw']['memory_total_bytes']-gs['raw']['memory_available_bytes'])/1024**3 if gs['fresh'] and all(k in gs['raw'] for k in ('memory_total_bytes','memory_available_bytes')) else None,'maxmem':gs['raw'].get('memory_total_bytes',0)/1024**3,'vcpus':gr.get('maxcpu',0),'allocatedDisk':gr.get('maxdisk',0)/1024**3,'disk':total/1024**3 if total else gr.get('maxdisk',0)/1024**3,'diskUsed':(total-free)/1024**3 if total and free is not None else None,'ips':address_list(guest['machine_id']),'ha':gr.get('_ha_managed') if ps['fresh'] else None,'source':gs['source']})
        nodes.append(n)
    storage=[]
    for resource in objects:
        if resource['kind']=='storage':
            raw=json.loads(resource['metrics']);storage.append({'name':resource['name'],'node':resource['node'],'used':raw.get('disk'),'total':raw.get('maxdisk'),'fresh':sample(None,resource,now)['fresh'],'status':resource['status']})
    return {'cluster':cluster['name'],'selected':obj['node'],'nodes':nodes,'storage':storage,'at':obj['last_seen']}


def guest_history(store,obj,window='1h'):
    from .metric_history import WINDOWS
    window=window if window in WINDOWS else '1h';now=time.time()
    agent=next(iter(store.rows('SELECT * FROM agents WHERE machine_id=? AND revoked=0',(obj['machine_id'],))),None)
    agent=agent if agent and sample(agent,obj,now)['fresh'] else None
    source='agent' if agent else 'proxmox';entity=obj['machine_id'] if agent else obj['id']
    rows=store.rows('SELECT at,metrics FROM metric_samples WHERE entity_id=? AND source=? AND at>=? AND at<=? ORDER BY at DESC LIMIT 20000',(entity,source,now-WINDOWS[window],now))
    fields=['cpu_percent','ram_percent']+(['disk_percent'] if agent or obj['kind']=='lxc' else [])
    return {'source':source,'start':now-WINDOWS[window],'end':now,'charts':[{'label':{'cpu_percent':'CPU usage','ram_percent':'RAM usage','disk_percent':'Storage usage'}[key],'unit':'%','samples':[{'time':r['at']*1000,'value':json.loads(r['metrics'])[key]} for r in reversed(rows) if key in json.loads(r['metrics'])]} for key in fields]}
