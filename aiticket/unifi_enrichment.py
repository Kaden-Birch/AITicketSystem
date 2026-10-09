"""Site-scoped network facts and explicitly inferred IP membership."""
import ipaddress
import json
import time


def networks(readings):
    result=[]
    for item in readings.get('networks',{}).get('items',[]):
        row={**item,**readings.get('network:'+str(item.get('id')),{})}
        cfg=row.get('ipv4Configuration',{});dhcp=cfg.get('dhcpConfiguration',{})
        try:subnet=str(ipaddress.ip_network(str(cfg['hostIpAddress'])+'/'+str(cfg['prefixLength']),strict=False))
        except (KeyError,ValueError,TypeError):subnet=None
        result.append({'id':row.get('id'),'name':row.get('name','Unnamed network'),'vlan_id':row.get('vlanId'),'subnet':subnet,'gateway':cfg.get('hostIpAddress'),'dhcp':dhcp,'enabled':row.get('enabled'),'observed_at':row.get('_observed_at')})
    return result


def match(address,rows,connection,site,at,interface=None):
    try:ip=ipaddress.ip_interface(address).ip
    except (ValueError,TypeError):return None
    candidates=[r for r in rows if r['subnet'] and r['enabled'] is not False and ip in ipaddress.ip_network(r['subnet'])]
    if not candidates:return None
    config_at=min((r['observed_at'] or at for r in candidates),default=at)
    return {'fresh':0<=at-config_at<=180,'ip':str(ip),'interface':interface,'connection_id':connection,'site_id':site,'observed_at':at,'configuration_observed_at':config_at,'basis':'Inferred from IP address and UniFi network configuration.','state':'inferred' if len(candidates)==1 else 'ambiguous','networks':candidates}


def enrich(connection,snapshot):
    readings=snapshot['readings'];rows=networks(readings)
    readings['network_definitions']=rows
    names={r['id']:r.get('name',r['id']) for r in readings.get('devices',{}).get('items',[])}
    for kind in ('devices','clients'):
        for item in readings.get(kind,{}).get('items',[]):
            key=('device:' if kind=='devices' else 'client:')+str(item.get('id'))
            row={**item,**readings.get(key,{})}
            membership=match(row.get('ipAddress'),rows,connection['id'],connection['site'],snapshot['sampled_at'])
            row['network_membership']=membership
            upstream=(row.get('uplink') or {}).get('deviceId',row.get('uplinkDeviceId'))
            if upstream:row['resolved_uplink']={'device_id':upstream,'name':names.get(upstream),'href':'/network-devices/'+connection['id']+'/devices/'+upstream if upstream in names else None}
            item.update(row)
            if key in readings:readings[key]=row


def host_memberships(store,machine,now=None):
    now=time.time() if now is None else now
    inventory=store.rows('SELECT data,at FROM network_inventory WHERE machine_id=?',(machine,))
    interfaces=json.loads(inventory[0]['data']) if inventory else []
    if isinstance(interfaces,dict):interfaces=interfaces.get('interfaces',[])
    addresses=[(i.get('name'),a) for i in interfaces for a in i.get('addresses',[])]
    if not addresses:
        agents=store.rows('SELECT address FROM agents WHERE machine_id=? AND revoked=0',(machine,))
        addresses=[(None,r['address']) for r in agents if r['address']]
    from .topology import context
    with store.connect() as c:topology=context(c,machine) or {}
    scopes={r['connection_id'] for r in topology.get('links',[]) if r.get('confidence') in ('confirmed','corroborated')}
    scopes.update(r['connection_id'] for r in store.rows('SELECT connection_id FROM network_links WHERE machine_id=?',(machine,)))
    scopes.update(r['connection_id'] for r in store.rows('SELECT connection_id FROM unifi_devices WHERE machine_id=? AND deleted IS NULL',(machine,)))
    connections=store.rows("SELECT u.*,c.interval FROM unifi_connections u LEFT JOIN checks c ON c.id=u.check_id WHERE u.deleted IS NULL AND u.kind='network' AND u.site<>''")
    if not scopes and len(connections)==1:scopes={connections[0]['id']}
    result=[]
    for c in connections:
        if c['id'] not in scopes:continue
        snapshot=json.loads(c['snapshot'] or '{}');at=snapshot.get('sampled_at',0)
        rows=networks(snapshot.get('readings',{}))
        for interface,address in addresses:
            item=match(address,rows,c['id'],c['site'],at,interface)
            if item:
                item['fresh']=bool(at and 0<=now-at<=max(180,3*(c['interval'] or 60)) and 0<=now-item['configuration_observed_at']<=max(180,3*(c['interval'] or 60)) and inventory and 0<=now-inventory[0]['at']<=180)
                item['address_observed_at']=inventory[0]['at'] if inventory else None
                result.append(item)
    return result


def cameras(snapshot,connection,fresh):
    readings=snapshot.get('readings',{});items=readings.get('protect:cameras',[])
    if isinstance(items,dict):items=items.get('data',items.get('cameras',[]))
    result=[]
    for item in items if isinstance(items,list) else []:
        row={**item,**readings.get('protect:camera:'+str(item.get('id')),{})}
        state=str(row.get('state','UNKNOWN')).upper()
        result.append({'id':connection+':'+str(row.get('id')),'name':row.get('name','Camera'),'model':row.get('type',row.get('modelKey','Camera')),'reported_state':state,'state':'unknown' if not fresh else 'healthy' if state=='CONNECTED' else 'failed' if state in ('DISCONNECTED','OFFLINE') else 'unknown','fresh':fresh,'href':'/network-devices/'+connection+'#protect-cameras'})
    return result
