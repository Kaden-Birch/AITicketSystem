"""Source-scoped historical connection evidence alongside fresh API snapshots."""
import json
import math
import sqlite3
import time
from urllib.parse import quote
from . import network_logs as logs
from .topology import mac

WINDOWS={'1h':3600,'6h':21600,'24h':86400,'7d':604800,'30d':2592000}


def port(value):
    if type(value) is int and 0<=value<=4096: return value
    if isinstance(value,str) and value.isascii() and value.isdigit() and len(value)<=4 and int(value)<=4096: return int(value)
    return None


def attachments(event):
    fields=event['fields']; result=[]
    for prefix,role in [('UNIFIconnectedToDevice','observed'),('UNIFIlastConnectedToDevice','previous'),('UNIFIdevice','device')]:
        identifier=mac(fields.get(prefix+'Mac'))
        if identifier:
            result.append({'mac':identifier,'port':port(fields.get(prefix+'Port')),'role':role})
    if not result and event.get('device_mac'): result.append({'mac':event['device_mac'],'port':port(event.get('port')),'role':'observed'})
    return result


def event_kind(event):
    name=event['name'].lower()
    if 'disconnect' in name: return 'disconnect'
    if 'roam' in name: return 'roam'
    if 'connect' in name and not any(word in name for word in ('failed','failure','unable','reconnect')): return 'connect'
    return 'other'


def events(c, connection, device_mac, start, end):
    sources=[r[0] for r in c.execute('SELECT id FROM log_sources WHERE connection_id=?',(connection,))]
    if not sources or not device_mac: return {'items':[],'available':True,'configured':bool(sources),'truncated':False}
    try:
        with logs.reader(c) as archive:
            deadline=time.monotonic()+0.25
            archive.set_progress_handler(lambda:int(time.monotonic()>deadline),2000)
            clauses=['source_id IN ('+','.join('?' for _ in sources)+')','at>=?','at<=?']
            expressions=['device_mac=?']
            args=[*sources,start,end,device_mac]
            for key in ('UNIFIconnectedToDeviceMac','UNIFIlastConnectedToDeviceMac','UNIFIdeviceMac'):
                expressions.append("lower(replace(json_extract(fields,?),'-',':'))=?")
                args += ['$.'+key,device_mac]
            rows=archive.execute('SELECT * FROM events WHERE '+' AND '.join(clauses)+' AND ('+' OR '.join(expressions)+') ORDER BY at DESC,id DESC LIMIT 501',args).fetchall()
        return {'items':logs.decorate(c,rows[:500]),'available':True,'configured':True,'truncated':len(rows)>500}
    except (sqlite3.Error,OSError): return {'items':[],'available':False,'configured':True,'truncated':False}


def build(store, connection, device_id, device, snapshot, ports, window='24h', interval=60, now=None):
    now=time.time() if now is None else now; window=window if window in WINDOWS else '24h'
    start=now-WINDOWS[window]; identifier=mac(device.get('macAddress'))
    with store.connect() as c:
        history=events(c,connection,identifier,start,now+30)
        names={r['id']:r['name'] for r in c.execute('SELECT id,name FROM machines')}
        inventory={}
        for row in c.execute('SELECT machine_id,data FROM network_inventory'):
            for interface in json.loads(row['data']).get('interfaces',[]):
                address=mac(interface.get('mac'))
                if address: inventory.setdefault(address,set()).add(row['machine_id'])
        bindings={(r['source_id'],r['mac']):r['machine_id'] for r in c.execute('SELECT b.* FROM log_host_bindings b JOIN log_sources s ON s.id=b.source_id WHERE s.connection_id=?',(connection,))}
    readings=snapshot.get('readings',{}); clients=readings.get('clients',{})
    clients=clients if isinstance(clients,dict) else {}
    api_at=snapshot.get('sampled_at')
    api_fresh=bool(api_at and 0<=now-api_at<=max(180,interval*3))
    api_available=isinstance(clients,dict) and isinstance(clients.get('items'),list) and not snapshot.get('errors',{}).get('clients')
    def host_link(machine): return '/hosts/'+quote(machine,safe='') if machine in names else None
    current=[]; seen=set()
    for item in clients.get('items',[]) if api_available else []:
        if not isinstance(item,dict): continue
        uplink=item.get('uplink',{}); uplink=uplink if isinstance(uplink,dict) else {}
        target=item.get('uplinkDeviceId') or uplink.get('deviceId') or item.get('deviceId')
        if target!=device_id or not device_id: continue
        address=mac(item.get('macAddress')); key=address or item.get('id')
        if not key or key in seen: continue
        seen.add(key)
        matches=inventory.get(address,set()); machine=next(iter(matches)) if len(matches)==1 else None
        # A unique, consistent manual association may also label a client lacking agent inventory.
        manual={value for (source,client_mac),value in bindings.items() if client_mac==address}
        if len(manual)==1: machine=next(iter(manual))
        attachment=port(item.get('uplinkPortIndex',uplink.get('portIndex',item.get('portIdx'))))
        current.append({'key':str(key),'name':logs.safe(item.get('name') or names.get(machine) or item.get('ipAddress') or address or item.get('id'),100),
                        'ip':logs.address(item.get('ipAddress','')),'mac':address,'port':attachment,'host_url':host_link(machine),
                        'type':str(item.get('type',item.get('connectionType','UNKNOWN'))).upper(),
                        'basis':'API-reported attachment / forwarding path','observed_at':api_at,'fresh':api_fresh})
    previous={}; timelines=[]; samples=[]
    counts={'connect':0,'disconnect':0,'roam':0,'other':0}
    for event in history['items']:
        matched=[a for a in attachments(event) if a['mac']==identifier]
        if not matched: continue
        category=event_kind(event); counts[category]+=1
        associated=[a['machine_id'] for a in event['associations'] if a['role']=='client']
        machine=associated[0] if len(set(associated))==1 else None
        fields=event['fields']; address=event.get('client_mac')
        label=fields.get('UNIFIclientAlias') or fields.get('UNIFIclientHostname') or names.get(machine) or event.get('client_ip') or address or 'Unidentified client'
        key=address or 'event:'+str(event['id'])
        item=previous.setdefault(key,{'name':logs.safe(label,100),'mac':address,'ip':event['client_ip'],'host_url':host_link(machine),
                                     'last_seen':event['at'],'disconnects':0,'roams':0,'ports':set()})
        if category=='disconnect': item['disconnects']+=1
        if category=='roam': item['roams']+=1
        item['ports'].update(a['port'] for a in matched if a['port'] is not None)
        observation={'id':event['id'],'url':'/network-events/'+str(event['id']),'at':event['at'],'name':event['name'],
                     'message':event['message'][:250],'client':logs.safe(label,100),'kind':category,
                     'ports':[a['port'] for a in matched if a['port'] is not None],
                     'role':', '.join(sorted({a['role'] for a in matched})),'maintenance':event['maintenance']}
        timelines.append(observation)
        sample={'at':event['at']*1000,'event_url':observation['url'],'client':observation['client']}
        for key,keys,low,high in [('rssi',['UNIFIWiFiRssi','UNIFIwifiRssi','UNIFIlastConnectedToWiFiRssi'],-130,0),
                                 ('airtime',['UNIFIwifiAirtimeUtilization'],0,100),('interference',['UNIFIwifiInterference'],0,100)]:
            value=None
            for field in keys:
                try:
                    candidate=float(fields[field])
                    if math.isfinite(candidate) and low<=candidate<=high: value=candidate; break
                except (KeyError,ValueError,TypeError): pass
            sample[key]=value
        # On a roam, the prior AP's signal belongs to that AP, not the new AP.
        if category=='roam':
            if any(a['role']=='previous' for a in matched):
                try:
                    value=float(fields['UNIFIlastConnectedToWiFiRssi']); sample['rssi']=value if -130<=value<=0 else None
                except (KeyError,ValueError,TypeError): sample['rssi']=None
                sample['airtime']=sample['interference']=None
            elif any(a['role']=='observed' for a in matched):
                try:
                    value=float(fields.get('UNIFIWiFiRssi',fields.get('UNIFIwifiRssi'))); sample['rssi']=value if -130<=value<=0 else None
                except (ValueError,TypeError): sample['rssi']=None
        if any(sample[k] is not None for k in ('rssi','airtime','interference')): samples.append(sample)
    for item in previous.values(): item['ports']=sorted(item['ports'])
    # Port insights do not recolor or change any monitoring decision.
    for entry in ports:
        matching=[event for event in timelines if entry['number'] in event['ports']]
        entry['observations']={'clients':[item for item in current if item['port']==entry['number']],
            'history':[item for item in previous.values() if entry['number'] in item['ports']][:20],
            'events':matching[:12],'disconnects':sum(e['kind']=='disconnect' for e in matching),
            'event_count':len(matching),'last_at':matching[0]['at'] if matching else None}
    interfaces=device.get('interfaces',{}); interfaces=interfaces if isinstance(interfaces,dict) else {}
    is_wireless=bool(interfaces.get('radios')) or any(item['type']=='WIRELESS' for item in current) or bool(samples) or any('wifi' in item['name'].lower() or 'wi-fi' in item['name'].lower() for item in timelines)
    return {'window':window,'start':start,'end':now,'available':history['available'],'configured':history['configured'],
            'truncated':history['truncated'],'counts':counts,'events':timelines[:20],'clients':list(previous.values())[:40],
            'current_clients':current[:100],'api_at':api_at,'api_fresh':api_fresh,'api_available':api_available,
            'api_partial':bool(clients.get('truncated') or any(k.startswith('client:') for k in snapshot.get('errors',{})) or snapshot.get('warnings')),
            'samples':sorted(samples,key=lambda item:item['at']),'wireless':is_wireless,
            'labels':[['rssi','Signal','dBm'],['airtime','Airtime','%'],['interference','Interference','%']]}
