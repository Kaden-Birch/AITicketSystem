"""Presentation of reported Network telemetry; no monitoring or action decisions."""
import json
from .unifi_nas_view import build as storage_view, number


def build(store,machine,readings,fresh,errors,network_names,window='1h',interval=60):
    original=readings.get('device',{})
    device=original if isinstance(original,dict) else {}
    statistics=readings.get('statistics',{})
    statistics=statistics if isinstance(statistics,dict) else {}
    merged={**device,**statistics}
    # Storage must belong to this device, never to another connection or console.
    storage=readings.get('storage',device.get('storage',{}))
    view=storage_view(store,machine,{'device':merged,'storage':storage},fresh,errors,window,interval)
    view['model']=device.get('model') or 'UniFi Network'
    interfaces=device.get('interfaces',{})
    interfaces=interfaces if isinstance(interfaces,dict) else {}
    rows=interfaces.get('ports',device.get('ports',[]))
    rows=rows if isinstance(rows,list) else []
    ports=[]
    uplink=device.get('uplink',{})
    uplink=uplink if isinstance(uplink,dict) else {}
    for row in rows[:256]:
        if not isinstance(row,dict):continue
        idx=next((row[k] for k in ('idx','index','portIndex','portIdx') if type(row.get(k)) is int),None)
        if idx is None or not 0<=idx<=4096:continue
        reported=str(row.get('state',row.get('status','UNKNOWN'))).upper()
        poe=row.get('poe',{});poe=poe if isinstance(poe,dict) else {}
        error_count=sum(max(0,number(row.get(k)) or 0) for k in ('rxErrors','txErrors','errors'))
        state='unknown' if not fresh else 'failed' if reported in ('FAILED','FAULTED','ERROR') else 'warning' if reported=='UP' and (error_count or poe.get('state')=='LIMITED') else 'healthy' if reported=='UP' else 'idle' if reported=='DOWN' else 'unknown'
        is_uplink=row.get('uplink') is True or (type(uplink.get('portIndex')) is int and uplink['portIndex']==idx)
        label={'healthy':'Connected','idle':'No link','warning':'Review port','failed':'Port fault','unknown':'Unavailable'}[state]
        speed=number(row.get('speedMbps'))
        connector=str(row.get('connector',row.get('media','RJ45')))
        tagged=row.get('taggedNetworkIds',[]);tagged=tagged if isinstance(tagged,list) else []
        fields=[('Reported state',reported),('Connector',connector),('Link speed',f'{speed:g} Mbps' if speed is not None else 'Not reported'),('Maximum speed',f'{row["maxSpeedMbps"]:g} Mbps' if number(row.get('maxSpeedMbps')) is not None else 'Not reported'),('Native network',network_names.get(row.get('nativeNetworkId'),'Not reported')),('Tagged networks',', '.join(network_names.get(n,'Unnamed network') for n in tagged) or 'Not reported'),('Uplink','Reported uplink' if is_uplink else 'Not reported'),('PoE',str(poe.get('state','Not reported'))),('PoE standard',str(poe.get('standard','Not reported')))]
        for key,name in [('rxErrors','Receive errors'),('txErrors','Transmit errors'),('dropped','Dropped packets'),('rxBytes','Received bytes'),('txBytes','Sent bytes')]:
            if number(row.get(key)) is not None:fields.append((name,f'{row[key]:,}'))
        ports.append({'number':idx,'name':str(row.get('name') or f'Port {idx}'),'state':state,'label':label,'uplink':is_uplink,'fiber':connector.upper().startswith(('SFP','QSFP')),'connector':connector,'fields':fields})
    ports.sort(key=lambda p:p['number'])
    view['ports']=ports
    view['connected']=sum(p['state'] in ('healthy','warning') for p in ports)
    view['powered']=sum(isinstance(r,dict) and isinstance(r.get('poe'),dict) and r['poe'].get('state')=='UP' for r in rows) if fresh else None
    states=[p['state'] for p in ports]+[d['state'] for d in view['disks']]+[p['state'] for p in view['pools']]
    reported=str(device.get('state',device.get('status','UNKNOWN'))).upper()
    state='unknown' if not fresh else 'failed' if reported in ('OFFLINE','DISCONNECTED') or 'failed' in states else 'warning' if 'warning' in states else 'unknown' if reported!='ONLINE' or errors else 'healthy'
    view.update(state=state,title={'healthy':'Everything looks good','warning':'A component needs attention','failed':'Device needs attention','unknown':'Visibility is incomplete'}[state],description={'healthy':'The device is online. Unused ports are shown in gray.','warning':'Review the highlighted port or drive for its reported details.','failed':'The device or a reported component has a fault.','unknown':'Some readings are missing or stale. Refresh to check current status.'}[state])
    # Use device uplink rates, not cumulative port byte counters or site-wide totals.
    rows=store.rows("SELECT at,metrics FROM metric_samples WHERE entity_id=? AND source='unifi' AND at>=? AND at<=? ORDER BY at DESC LIMIT 10001",(machine,view['start']/1000,view['end']/1000))
    view['capped']=len(rows)>10000;view['samples']=[]
    for row in reversed(rows[:10000]):
        values=json.loads(row['metrics'])
        rates=[number(values.get('statistics.uplink.'+key)) for key in ('rxRateBps','txRateBps')]
        if any(v is not None and v>=0 for v in rates):view['samples'].append({'at':row['at']*1000,'read':rates[0]/1e6 if rates[0] is not None and rates[0]>=0 else None,'write':rates[1]/1e6 if rates[1] is not None and rates[1]>=0 else None})
    return view
