"""Read-only presentation of UniFi Drive snapshots; never changes monitoring decisions."""
import json
import math
import time

WINDOWS={'10m':600,'30m':1800,'1h':3600,'6h':21600,'24h':86400,'7d':604800,'30d':2592000}


def number(value):
    return value if type(value) in (int,float) and math.isfinite(value) else None


def size(value):
    value=number(value)
    if value is None or value<0:return 'Not reported'
    for scale,unit in [(1e12,'TB'),(1e9,'GB'),(1e6,'MB')]:
        if value>=scale:return f'{value/scale:,.1f} {unit}'
    return f'{value:,.0f} B'


def health(state):
    state=str(state or '').lower().replace('_','').replace('-','')
    if state in ('optimal','healthy','fullyoperational','online','ok'):return 'healthy'
    if state in ('failed','failure','faulted','dead'):return 'failed'
    if state in ('empty','notinstalled','absent'):return 'empty'
    if state in ('warning','degraded','error','rebuilding','initializing'):return 'warning'
    return 'unknown'


def build(store,machine,readings,fresh,errors,window='1h',interval=60,connection=None):
    device=readings.get('device',{});device=device if isinstance(device,dict) else {}
    storage=readings.get('storage',{});storage=storage if isinstance(storage,dict) else {}
    cpu=device.get('cpu',{});cpu=cpu if isinstance(cpu,dict) else {}
    memory=device.get('memory',{});memory=memory if isinstance(memory,dict) else {}
    load=number(cpu.get('currentload'));cpu_percent=load*100 if load is not None else number(device.get('cpuUtilizationPct'))
    total=number(memory.get('total'));available=number(memory.get('available'))
    ram=100*(1-available/total) if total and available is not None and 0<=available<=total else number(device.get('memoryUtilizationPct'))
    temperature=number(cpu.get('temperature'))
    def metric(label,value,low,high,warning,danger,unit):
        valid=fresh and value is not None and 0<=value<=(500 if unit=='°C' else 100)
        return {'label':label,'value':round(value,1) if valid else None,'unit':unit,'min':low,'max':high,'fill':round(max(0,min(100,(value-low)/(high-low)*100)),1) if valid else 0,'state':'unknown' if not valid else 'failed' if value>=danger else 'warning' if value>=warning else 'healthy'}
    metrics=[metric('CPU usage',cpu_percent,0,100,70,90,'%'),metric('CPU temperature',temperature,20,100,70,85,'°C'),metric('RAM usage',ram,0,100,75,90,'%')]
    disks=[]
    for index,item in enumerate(storage.get('disks',[]) if isinstance(storage.get('disks'),list) else []):
        if not isinstance(item,dict):continue
        slot=item.get('slotId',index+1);state=health(item.get('state')) if fresh else 'unknown'
        if state=='healthy' and any((number(item.get(k)) or 0)>0 for k in ('badSectorCount','uncorrectableSectorCount')):state='warning'
        fields=[('Model',item.get('model')),('Capacity',size(item.get('size'))),('Pool',item.get('poolId')),('Temperature',str(item['temperature'])+' °C' if number(item.get('temperature')) is not None else None),('Power-on time',str(item['powerOnHours'])+' hours' if number(item.get('powerOnHours')) is not None else None),('Bad sectors',item.get('badSectorCount')),('Uncorrectable sectors',item.get('uncorrectableSectorCount')),('Read error rate',item.get('readErrorRate')),('Health score',item.get('healthScore'))]
        disks.append({'slot':str(slot),'state':state,'reported':str(item.get('state') or 'Not reported'),'fields':[(k,str(v) if v is not None else 'Not reported') for k,v in fields]})
    # Only explicitly reported bay counts establish empty/missing slots. Never infer chassis size from a model name.
    count=number(storage.get('slotCount',device.get('slotCount')))
    if count is not None and count==int(count) and 0<count<=128 and all(d['slot'].isdigit() for d in disks):
        slots={int(d['slot']) for d in disks};base=0 if 0 in slots else 1
        if all(base<=i<base+count for i in slots):
            for slot in range(base,base+int(count)):
                if slot not in slots:disks.append({'slot':str(slot),'state':'unknown','reported':'No reading for this bay','fields':[]})
    disks.sort(key=lambda d:(0,int(d['slot'])) if d['slot'].isdigit() else (1,d['slot']))
    pools=[]
    for i,pool in enumerate(storage.get('pools',[]) if isinstance(storage.get('pools'),list) else []):
        if not isinstance(pool,dict):continue
        capacity=number(pool.get('capacity'));used=number(pool.get('usage'));valid=capacity and used is not None and 0<=used<=capacity
        raid=[str(g.get('currentLevel')) for g in pool.get('raidGroups',[]) if isinstance(g,dict) and g.get('currentLevel') is not None]
        pools.append({'name':'Pool '+str(pool.get('number',i+1)),'state':health(pool.get('status')) if fresh else 'unknown','status':str(pool.get('status') or 'Not reported'),'raid':', '.join(raid) or 'RAID type not reported','used':size(used),'capacity':size(capacity),'free':size(capacity-used) if valid else 'Not reported','percent':round(used/capacity*100,1) if valid else None})
        from .capacity_forecasts import forecast,pool_entity
        pools[-1]['forecast']=forecast(store,pool_entity('unifi',dict(connection),pool) if connection else None,max_age=max(180,interval*3),fresh=fresh and bool(valid))
    states=[d['state'] for d in disks if d['state']!='empty']+[p['state'] for p in pools]
    state='unknown' if not fresh else 'failed' if 'failed' in states else 'warning' if 'warning' in states else 'unknown' if errors or not states or 'unknown' in states else 'healthy'
    titles={'unknown':'Visibility is incomplete','failed':'Storage needs attention','warning':'Review storage health','healthy':'Everything looks good'}
    descriptions={'unknown':'Some readings are missing or stale. Refresh the connection to check current health.','failed':'A drive or pool has reported a failure. Review the affected component.','warning':'A drive or pool has reported a warning. Select it to review the available details.','healthy':'All reported drives and pools are healthy.'}
    window=window if window in WINDOWS else '1h';now=time.time();start=now-WINDOWS[window]
    rows=store.rows("SELECT at,metrics FROM metric_samples WHERE entity_id=? AND source='unifi' AND at>=? AND at<=? ORDER BY at DESC LIMIT 10001",(machine,start,now));capped=len(rows)>10000;rows=rows[:10000]
    def rate(values,fields):
        for suffix,scale in fields:
            parts=[v*scale/1e6 for k,v in values.items() if k.startswith('throughput.') and k.split('.')[-1]==suffix and number(v) is not None and v>=0]
            if parts:return sum(parts)
        return None
    samples=[]
    for row in reversed(rows):
        values=json.loads(row['metrics']);read=rate(values,[('receiveKBPS',1000),('rxBytesPerSecond',1),('rxRateBps',1)]);write=rate(values,[('transmitKBPS',1000),('txBytesPerSecond',1),('txRateBps',1)])
        if read is not None or write is not None:samples.append({'at':row['at']*1000,'read':read,'write':write})
    return {'metrics':metrics,'ram_detail':f'{size(total-available)} / {size(total)}' if total and available is not None and 0<=available<=total else 'Used / total not reported','disks':disks,'pools':pools,'state':state,'title':titles[state],'description':descriptions[state],'model':device.get('model') or 'UniFi NAS','temperatures':[number(d.get('temperature')) for d in storage.get('disks',[]) if isinstance(d,dict) and number(d.get('temperature')) is not None],'samples':samples,'window':window,'start':start*1000,'end':now*1000,'gap':max(180,interval*3)*1000,'capped':capped,'device':device}
