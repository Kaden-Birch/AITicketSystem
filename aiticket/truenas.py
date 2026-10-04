"""Read-only TrueNAS 25.04+ JSON-RPC collector; HexOS uses the same middleware."""
import json,ssl,time
from urllib.parse import urlsplit,urlunsplit
from .diagnostics import redact

READ_METHODS={'auth.login_ex','system.info','pool.query','pool.dataset.query','alert.list','service.query','app.query','core.subscribe'}

class RPCError(ValueError):
    def __init__(self,method):super().__init__('TrueNAS could not read '+{'auth.login_ex':'the account credentials','system.info':'system information','pool.query':'storage pools','pool.dataset.query':'datasets','app.query':'applications','service.query':'services','alert.list':'alerts','core.subscribe':'live statistics'}.get(method,'this information')+'. Check the account permissions and API version.')

class Client:
    def __init__(self,cfg):
        import websocket
        p=urlsplit(cfg['url']);self.deadline=time.monotonic()+40;self.serial=0;self.events={}
        self.ws=websocket.create_connection(urlunsplit(('wss',p.netloc,'/api/current','','')),timeout=5,sslopt={'cert_reqs':ssl.CERT_REQUIRED,'check_hostname':True,**({'ca_certs':cfg['ca']} if isinstance(cfg.get('ca'),str) else {})},redirect_limit=0)
    def receive(self):
        self.ws.settimeout(max(.1,min(5,self.deadline-time.monotonic())))
        raw=self.ws.recv()
        if len(raw)>4_000_000:raise ValueError('TrueNAS response exceeds the supported size.')
        msg=json.loads(raw)
        if msg.get('method')=='collection_update':
            params=msg.get('params',{});self.events[str(params.get('collection','')).split(':',1)[0]]=params.get('fields')
        return msg
    def call(self,method,*params):
        if method not in READ_METHODS:raise ValueError('Only supported read-only TrueNAS methods are permitted.')
        if method=='core.subscribe' and (len(params)!=1 or str(params[0]).split(':',1)[0] not in ('reporting.realtime','app.stats')):raise ValueError('Unsupported statistics subscription.')
        self.serial+=1;identifier=self.serial
        self.ws.send(json.dumps({'jsonrpc':'2.0','id':identifier,'method':method,'params':list(params)}))
        for _ in range(100):
            if time.monotonic()>self.deadline:raise TimeoutError('TrueNAS request timed out.')
            msg=self.receive()
            if msg.get('id')==identifier:
                if 'error' in msg:raise RPCError(method)
                return msg.get('result')
        raise ValueError('TrueNAS response could not be matched.')
    def statistics(self):
        for name in ('reporting.realtime','app.stats'):
            try:self.call('core.subscribe',name+':'+json.dumps({'interval':2}))
            except RPCError:pass
        until=min(self.deadline,time.monotonic()+4)
        while time.monotonic()<until and not all(k in self.events for k in ('reporting.realtime','app.stats')):
            try:self.receive()
            except TimeoutError:break
            except Exception:break
        return self.events
    def close(self):self.ws.close()


def fields(item,names):return {k:item[k] for k in names if k in item}
def value(prop):
    if isinstance(prop,dict):prop=prop.get('parsed',prop.get('rawvalue',prop.get('value')))
    try:return float(prop)
    except (TypeError,ValueError):return None


def normalize(raw,events):
    from .hostview import percent
    result={'coverage':{'pool_limit':100,'dataset_limit':300,'application_limit':100,'pool_limit_reached':len(raw.get('pools',[]))>=100,'dataset_limit_reached':len(raw.get('datasets',[]))>=300,'application_limit_reached':len(raw.get('apps',[]))>=100},'version':raw.get('system',{}).get('version'),'system':fields(raw.get('system',{}),('hostname','version','system_product','physical_cores','cores','uptime_seconds','physmem')),'metrics':{},'warnings':raw.get('warnings',[])}
    realtime=events.get('reporting.realtime') or {};memory=realtime.get('memory',{});cpu=realtime.get('cpu',{}).get('cpu',{})
    metrics=result['metrics'];metrics.update({k:v for k,v in {'cpu_percent':cpu.get('usage'),'cpu_cores':result['system'].get('cores'),'memory_total_bytes':memory.get('physical_memory_total',result['system'].get('physmem')),'memory_available_bytes':memory.get('physical_memory_available'),'uptime_seconds':result['system'].get('uptime_seconds')}.items() if type(v) in (int,float)})
    if type(cpu.get('temp')) in (int,float):metrics['cpu_temperature']=cpu['temp']
    for key in ('busy','read_bytes','write_bytes','read_ops','write_ops'):
        v=realtime.get('disks',{}).get(key)
        if type(v) in (int,float):metrics['disk_'+key]=v
    for source,target in [('arc_size','arc_gib'),('arc_available_memory','arc_available_gib')]:
        if type(memory.get(source)) in (int,float):metrics[target]=memory[source]/1024**3
    interfaces=realtime.get('interfaces',{})
    for key,out in [('received_bytes_rate','receive_kib_s'),('sent_bytes_rate','transmit_kib_s')]:
        values=[v[key] for v in interfaces.values() if type(v.get(key)) in (int,float)]
        if values:metrics[out]=sum(values)/1024
    result['interfaces']=realtime.get('interfaces',{});result['disk_performance']=realtime.get('disks',{});result['zfs']=realtime.get('zfs',{})
    if 'pools' in raw:
        pools=[]
        for p in raw['pools'][:100]:
            pool=fields(p,('id','name','status','healthy','warning','status_detail','scan','expand'));types=[]
            for v in (p.get('topology') or {}).get('data',[]):
                kind=v.get('type','Unknown');parity=v.get('parity');types.append(('RAIDZ'+str(parity)) if kind=='RAIDZ' and parity is not None else kind.upper())
            pool['raid']=' + '.join(types) or 'Not reported';pool['topology']=p.get('topology',{})
            root=next((d for d in raw.get('datasets',[]) if d.get('id')==p.get('name')),{});used=value(root.get('used'));available=value(root.get('available'))
            pool.update(used_bytes=used,available_bytes=available,used_percent=percent(used,used+available) if used is not None and available is not None else None);pools.append(pool)
        result['pools']=pools
        used=sum(p['used_bytes'] or 0 for p in pools);available=sum(p['available_bytes'] or 0 for p in pools)
        if pools and all(p['used_bytes'] is not None and p['available_bytes'] is not None for p in pools) and used+available:metrics.update(disk_total_bytes=used+available,disk_free_bytes=available)
    if 'datasets' in raw:result['datasets']=[{'name':d.get('id'),'used_bytes':value(d.get('used')),'available_bytes':value(d.get('available')),'mountpoint':(d.get('mountpoint') or {}).get('value') if isinstance(d.get('mountpoint'),dict) else d.get('mountpoint')} for d in raw['datasets'][:300]]
    stats={x['app_name']:x for x in (events.get('app.stats') or []) if isinstance(x,dict) and 'app_name' in x}
    if 'apps' in raw:
        apps=[]
        for a in raw['apps'][:100]:
            workloads=a.get('active_workloads') or {};stat=stats.get(a['name'],{});net=stat.get('networks',[]);io=stat.get('blkio',{})
            app={'name':a['name'],'state':a.get('state','UNKNOWN'),'version':a.get('human_version',a.get('version')),'upgrade_available':a.get('upgrade_available',False),'containers':[fields(x,('id','service_name','image','state','port_config','volume_mounts')) for x in workloads.get('container_details',[])[:50]],'volumes':[fields(v,('source','destination','type')) if isinstance(v,dict) else str(v)[:300] for v in workloads.get('volumes',[])[:50]],'ports':workloads.get('used_ports',[])[:50],'metrics':{k:v for k,v in {'cpu_percent':stat.get('cpu_usage'),'memory_gib':stat.get('memory',0)/1024**3 if 'memory' in stat else None,'receive_kib_s':sum(x.get('rx_bytes',0) for x in net)/1024 if stat else None,'transmit_kib_s':sum(x.get('tx_bytes',0) for x in net)/1024 if stat else None,'read_mib':io.get('read',0)/1024**2 if stat else None,'write_mib':io.get('write',0)/1024**2 if stat else None}.items() if v is not None}}
            apps.append(app)
        result['apps']=apps
    if 'alerts' in raw:result['alerts']=[{'level':a.get('level'),'message':redact(str(a.get('formatted',a.get('text','Alert'))))[:500]} for a in raw['alerts'][:100]]
    if 'services' in raw:result['services']=[fields(s,('service','state','enable')) for s in raw['services'][:100]]
    return result


def collect(cfg,secret):
    client=Client(cfg)
    try:
        login=client.call('auth.login_ex',{'mechanism':'API_KEY_PLAIN','username':cfg['username'],'api_key':secret})
        if not isinstance(login,dict) or login.get('response_type')!='SUCCESS':raise ValueError('TrueNAS rejected this user/API key. Check the key owner and read permissions.')
        system=client.call('system.info')
        if not isinstance(system,dict) or not system.get('version'):raise ValueError('The server did not return valid TrueNAS system information.')
        raw={'system':system,'warnings':[]}
        for key,method in [('pools','pool.query'),('datasets','pool.dataset.query'),('apps','app.query'),('alerts','alert.list'),('services','service.query')]:
            try:
                args=([],{'limit':300}) if method.endswith('.query') else ()
                data=client.call(method,*args)
                if not isinstance(data,list):raise ValueError('Unexpected TrueNAS data shape.')
                raw[key]=data
            except RPCError:raw['warnings'].append('Could not read '+key+'. Check API permissions and version support.')
        events=client.statistics()
        if not events:raw['warnings'].append('Live performance statistics are not available.')
        return normalize(raw,events)
    finally:client.close()
