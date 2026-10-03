import json
import time
import pytest
from aiticket import unifi


def host(store):
    with store.connect() as c: c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',('host','NAS',time.time()))


def configured(store,vault,kind='drive'):
    host(store)
    identifier=unifi.save(store,vault,{'name':'NAS','machine_id':'host','url':'https://10.0.0.1','secret':'private-key','kind':kind})
    return store.rows('SELECT * FROM unifi_connections WHERE id=?',(identifier,))[0]


def test_read_boundary_and_redaction(environment,monkeypatch):
    _,store,vault=environment
    row=configured(store,vault)
    calls=[]
    class Response:
        status_code=200
        headers={'Content-Type':'application/json'}
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def iter_content(self,n): yield json.dumps({'pools':[{'status':'fullyOperational','capacity':100,'usage':30,'password':'oops'}],'apiKey':'private-key'}).encode()
    def get(url,**kwargs): calls.append((url,kwargs)); return Response()
    monkeypatch.setattr(unifi.requests,'get',get)
    client=unifi.Client(row,vault)
    for path in ('/api/auth/login',unifi.NETWORK+'/sites/x/devices/x/actions','/proxy/drive/api/v2/drives','//other.example'):
        with pytest.raises(ValueError): client.get(path)
    result=unifi.refresh(store,vault,row['id'])
    assert len(calls)==3 and all(c[1]['allow_redirects'] is False for c in calls)
    assert all(c[1]['headers']['X-API-KEY']=='private-key' for c in calls)
    assert 'private-key' not in json.dumps(result) and 'password' not in json.dumps(result)
    with store.connect() as c: assert 'private-key' not in json.dumps(unifi.ai_context(c,row['machine_id']))


def test_partial_drive_and_storage_alert(environment,monkeypatch):
    _,store,vault=environment; row=configured(store,vault)
    def get(self,path,params=None):
        if path.endswith('storage'): return {'pools':[{'status':'degraded','capacity':100,'usage':95}]}
        raise ValueError('HTTP 404')
    monkeypatch.setattr(unifi.Client,'get',get)
    healthy,evidence=unifi.probe(store,vault,{'connection_id':row['id']})
    assert not healthy and len(evidence['alerts'])==2
    assert evidence['endpoint_errors']['device']=='HTTP 404'
    assert json.loads(store.rows('SELECT snapshot FROM unifi_connections')[0]['snapshot'])['readings']['storage']


def test_network_pagination_and_shared_ai(environment,monkeypatch):
    _,store,vault=environment; row=configured(store,vault,'network')
    with store.connect() as c: c.execute("UPDATE unifi_connections SET site='site1',ai_context=1")
    calls=[]
    def get(self,path,params=None):
        calls.append(path)
        if path.endswith('/sites'): return {'data':[{'id':'site1','name':'Home'}]}
        if path.endswith('/devices'): return {'data':[{'id':'device1','state':'ONLINE'}]}
        if path.endswith('/clients'): return {'data':[{'ipAddress':'10.0.0.2','networkId':'vlan20'}]}
        if path.endswith('/networks'): return {'data':[{'id':'vlan20','vlanId':20}]}
        return {'uptimeSec':120}
    monkeypatch.setattr(unifi.Client,'get',get)
    unifi.refresh(store,vault,row['id'])
    assert len(calls)==6
    with store.connect() as c:
        context=unifi.ai_context(c,'different-host')
        assert context[0]['snapshot']['readings']['networks']['items'][0]['vlanId']==20
        c.execute('UPDATE unifi_connections SET ai_context=0')
        assert unifi.ai_context(c,'different-host')==[]


def test_ui_secret_preservation_and_csrf(signed_in,monkeypatch):
    client,store,vault,csrf=signed_in; host(store)
    form={'csrf':csrf,'name':'NAS','machine_id':'host','url':'https://10.0.0.1','secret':'private-key','kind':'drive','interval':'30'}
    assert client.post('/unifi',data={**form,'csrf':'wrong'}).status_code==403
    assert client.post('/unifi',data=form).status_code==302
    row=store.rows('SELECT * FROM unifi_connections')[0]
    assert vault.decrypt(row['secret'])=='private-key'
    assert b'private-key' not in client.get('/unifi').data
    assert client.post('/unifi',data={**form,'id':row['id'],'secret':''}).status_code==302
    assert vault.decrypt(store.rows('SELECT * FROM unifi_connections')[0]['secret'])=='private-key'
    assert client.get('/checks/'+row['check_id']+'/edit').status_code==302
    assert store.rows('SELECT kind,interval FROM checks')[0]=={'kind':'unifi','interval':30}


def test_redirect_html_oversize_and_pagination_bound(environment,monkeypatch):
    _,store,vault=environment; row=configured(store,vault)
    class Response:
        status_code=302; headers={'Content-Type':'text/html'}
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def iter_content(self,n): yield b'x'*2_000_001
    response=Response()
    monkeypatch.setattr(unifi.requests,'get',lambda *a,**k:response)
    client=unifi.Client(row,vault)
    with pytest.raises(ValueError,match='HTTP 302'): client.get(unifi.DRIVE['storage'])
    response.status_code=200
    with pytest.raises(ValueError,match='Non-JSON'): client.get(unifi.DRIVE['storage'])
    response.headers={'Content-Type':'application/json'}
    with pytest.raises(ValueError,match='limit'): client.get(unifi.DRIVE['storage'])
    monkeypatch.setattr(client,'get',lambda *a,**k:{'data':[{'id':'x'}]*100})
    assert unifi.listing(client,unifi.NETWORK+'/sites')['truncated'] is True


def test_inventory_rotation_and_monitor_toggle(signed_in,tmp_path,monkeypatch):
    from aiticket.administration import rotate_key
    from aiticket.inventory import export_inventory
    client,store,vault,csrf=signed_in
    row=configured(store,vault)
    assert export_inventory(store)['tables']['checks']==[]
    for value in ('no','yes'):
        assert client.post('/checks/'+row['check_id']+'/enabled',data={'csrf':csrf,'enabled':value}).status_code==302
    new=rotate_key(store,vault,tmp_path/'rotated.key')
    assert new.decrypt(store.rows('SELECT secret FROM unifi_connections')[0]['secret'])=='private-key'


def test_collected_ui_and_ai_size_budget(signed_in,monkeypatch):
    client,store,vault,csrf=signed_in
    row=configured(store,vault)
    monkeypatch.setattr(unifi.Client,'get',lambda self,path,params=None:{'pools':[{'number':1,'status':'fullyOperational','usage':30,'capacity':100}],'disks':[{'slotId':'1','state':'optimal','temperature':40}]})
    assert client.post('/unifi',data={'csrf':csrf,'id':row['id'],'operation':'refresh'}).status_code==302
    assert b'Storage pools' in client.get('/unifi').data
    snapshot={'sampled_at':time.time(),'readings':{'clients':{'items':[{'id':'x'*200}]*100}},'errors':{}}
    with store.connect() as c:
        c.execute('UPDATE unifi_connections SET snapshot=?',(json.dumps(snapshot),))
        context=unifi.ai_context(c,row['machine_id'])
        assert len(json.dumps(context))<5000
        assert 'Omitted' in context[0]['snapshot']['errors']['clients']


def test_standalone_setup_without_any_hosts(signed_in):
    client,store,vault,csrf=signed_in
    assert store.rows('SELECT id FROM machines')==[]
    response=client.post('/unifi',data={'csrf':csrf,'name':'Home Network','kind':'network','url':'https://10.0.0.1','secret':'private-key'})
    assert response.status_code==302
    row=store.rows('SELECT * FROM unifi_connections')[0]
    machine=store.rows('SELECT * FROM machines')[0]
    assert machine['id']==row['machine_id']=='unifi:'+row['id']
    assert machine['name']=='UniFi Home Network'
    page=client.get('/unifi').data
    assert b'Associated host' not in page and b'name="machine_id"' not in page
    response=client.post('/unifi',data={'csrf':csrf,'id':row['id'],'name':'Renamed','kind':'network','url':'https://10.0.0.1','secret':'','machine_id':'unrelated-host'})
    assert response.status_code==302
    assert store.rows('SELECT machine_id FROM unifi_connections')[0]['machine_id']==machine['id']
    assert store.rows('SELECT name FROM machines')[0]['name']=='UniFi Renamed'


def test_migration_detaches_existing_connection_preserving_history(environment):
    from aiticket.db import Store
    from aiticket.engine import observe
    _,store,vault=environment
    row=configured(store,vault)
    observe(store,row['check_id'],False,{'reason':'test'},now=1)
    observe(store,row['check_id'],False,{'reason':'test'},now=2)
    observe(store,row['check_id'],False,{'reason':'test'},now=3)
    incident=store.rows('SELECT * FROM incidents')[0]
    secret=row['secret']
    # Reconstruct the immediately preceding schema's required host association.
    with store.connect() as c:
        c.execute('UPDATE unifi_connections SET machine_id=?',('host',))
        c.execute('UPDATE checks SET machine_id=? WHERE id=?',('host',row['check_id']))
        c.execute('UPDATE incidents SET machine_id=?',('host',))
        c.execute('DELETE FROM machines WHERE id=?',(row['machine_id'],))
        c.execute('DROP TABLE unifi_devices')
        c.execute('ALTER TABLE unifi_connections DROP COLUMN deleted')
        c.execute('DROP TABLE health_rules')
        c.execute('DROP TABLE fleet_targets')
        c.execute('DROP TABLE fleet_jobs')
        c.execute('DROP TABLE fleet_keys')
        c.execute('ALTER TABLE machines DROP COLUMN offline_expected')
        c.execute('UPDATE schema_version SET version=26')
    migrated=Store(store.path)
    connection=migrated.rows('SELECT * FROM unifi_connections')[0]
    assert connection['secret']==secret and connection['check_id']==row['check_id']
    assert connection['machine_id']==row['machine_id']
    assert migrated.rows('SELECT id,machine_id FROM incidents')[0]=={'id':incident['id'],'machine_id':row['machine_id']}
    assert len(migrated.rows('SELECT * FROM observations'))==3
    assert migrated.rows('SELECT name FROM machines WHERE id=?',('host',))[0]['name']=='NAS'


def test_device_inventory_metrics_and_deduplicated_tickets(signed_in,monkeypatch):
    from aiticket.engine import observe
    from aiticket.hostview import overview
    client,store,vault,csrf=signed_in
    row=configured(store,vault,'network')
    with store.connect() as c:c.execute("UPDATE unifi_connections SET site='site1'")
    def get(self,path,params=None):
        if path.endswith('/devices'):return {'data':[{'id':'switch1','name':'Switch','model':'USW','state':'OFFLINE','ipAddress':'10.0.0.5'}]}
        if path.endswith('/devices/switch1'):return {'id':'switch1','name':'Switch','state':'OFFLINE','interfaces':{'ports':[{'idx':3,'speedMbps':1000,'state':'UP','nativeNetworkId':'net1'}]}}
        if path.endswith('/statistics/latest'):return {'cpuUtilizationPct':25,'memoryUtilizationPct':50,'uptimeSec':120}
        return {'data':[]}
    monkeypatch.setattr(unifi.Client,'get',get)
    for i in range(3):
        unifi.refresh(store,vault,row['id'])
        device=store.rows('SELECT * FROM unifi_devices')[0]
        healthy,evidence=unifi.device_probe(store,{'connection_id':row['id'],'device_id':'switch1'})
        assert healthy is False
        observe(store,device['check_id'],healthy,evidence)
        observe(store,device['check_id'],healthy,evidence)
        assert store.rows('SELECT failures FROM checks WHERE id=?',(device['check_id'],))[0]['failures']==i+1
    assert len(store.rows('SELECT * FROM incidents WHERE machine_id=?',(device['machine_id'],)))==1
    assert not any(x['id']==device['machine_id'] or x['id']==row['machine_id'] for x in overview(store))
    listing=client.get('/network-devices').data
    assert b'Switch' in listing
    page=client.get('/network-devices/'+row['id']+'/devices/switch1')
    assert page.status_code==200 and b'1000' in page.data and b'net1' in page.data and b'<svg' in page.data
    assert client.get('/hosts/'+device['machine_id']).status_code==302
    assert b'Switch' not in client.get('/hosts').data
    with store.connect() as c:
        context=unifi.ai_context(c,device['machine_id'])
        assert context[0]['snapshot']['readings']['device']['id']=='switch1'
        assert context[0]['snapshot']['sampled_at']==device['last_seen']


def test_nas_readable_metrics_and_history(signed_in,monkeypatch):
    client,store,vault,csrf=signed_in
    row=configured(store,vault)
    def get(self,path,params=None):
        if path.endswith('/storage'):return {'pools':[{'number':1,'status':'fullyOperational','capacity':1000000000000,'usage':500000000000,'raidGroups':[{'currentLevel':'raid5'}]}],'disks':[{'slotId':'1','model':'disk','state':'optimal','temperature':47,'powerOnHours':123,'healthScore':5,'badSectorCount':0,'uncorrectableSectorCount':0}]}
        if path.endswith('/device-info'):return {'name':'UNAS','model':'UNASPRO','cpu':{'currentload':.078,'temperature':78},'memory':{'total':100,'available':40},'networkInterfaces':[{'interfaceName':'eth1','connected':True,'linkSpeed':'10 GbE'}]}
        return {'receiveKBPS':27,'transmitKBPS':8}
    monkeypatch.setattr(unifi.Client,'get',get)
    unifi.refresh(store,vault,row['id'])
    page=client.get('/network-devices/'+row['id'])
    assert page.status_code==200
    for text in (b'Storage pools',b'raid5',b'47',b'CPU usage',b'Memory usage',b'Pool 1 usage',b'10 GbE',b'<svg'):assert text in page.data
    hist=unifi.history(store,row['machine_id'],'1h')
    assert hist['count']==1
    assert any(c['latest']==7.8 for c in hist['charts'])
    assert unifi.clean({'interfaces':{'ports':[{'idx':3,'speedMbps':1000,'nativeNetworkId':'net1','password':'secret'}]}})['interfaces']['ports'][0]=={'idx':3,'speedMbps':1000,'nativeNetworkId':'net1'}


def test_extra_numeric_telemetry_retained_without_credentials():
    assert unifi.clean({'newStatistics':{'packetLossPct':2.5,'numericSecret':123,'description':'unknown text'},'apiKey':'private'})=={'newStatistics':{'packetLossPct':2.5}}


def test_delete_connection_csrf_and_history(signed_in,monkeypatch):
    from aiticket.engine import observe
    client,store,vault,csrf=signed_in
    row=configured(store,vault)
    for i in range(3):observe(store,row['check_id'],False,{'reason':'test'},now=i+1)
    incident=store.rows('SELECT * FROM incidents')[0]
    assert b'Delete connection' in client.get('/unifi?connection='+row['id']).data
    path='/network-devices/'+row['id']+'/delete'
    assert client.post(path,data={'csrf':'wrong'}).status_code==403
    assert client.post(path,data={'csrf':csrf}).status_code==302
    deleted=store.rows('SELECT * FROM unifi_connections')[0]
    assert deleted['deleted'] and deleted['secret']=='' and deleted['snapshot'] is None
    assert store.rows('SELECT enabled FROM checks')[0]['enabled']==0
    assert store.rows('SELECT id,status FROM incidents')[0]=={'id':incident['id'],'status':'Open'}
    assert store.rows('SELECT handling_mode FROM incident_control')[0]['handling_mode']=='paused'
    assert client.get('/network-devices/'+row['id']).status_code==404
    assert client.get('/unifi?connection='+row['id']).status_code==404
    assert b'Delete connection' not in client.get('/unifi').data
    with pytest.raises(ValueError):unifi.refresh(store,vault,row['id'])


def test_delete_discovered_device_suppresses_rediscovery(signed_in,monkeypatch):
    client,store,vault,csrf=signed_in;row=configured(store,vault,'network')
    with store.connect() as c:c.execute("UPDATE unifi_connections SET site='site1'")
    def get(self,path,params=None):
        if path.endswith('/devices'):return {'data':[{'id':'switch1','name':'Switch','state':'ONLINE'}]}
        if '/devices/switch1' in path:return {'id':'switch1','name':'Switch','state':'ONLINE'}
        return {'data':[]}
    monkeypatch.setattr(unifi.Client,'get',get)
    unifi.refresh(store,vault,row['id'])
    device=store.rows('SELECT * FROM unifi_devices')[0]
    root='/network-devices/'+row['id']+'/devices/switch1'
    assert b'Delete device' in client.get(root+'/settings').data
    assert client.post(root+'/delete',data={'csrf':csrf}).status_code==302
    unifi.refresh(store,vault,row['id'])
    assert len(store.rows('SELECT * FROM unifi_devices'))==1
    assert store.rows('SELECT deleted FROM unifi_devices')[0]['deleted']
    assert store.rows('SELECT enabled FROM checks WHERE id=?',(device['check_id'],))[0]['enabled']==0
    assert client.get(root).status_code==404
    assert b'Switch' not in client.get('/network-devices').data
    assert client.get('/network-devices/'+row['id']).status_code==200
    with store.connect() as c:assert unifi.ai_context(c,device['machine_id'])==[]


def test_delete_connection_cascades_child_monitoring(environment,monkeypatch):
    _,store,vault=environment;row=configured(store,vault,'network')
    snapshot={'sampled_at':time.time(),'readings':{'devices':{'items':[{'id':'switch1','name':'Switch','state':'ONLINE'}]}},'errors':{}}
    with store.connect() as c:unifi.retain(c,row,snapshot)
    unifi.remove(store,row['id'])
    assert all(r['enabled']==0 for r in store.rows('SELECT enabled FROM checks'))
    assert store.rows('SELECT deleted FROM unifi_devices')[0]['deleted']


def test_statistics_latest_and_optional_failure_do_not_mark_network_down(environment,monkeypatch):
    _,store,vault=environment;row=configured(store,vault,'network')
    with store.connect() as c:c.execute("UPDATE unifi_connections SET site='site1'")
    requested=[]
    def get(self,path,params=None):
        requested.append(path)
        if path.endswith('/devices'):return {'data':[{'id':'device1','state':'ONLINE'}]}
        if path.endswith('/statistics/latest'):raise ValueError('HTTP 404')
        if path.endswith('/devices/device1'):return {'id':'device1','state':'ONLINE'}
        return {'data':[]}
    monkeypatch.setattr(unifi.Client,'get',get)
    healthy,evidence=unifi.probe(store,vault,{'connection_id':row['id']})
    assert healthy is True
    assert evidence['endpoint_errors']=={}
    assert evidence['optional_telemetry_errors']=={'statistics:device1':'HTTP 404'}
    assert any(p.endswith('/statistics/latest') for p in requested)
    assert not any(p.endswith('/statistics') for p in requested)


def test_statistics_allowlist_uses_latest(environment,monkeypatch):
    _,store,vault=environment;row=configured(store,vault,'network')
    class Response:
        status_code=200;headers={'Content-Type':'application/json'}
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def iter_content(self,n):yield b'{"cpuUtilizationPct":25}'
    calls=[]
    monkeypatch.setattr(unifi.requests,'get',lambda url,**kw:(calls.append(url) or Response()))
    api=unifi.Client(row,vault)
    with pytest.raises(ValueError):api.get(unifi.NETWORK+'/sites/site1/devices/device1/statistics')
    assert api.get(unifi.NETWORK+'/sites/site1/devices/device1/statistics/latest')['cpuUtilizationPct']==25
    assert len(calls)==1
