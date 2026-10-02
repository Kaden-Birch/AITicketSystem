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
    with store.connect() as c: assert 'private-key' not in json.dumps(unifi.ai_context(c,'host'))


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
        context=unifi.ai_context(c,'host')
        assert len(json.dumps(context))<5000
        assert 'Omitted' in context[0]['snapshot']['errors']['clients']
