import json
import time
from unittest.mock import Mock,patch
import pytest
from aiticket import power
from aiticket.proxmox import Client,discover,link
from aiticket.hostview import overview,detail
from aiticket.security import digest
from test_proxmox import setup,inventory
from test_actions import environment_setup


@pytest.fixture(autouse=True)
def power_permission(monkeypatch):
    monkeypatch.setattr(Client,'power_allowed',lambda self,obj:True)


def guest(store,vault,status='running'):
    setup(store,vault)
    resources=inventory()
    for r in resources:
        if r['type']=='qemu': r.update(status=status,cpu=.4,maxcpu=4,mem=1024,maxmem=2048,maxdisk=4096,disk=1024,uptime=500)
    with patch.object(Client,'get',return_value=resources): discover(store,vault,'p1')
    obj=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu'")[0]
    link(store,obj['id'],None,'running','Web VM')
    mid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(obj['id'],))[0]['machine_id']
    power.configure(store,vault,mid,'proxmox','p1','power@pve!guest','power-only-secret',True,True,True)
    return mid,resources


def approve(store,job):
    row=store.rows('SELECT * FROM power_jobs WHERE id=?',(job,))[0]
    power.decide(store,job,row['payload_hash'],'approve')


def test_inventory_workspaces_without_agents_and_linked_resource_redirect(signed_in):
    client,store,vault,_=signed_in
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()): discover(store,vault,'p1')
    objects=store.rows("SELECT * FROM proxmox_objects WHERE kind IN ('node','qemu','lxc')")
    assert objects
    for obj in objects:
        response=client.get('/proxmox/resources/'+obj['id'])
        assert response.status_code==200
        assert obj['name'].encode() in response.data
        assert b'Performance history' in response.data
        assert b'Inventory resource' in response.data
    obj=next(o for o in objects if o['kind']=='qemu')
    link(store,obj['id'],None,'running','Guest without agent')
    mid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(obj['id'],))[0]['machine_id']
    response=client.get('/proxmox/resources/'+obj['id'])
    assert response.status_code==302 and response.headers['Location']=='/hosts/'+mid
    response=client.get(response.headers['Location'])
    assert response.status_code==200 and b'Guest without agent' in response.data
    assert client.get('/proxmox/resources/missing').status_code==404


def test_dashboard_metrics_guest_tree_stale_and_history(signed_in):
    client,store,vault,_=signed_in
    mid,resources=guest(store,vault)
    node=store.rows("SELECT * FROM proxmox_objects WHERE object_key='node/a'")[0]
    link(store,node['id'],None,'online','Proxmox A')
    nodeid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(node['id'],))[0]['machine_id']
    data=detail(store,mid)
    assert data['host']['sample']['cpu']==40 and data['host']['sample']['ram']==50
    assert data['host']['sample']['disk']==25
    assert b'Web VM' in client.get('/hosts').data
    response=client.get('/hosts/'+nodeid)
    assert response.status_code==200 and b'Guests on this Proxmox node' in response.data and b'qemu/209' in response.data
    assert len(detail(store,nodeid)['guests'])==2
    with store.connect() as c: c.execute('UPDATE proxmox_objects SET last_seen=1')
    assert not next(m for m in overview(store) if m['id']==mid)['sample']['fresh']
    assert b'Stale or unavailable' in client.get('/hosts/'+mid).data
    assert client.get('/hosts/missing').status_code==404


def test_power_existing_credentials_protected_hash_and_state(environment):
    _,store,vault=environment
    mid,_=guest(store,vault)
    power.configure(store,vault,mid,'proxmox','p1',enabled=True,validated=True,confirm=True)
    policy=store.rows('SELECT * FROM power_policies WHERE machine_id=?',(mid,))[0]
    assert policy['token_id'] is None and policy['token_secret'] is None
    job=power.propose(store,mid,'shutdown','Planned maintenance')
    with pytest.raises(ValueError,match='hash'): power.decide(store,job,'wrong','approve')
    with pytest.raises(ValueError,match='already exists'): power.propose(store,mid,'restart','Duplicate')
    approve(store,job)
    with store.connect() as c: c.execute("UPDATE proxmox_objects SET node='b' WHERE machine_id=?",(mid,))
    with patch('aiticket.power.requests.post') as post:
        power.tick(store,vault)
        post.assert_not_called()
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='cancelled'


def test_proxmox_once_dispatch_task_and_fresh_state_verification(environment):
    _,store,vault=environment
    mid,resources=guest(store,vault)
    job=power.propose(store,mid,'shutdown','Planned maintenance');approve(store,job)
    response=Mock(status_code=200);response.raw.read.return_value=json.dumps({'data':'UPID:a:task'}).encode()
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',return_value=response) as post:
        assert power.tick(store,vault)
        assert post.call_count==1
        args=post.call_args
        assert '/nodes/a/qemu/209/status/shutdown' in args.args[0]
        assert args.kwargs['headers']['Authorization'].endswith('fixture-secret')
        assert args.kwargs['data']['forceStop']==0 and args.kwargs['allow_redirects'] is False
    stopped=[{**r,'status':'stopped'} if r['type']=='qemu' else r for r in resources]
    with patch.object(Client,'get',side_effect=[{'status':'stopped','exitstatus':'OK'},stopped]),patch('aiticket.power.requests.post') as post:
        power.tick(store,vault)
        post.assert_not_called()
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='verified'
    with pytest.raises(Exception,match='immutable'):
        with store.connect() as c: c.execute("UPDATE power_jobs SET payload='{}'")


def test_ambiguous_power_write_never_replayed(environment):
    _,store,vault=environment
    mid,resources=guest(store,vault)
    job=power.propose(store,mid,'restart','Planned maintenance');approve(store,job)
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',side_effect=TimeoutError) as post:
        power.tick(store,vault);power.tick(store,vault)
        assert post.call_count==1
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='unknown'
    with pytest.raises(ValueError): power.propose(store,mid,'restart','Repeat')


def test_agent_once_authorization_and_new_uptime_verification(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    with store.connect() as c:
        caps=json.loads(c.execute("SELECT capabilities FROM agents WHERE id='agent'").fetchone()[0]);caps['power_operations']=['host_restart','host_shutdown']
        c.execute("UPDATE agents SET capabilities=?,telemetry=?,sampled_at=? WHERE id='agent'",(json.dumps(caps),json.dumps({'uptime_seconds':1000,'cpu_percent':25,'memory_total_bytes':4096,'memory_available_bytes':2048}),now))
    power.configure(store,vault,'m','agent',enabled=True,validated=True,confirm=True)
    with pytest.raises(ValueError,match='Start'): power.propose(store,'m','start','No VM')
    job=power.propose(store,'m','restart','Planned reboot');approve(store,job)
    with store.connect() as c:
        delivery=power.poll(c,store,'agent',now)[0]
    with store.connect() as c: assert power.poll(c,store,'agent',now+1)==[]
    result=power.authorize(store,'agent',delivery,now+1)
    assert result['operation']=='host_restart'
    with pytest.raises(ValueError): power.authorize(store,'agent',delivery,now+2)
    with store.connect() as c: c.execute("UPDATE agents SET telemetry=?,sampled_at=?,last_seen=? WHERE id='agent'",(json.dumps({'uptime_seconds':5}),now+5,now+5))
    power.tick(store,vault,now+5)
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='verified'


def test_power_ui_csrf_and_explicit_confirmation(signed_in):
    client,store,vault,csrf=signed_in
    mid,_=guest(store,vault,status='stopped')
    assert client.post('/hosts/'+mid+'/power',data={'operation':'start','reason':'Test'}).status_code==403
    assert client.post('/hosts/'+mid+'/power',data={'csrf':csrf,'operation':'start','reason':'Test'}).status_code==302
    row=store.rows('SELECT * FROM power_jobs')[0]
    assert client.post('/power/'+row['id']+'/decide',data={'csrf':csrf,'decision':'approve','payload_hash':row['payload_hash']}).status_code==400
    assert b'Approve once' in client.get('/hosts/'+mid).data


def test_power_expiry_stale_samples_and_unlink_fencing(environment):
    from aiticket.proxmox import unlink
    _,store,vault=environment
    mid,resources=guest(store,vault)
    job=power.propose(store,mid,'restart','Maintenance');approve(store,job)
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',side_effect=TimeoutError):
        power.tick(store,vault)
    obj=store.rows('SELECT id FROM proxmox_objects WHERE machine_id=?',(mid,))[0]['id']
    with pytest.raises(ValueError,match='Reconcile'): unlink(store,obj)
    row=store.rows('SELECT * FROM power_jobs WHERE id=?',(job,))[0]
    power.decide(store,job,row['payload_hash'],'reconcile')
    unlink(store,obj)
    incident,now=environment_setup(store,vault)
    with store.connect() as c:
        cap=json.loads(c.execute("SELECT capabilities FROM agents WHERE id='agent'").fetchone()[0]);cap['power_operations']=['host_restart']
        c.execute("UPDATE agents SET capabilities=?,telemetry=?,sampled_at=? WHERE id='agent'",(json.dumps(cap),json.dumps({'uptime_seconds':1000}),now-181))
    power.configure(store,vault,'m','agent',enabled=True,validated=True,confirm=True)
    with pytest.raises(ValueError,match='uptime'): power.propose(store,'m','restart','Stale sample')
    with store.connect() as c: c.execute("UPDATE agents SET sampled_at=? WHERE id='agent'",(now,))
    proposal=power.propose(store,'m','restart','Expiry')
    row=store.rows('SELECT * FROM power_jobs WHERE id=?',(proposal,))[0]
    with pytest.raises(ValueError): power.decide(store,proposal,row['payload_hash'],'approve',now+301)


def test_agent_power_api_requires_separate_action_credential(environment):
    app,store,vault=environment
    _,now=environment_setup(store,vault)
    with store.connect() as c:
        c.execute("UPDATE agents SET capabilities=?,telemetry=?,sampled_at=? WHERE id='agent'",(json.dumps({'power_operations':['host_restart']}),json.dumps({'uptime_seconds':1000}),now))
    power.configure(store,vault,'m','agent',enabled=True,validated=True,confirm=True)
    job=power.propose(store,'m','restart','Maintenance');approve(store,job)
    with store.connect() as c: delivery=power.poll(c,store,'agent',now)[0]
    client=app.test_client()
    assert client.post('/api/agent/action-authorize',json=delivery,headers={'Authorization':'Bearer monitoring-token'}).status_code==401
    headers={'Authorization':'Bearer action-fixture-credential'}
    assert client.post('/api/agent/action-authorize',json=delivery,headers=headers).json['operation']=='host_restart'
    assert client.post('/api/agent/action-authorize',json=delivery,headers=headers).status_code==400
    result={**delivery,'status':'completed','output':'Accepted'}
    assert client.post('/api/agent/action-result',json=result,headers=headers).json['status']=='accepted'
    assert client.post('/api/agent/action-result',json=result,headers=headers).json['status']=='duplicate'


def test_proxmox_reboot_uses_supported_parameters(environment):
    _,store,vault=environment
    mid,resources=guest(store,vault)
    job=power.propose(store,mid,'restart','Maintenance');approve(store,job)
    response=Mock(status_code=200);response.raw.read.return_value=b'{"data":"UPID:a:task"}'
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',return_value=response) as post:
        power.tick(store,vault)
        assert post.call_args.args[0].endswith('/status/reboot')
        assert post.call_args.kwargs['data']=={'timeout':60}


def test_host_ticket_links_and_protected_node_controls(signed_in):
    client,store,vault,_=signed_in
    incident,_=environment_setup(store,vault)
    page=client.get('/hosts/m')
    assert page.status_code==200 and ('/incidents/'+incident).encode() in page.data
    mid,_=guest(store,vault)
    node=store.rows("SELECT * FROM proxmox_objects WHERE kind='node'")[0]
    link(store,node['id'],None,'online','Protected node')
    nodeid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(node['id'],))[0]['machine_id']
    with pytest.raises(ValueError,match='protected'):
        power.configure(store,vault,nodeid,'proxmox','p1','power@pve!node','secret',True,True,True)


def test_existing_connection_token_rotation_applies_to_legacy_power_policy(environment):
    _,store,vault=environment
    mid,resources=guest(store,vault)
    with store.connect() as c:
        c.execute('UPDATE power_policies SET token_id=?,token_secret=? WHERE machine_id=?',('legacy@pve!power',vault.encrypt('legacy-unused'),mid))
        c.execute('UPDATE proxmox_connections SET token_id=?,token_secret=? WHERE id=?',('current@pve!power',vault.encrypt('rotated-current'),'p1'))
    job=power.propose(store,mid,'restart','Token reuse test');approve(store,job)
    response=Mock(status_code=403)
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',return_value=response) as post:
        power.tick(store,vault)
        assert post.call_args.kwargs['headers']['Authorization']=='PVEAPIToken=current@pve!power=rotated-current'
        assert '/status/reboot' in post.call_args.args[0]
    assert store.rows('SELECT state FROM power_jobs WHERE id=?',(job,))[0]['state']=='failed'
