import importlib.util
import json
import time
from pathlib import Path
from unittest.mock import Mock,patch
import pytest
from aiticket import power
from aiticket.proxmox import Client,discover,link
from aiticket.security import digest
from test_hosts_power import guest,approve
from test_proxmox import setup,inventory
from test_actions import environment_setup


def test_linked_guest_automatically_enables_buttons_without_policy(signed_in,monkeypatch):
    client,store,vault,csrf=signed_in
    mid,_=guest(store,vault,status='stopped')
    with store.connect() as c:
        c.execute('DELETE FROM power_policies')
        c.execute("UPDATE machines SET recovery_role='protected' WHERE id=?",(mid,))
    monkeypatch.setattr(Client,'power_allowed',lambda self,obj:True)
    page=client.get('/hosts/'+mid)
    assert page.status_code==200 and b'value="start" disabled' not in page.data
    assert b'Configure manual power' not in page.data
    assert b'Manual power buttons' not in client.get('/hosts/'+mid+'/settings').data
    assert client.post('/hosts/'+mid+'/power',data={'csrf':csrf,'operation':'start'}).status_code==302
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='awaiting'
    assert b'Confirm start for Web VM.' in client.get('/hosts/'+mid).data
    assert store.rows('SELECT * FROM power_policies')==[]


def test_permission_denial_does_not_fall_back_to_agent(environment,monkeypatch):
    _,store,vault=environment;mid,_=guest(store,vault)
    monkeypatch.setattr(Client,'power_allowed',lambda self,obj:False)
    assert not any(power.availability(store,vault,mid)[k] for k in ('start','restart','shutdown'))
    with pytest.raises(ValueError,match='permission'):power.propose(store,mid,'restart','Maintenance',vault=vault)
    assert not store.rows('SELECT * FROM power_jobs')


def test_permission_scope_matches_exact_resource(environment):
    _,_,vault=environment
    client=Client({'url':'https://example.test','token_id':'fixture','token_secret':vault.encrypt('fixture')},vault)
    for kind,key,node,path,privilege in [('qemu','qemu/208','R730','/vms/208','VM.PowerMgmt'),('node','node/R730','R730','/nodes/R730','Sys.PowerMgmt')]:
        obj={'kind':kind,'object_key':key,'node':node}
        with patch.object(client,'get',return_value={path:{privilege:1}}) as get:
            assert client.power_allowed(obj)
            assert 'path=%2F' in get.call_args.args[0]
        with patch.object(client,'get',return_value={'/':{privilege:1}}):assert not client.power_allowed(obj)


def test_readonly_endpoint_fallback_binds_single_write(environment,monkeypatch):
    _,store,vault=environment;mid,resources=guest(store,vault)
    def allowed(self,obj):
        if self.connection['id']=='p1':raise TimeoutError()
        return True
    monkeypatch.setattr(Client,'power_allowed',allowed)
    job=power.propose(store,mid,'restart','Maintenance',vault=vault);approve(store,job)
    assert json.loads(store.rows('SELECT payload FROM power_jobs')[0]['payload'])['connection_id']=='p2'
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',side_effect=TimeoutError) as post:
        power.tick(store,vault);power.tick(store,vault)
        assert post.call_count==1 and post.call_args.args[0].startswith('https://192.0.2.2:8006/')
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='unknown'


def test_revoked_permission_prevents_write(environment,monkeypatch):
    _,store,vault=environment;mid,_=guest(store,vault)
    monkeypatch.setattr(Client,'power_allowed',lambda self,obj:True)
    job=power.propose(store,mid,'restart','Maintenance',vault=vault);approve(store,job)
    monkeypatch.setattr(Client,'power_allowed',lambda self,obj:False)
    with patch('aiticket.power.requests.post') as post:power.tick(store,vault);post.assert_not_called()
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='failed'


def test_node_acceptance_and_independent_shutdown_verification(environment,monkeypatch):
    _,store,vault=environment;setup(store,vault);resources=inventory()
    resources[0]['uptime']=1000
    with patch.object(Client,'get',return_value=resources):discover(store,vault,'p1')
    obj=store.rows("SELECT * FROM proxmox_objects WHERE object_key='node/a'")[0]
    link(store,obj['id'],None,'online','Node A')
    mid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(obj['id'],))[0]['machine_id']
    monkeypatch.setattr(Client,'power_allowed',lambda self,obj:True)
    availability=power.availability(store,vault,mid)
    assert availability['restart'] and availability['shutdown'] and not availability['start']
    job=power.propose(store,mid,'shutdown','Maintenance',vault=vault);approve(store,job)
    response=Mock(status_code=200);response.raw.read.return_value=b'{"data":null}'
    with patch.object(Client,'get',return_value=resources),patch('aiticket.power.requests.post',return_value=response) as post:
        power.tick(store,vault)
        assert post.call_args.args[0].endswith('/nodes/a/status') and post.call_args.kwargs['data']=={'command':'shutdown'}
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='verifying'
    resources[0]['status']='offline'
    with patch.object(Client,'get',return_value=resources):power.tick(store,vault)
    assert store.rows('SELECT state FROM power_jobs')[0]['state']=='unknown'


def test_agent_power_uses_existing_identity_but_not_service_recovery(environment):
    app,store,vault=environment;_,now=environment_setup(store,vault)
    with store.connect() as c:
        c.execute("UPDATE agents SET action_credential_digest=NULL,credential_digest=?,capabilities=?,sampled_at=?,telemetry=? WHERE id='agent'",(digest('existing-enrollment-token'),json.dumps({'power_operations':['host_restart','host_shutdown']}),now,json.dumps({'uptime_seconds':1000})))
    job=power.propose(store,'m','restart','Maintenance');approve(store,job)
    with store.connect() as c:delivery=power.poll(c,store,'agent',now)[0]
    client=app.test_client();headers={'Authorization':'Bearer existing-enrollment-token'}
    assert client.post('/api/agent/action-authorize',json={**delivery,'id':'another-job'},headers=headers).status_code==401
    assert client.post('/api/agent/action-authorize',json=delivery,headers=headers).json['operation']=='host_restart'
    assert client.post('/api/agent/action-authorize',json=delivery,headers=headers).status_code==400
    assert client.post('/api/agent/action-result',json={**delivery,'status':'completed','output':'Accepted'},headers=headers).json['status']=='accepted'
    with store.connect() as c:c.execute("UPDATE agents SET revoked=1 WHERE id='agent'")
    assert client.post('/api/agent/action-result',json={**delivery,'status':'completed','output':'Accepted'},headers=headers).status_code==401


def test_linux_power_capability_defaults_to_root_only(tmp_path,monkeypatch):
    spec=importlib.util.spec_from_file_location('power_diagnostics',Path(__file__).resolve().parents[1]/'agent/diagnostics.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    policy=tmp_path/'policy.json';policy.write_text('{}')
    monkeypatch.setattr(module.os,'geteuid',lambda:0)
    assert module.capabilities(module.load_policy(policy))['power_operations']==['host_restart','host_shutdown']
    policy.write_text('{"power":{"enabled":false}}')
    assert 'power_operations' not in module.capabilities(module.load_policy(policy))
    policy.write_text('{}');monkeypatch.setattr(module.os,'geteuid',lambda:1000)
    assert 'power_operations' not in module.capabilities(module.load_policy(policy))
