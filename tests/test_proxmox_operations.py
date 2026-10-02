import json,time,uuid
from unittest.mock import patch,Mock
import pytest
from aiticket import proxmox_operations as ops,commands
from aiticket.proxmox import discover,link,Client,unlink
from test_proxmox import setup,inventory


def host(store,vault,approval='immediate'):
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()): discover(store,vault,'p1')
    obj=store.rows("SELECT id FROM proxmox_objects WHERE object_key='qemu/209'")[0]
    link(store,obj['id'],None,'stopped','Guest')
    machine=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(obj['id'],))[0]['machine_id']
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','external':'yes','approval':approval})
    return machine,obj['id']


def payload(method='POST',path='/nodes/a/qemu/209/status/start'):
    return {'id':str(uuid.uuid4()),'connection_id':'p1','method':method,'path':path,'params':{}}


def response(code=200):
    r=Mock();r.status_code=code;r.raw.read.return_value=b'{"data":"UPID:fixture"}'
    r.__enter__=Mock(return_value=r);r.__exit__=Mock(return_value=False)
    return r


def test_general_api_without_guest_agent_token_scope_and_no_replay(environment):
    _,store,vault=environment;machine,_=host(store,vault);p=payload('PUT','/nodes/a/qemu/209/config');p['params']={'memory':2048}
    with patch('aiticket.proxmox_operations.requests.request',return_value=response()) as request:
        identifier=ops.queue(store,vault,machine,p,external=True)
        assert ops.view(store,vault,identifier)['state']=='completed'
        assert ops.queue(store,vault,machine,p,external=True)==identifier
        assert request.call_count==1
        assert request.call_args.args[0]=='PUT'
        assert request.call_args.kwargs['data']=={'memory':2048}
        assert request.call_args.kwargs['allow_redirects'] is False
        assert 'PVEAPIToken=' in request.call_args.kwargs['headers']['Authorization']
    with pytest.raises(ValueError): ops.queue(store,vault,machine,{**p,'path':'/other'},external=True)


def test_exact_approval_and_migration_fencing(environment):
    _,store,vault=environment;machine,obj=host(store,vault,'required');p=payload()
    with patch('aiticket.proxmox_operations.requests.request') as request:
        identifier=ops.queue(store,vault,machine,p,external=True);assert not request.called
        with pytest.raises(ValueError): ops.decide(store,vault,identifier,'approve','wrong')
        with store.connect() as c: c.execute("UPDATE proxmox_objects SET node='b',generation=generation+1 WHERE id=?",(obj,))
        with pytest.raises(ValueError,match='binding'): ops.decide(store,vault,identifier,'approve',ops.view(store,vault,identifier)['fingerprint'])
        assert not request.called


def test_unknown_delivery_locks_and_unlink_blocks_until_reconciliation(environment):
    _,store,vault=environment;machine,obj=host(store,vault);p=payload()
    with patch('aiticket.proxmox_operations.requests.request',side_effect=TimeoutError): identifier=ops.queue(store,vault,machine,p,external=True)
    assert ops.view(store,vault,identifier)['state']=='unknown'
    with pytest.raises(ValueError): ops.queue(store,vault,machine,payload(),external=True)
    with pytest.raises(ValueError): unlink(store,obj)
    ops.decide(store,vault,identifier,'reconcile',ops.view(store,vault,identifier)['fingerprint'])
    unlink(store,obj)


def test_api_paths_connections_and_policy_are_bound(environment):
    _,store,vault=environment;machine,_=host(store,vault)
    for changed in ({'path':'//evil.example'}, {'path':'/%2e%2e/x'}, {'path':'/x?secret=y'}, {'connection_id':'unlinked'}):
        with pytest.raises(ValueError):ops.queue(store,vault,machine,{**payload(),**changed},external=True)
    commands.configure(store,machine,{'enabled':'yes','external':'no'})
    with pytest.raises(ValueError):ops.queue(store,vault,machine,payload(),external=True)


def test_operational_snapshot_keeps_current_task_and_linked_identity(environment):
    from test_codex_mode import configure
    from aiticket import ai
    _,store,vault=environment;machine,_=host(store,vault)
    incident=configure(store,vault,command_tools=True)
    with store.connect() as c:c.execute('UPDATE incidents SET machine_id=? WHERE id=?',(machine,incident))
    job=ai.request_job(store,vault,incident,mode='exploration',request_id=str(uuid.uuid4()),question='Run id now; investigate the linked VM if it is down.')
    document=json.loads(store.rows('SELECT evidence FROM ai_jobs WHERE id=?',(job,))[0]['evidence'])
    assert document['administrator_task'].startswith('Run id now')
    assert document['linked_proxmox']['objects'][0]['object_key']=='qemu/209'
    assert document['linked_proxmox']['connections'][0]['id']=='p1'
    assert 'fixture-secret' not in json.dumps(document)


def test_api_response_redacts_sensitive_fields_and_reports_denial(environment):
    _,store,vault=environment;machine,_=host(store,vault);r=response(403);r.raw.read.return_value=b'{"data":{"token":"secret-value"},"errors":"denied"}'
    with patch('aiticket.proxmox_operations.requests.request',return_value=r): identifier=ops.queue(store,vault,machine,payload(),external=True)
    result=ops.view(store,vault,identifier)
    assert result['state']=='failed' and 'secret-value' not in json.dumps(result)


def test_gui_exact_proxmox_approval_and_history(signed_in):
    client,store,vault,csrf=signed_in;machine,_=host(store,vault,'required')
    identifier=ops.queue(store,vault,machine,payload(),external=True)
    assert b'Approve exact Proxmox request' in client.get('/hosts/'+machine).data
    url='/proxmox-requests/'+identifier+'/decide'
    assert client.post(url,data={'csrf':csrf,'operation':'approve'}).status_code==400
    with patch('aiticket.proxmox_operations.requests.request',return_value=response()) as request:
        result=client.post(url,data={'csrf':csrf,'operation':'approve','confirm':'yes','fingerprint':ops.view(store,vault,identifier)['fingerprint']})
        assert result.status_code==302 and request.call_count==1
    assert ops.view(store,vault,identifier)['state']=='completed'


def test_tool_api_output_is_bounded_without_shell_fields():
    from aiticket.command_tools import invoke
    r=response();r.status_code=200;r.raw.read.return_value=json.dumps({'id':'fixture','state':'completed','result':{'body':'x'*6000,'http_status':200}}).encode()
    with patch('aiticket.command_tools.requests.post',return_value=r):
        result=json.loads(invoke('http://192.0.2.10',{'action':'proxmox_status','id':'fixture'},credential='fixture',job='fixture'))
    assert result['more_output'] and len(result['result']['body'])==2048


def test_api_payload_rotation_preserves_immutable_request(environment,tmp_path):
    from aiticket.administration import rotate_key
    _,store,vault=environment;machine,_=host(store,vault,'required');p=payload();p['params']={'password':'fixture-sensitive-value'}
    identifier=ops.queue(store,vault,machine,p,external=True)
    before=store.rows('SELECT payload,fingerprint FROM proxmox_api_jobs WHERE id=?',(identifier,))[0]
    assert 'fixture-sensitive-value' not in before['payload']
    new_vault=rotate_key(store,vault,tmp_path/'rotated.key')
    after=store.rows('SELECT payload,fingerprint FROM proxmox_api_jobs WHERE id=?',(identifier,))[0]
    assert after['payload']!=before['payload'] and after['fingerprint']==before['fingerprint']
    assert json.loads(new_vault.decrypt(after['payload']))['params']['password']=='fixture-sensitive-value'
    assert 'fixture-sensitive-value' not in json.dumps(ops.view(store,new_vault,identifier))
    with pytest.raises(Exception):
        with store.connect() as c: c.execute("UPDATE proxmox_api_jobs SET payload='changed' WHERE id=?",(identifier,))
