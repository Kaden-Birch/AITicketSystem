import json,time
from unittest.mock import Mock,patch
from aiticket.machine_context import context
from test_commands import setup
from test_codex_mode import configure
from aiticket import ai


def test_agent_address_freshness_and_shell_reason(environment):
    _,store,_=environment;machine=setup(store)
    with store.connect() as c:
        c.execute("UPDATE agents SET address='10.128.2.45',last_seen=100,capabilities='{}' WHERE machine_id=?",(machine,))
        facts=context(c,machine,110)
        assert facts['agent_connection']['address']=='10.128.2.45' and facts['agent_connection']['fresh']
        assert not facts['shell']['available'] and 'capability' in facts['shell']['reason']
        assert not context(c,machine,400)['agent_connection']['fresh']
        c.execute("UPDATE agents SET capabilities='{\"shell_commands\":true}' WHERE machine_id=?",(machine,))
        assert context(c,machine,110)['shell']['available']


def test_ticket_target_and_context_exist_without_shell_permission(environment):
    app,store,vault=environment;incident=configure(store,vault,command_tools=True)
    job=ai.request_job(store,vault,incident)
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    evidence=json.loads(row['evidence'])
    assert evidence['machine']['id']=='m' and not evidence['machine']['shell']['available']
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    auth={'Authorization':'Bearer '+vault.decrypt(row['credential'])}
    response=app.test_client().post('/api/hermes/'+job+'/command',json={'action':'targets'},headers=auth)
    assert response.status_code==200 and response.json['targets'][0]['id']=='m'
    assert not response.json['targets'][0]['shell']['available']
    # Discovery of the bound machine does not grant shell access.
    import uuid
    response=app.test_client().post('/api/hermes/'+job+'/command',json={'action':'run','id':str(uuid.uuid4()),'command':'ip -j address'},headers=auth)
    assert response.status_code==400 and response.json['state']=='rejected'


def test_tool_relays_rejected_request_detail():
    from aiticket.command_tools import invoke
    response=Mock(status_code=400);response.raw.read.return_value=b'{"error":"No fresh command-capable agent available.","state":"rejected"}'
    response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
    with patch('aiticket.command_tools.requests.post',return_value=response):
        result=json.loads(invoke('http://fixture',{'action':'run','id':'fixture','command':'id'},credential='fixture',job='fixture'))
    assert result['state']=='rejected' and result['http_status']==400 and 'fresh command-capable' in result['error']


def test_proxmox_network_error_retains_safe_type(environment):
    from test_proxmox_operations import host,payload
    from aiticket import proxmox_operations as ops
    _,store,vault=environment;machine,_=host(store,vault)
    with patch('aiticket.proxmox_operations.requests.request',side_effect=TimeoutError('private credentials must not appear')):
        identifier=ops.queue(store,vault,machine,payload('GET','/nodes/a/qemu/209/agent/network-get-interfaces'),external=True)
    result=ops.view(store,vault,identifier)
    assert result['state']=='unknown' and result['result']['error_type']=='TimeoutError'
    assert 'private credentials' not in json.dumps(result)
