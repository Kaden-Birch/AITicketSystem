import json,time,uuid
from unittest.mock import patch
from aiticket import ai,commands,proxmox_operations as ops
from test_codex_mode import configure
from test_proxmox_operations import host,payload


def auth(vault,row):return {'Authorization':'Bearer '+vault.decrypt(row['credential'])}


def test_resumed_ticket_can_read_previous_shell_result_but_not_cancel_it(environment):
    app,store,vault=environment;incident=configure(store,vault,command_tools=True,incident_runs=5,daily_runs=10)
    with store.connect() as c:c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES('shell','m','fixture',?,'{\"shell_commands\":true}')",(time.time(),))
    commands.configure(store,'m',{'enabled':'yes','hermes':'yes','approval':'required'})
    old=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(old,))
    identifier=str(uuid.uuid4());commands.queue(store,vault,'m','ip -brief address',identifier,incident,old)
    ai.cancel(store,old)
    new=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(new,))
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(new,))[0]
    client=app.test_client();url='/api/hermes/'+new+'/command'
    result=client.post(url,json={'action':'status','id':identifier},headers=auth(vault,row))
    assert result.status_code==200 and result.json['id']==identifier
    assert client.post(url,json={'action':'cancel','id':identifier},headers=auth(vault,row)).status_code==403
    missing=client.post(url,json={'action':'status','id':str(uuid.uuid4())},headers=auth(vault,row))
    assert missing.status_code==200 and missing.json['state']=='not_recorded'
    # Another ticket on the same host is still outside this execution's scope.
    from aiticket.host_admin import open_ticket
    other=open_ticket(store,'m','Other issue','Different ticket.','high')
    with store.connect() as c:
        c.execute("UPDATE command_jobs SET state='cancelled' WHERE id=?",(identifier,))
    different=str(uuid.uuid4());commands.queue(store,vault,'m','uptime',different,other)
    assert client.post(url,json={'action':'status','id':different},headers=auth(vault,row)).status_code==403


def test_resumed_ticket_can_read_old_proxmox_request(environment):
    app,store,vault=environment;incident=configure(store,vault,command_tools=True,incident_runs=5,daily_runs=10)
    machine,_=host(store,vault,approval='required')
    with store.connect() as c:c.execute('UPDATE incidents SET machine_id=? WHERE id=?',(machine,incident))
    old=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(old,))
    identifier=ops.queue(store,vault,machine,payload('GET','/nodes/a/qemu/209/status/current'),old)
    ai.cancel(store,old)
    new=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(new,))
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(new,))[0]
    response=app.test_client().post('/api/hermes/'+new+'/command',json={'action':'proxmox_status','id':identifier},headers=auth(vault,row))
    assert response.status_code==200 and response.json['state']=='awaiting'
    assert response.json['ai_job_id']==old


def test_lookup_transport_failure_is_not_reported_as_command_dispatch():
    from aiticket.command_tools import invoke
    with patch('aiticket.command_tools.requests.post',side_effect=TimeoutError('private secret')):
        result=json.loads(invoke('http://fixture',{'action':'status','id':'fixture'},credential='fixture',job='fixture'))
    assert result['state']=='lookup_failed' and result['error_type']=='TimeoutError'
    assert 'private secret' not in json.dumps(result)
