import json,time
from aiticket.security import digest
from aiticket.agent_updates import report,request_update
from test_commands import setup


def payload():return {'state':'available','installed':'0.8.0','available':'0.9.0+123456789abc','checked':time.time(),'automatic':True,'detail':'Update available.','handled_request':None}


def test_status_is_authenticated_separate_from_heartbeat_and_requests_are_idempotent(signed_in):
    client,store,vault,csrf=signed_in;machine=setup(store)
    with store.connect() as c:c.execute("UPDATE agents SET credential_digest=?,last_seen=0 WHERE id='shell-agent'",(digest('updater-credential'),))
    assert client.post('/api/agent/updater',json=payload()).status_code==401
    headers={'Authorization':'Bearer updater-credential'}
    assert client.post('/api/agent/updater',json=payload(),headers=headers).status_code==200
    assert store.rows("SELECT last_seen FROM agents WHERE id='shell-agent'")[0]['last_seen']==0
    page=client.get('/hosts/'+machine+'/settings');assert b'Update now' in page.data
    route='/hosts/'+machine+'/agent-update'
    assert client.post(route,data={}).status_code==403
    assert client.post(route,data={'csrf':csrf}).status_code==302
    first=store.rows('SELECT request FROM agent_updates')[0]['request']
    assert client.post(route,data={'csrf':csrf}).status_code==302
    assert store.rows('SELECT request FROM agent_updates')[0]['request']==first
    result=client.post('/api/agent/updater',json=payload(),headers=headers);assert result.json['request']==first
    completed={**payload(),'state':'updated','installed':payload()['available'],'handled_request':first}
    assert client.post('/api/agent/updater',json=completed,headers=headers).json['request'] is None
    assert b'Update now' not in client.get('/hosts/'+machine+'/settings').data
    with store.connect() as c:c.execute("UPDATE agents SET revoked=1 WHERE id='shell-agent'")
    assert client.post('/api/agent/updater',json=payload(),headers=headers).status_code==401


def test_old_agent_shows_bootstrap_and_invalid_reports_rejected(signed_in):
    client,store,vault,csrf=signed_in;machine=setup(store)
    page=client.get('/hosts/'+machine+'/settings');assert b'Setup needed' in page.data
    assert client.post('/hosts/'+machine+'/agent-update',data={'csrf':csrf}).status_code==400
    import pytest
    for bad in ({**payload(),'state':'invalid'},{**payload(),'checked':float('inf')},{**payload(),'installed':'<script>'},{**payload(),'detail':'x'*241}):
        with pytest.raises(ValueError):report(store,'shell-agent',bad)


def test_probation_heartbeat_does_not_dispatch_commands(signed_in):
    client,store,vault,csrf=signed_in;machine=setup(store)
    from aiticket import commands
    commands.configure(store,machine,{'enabled':'yes','hermes':'yes','approval':'immediate'})
    import uuid
    identifier=str(uuid.uuid4());commands.queue(store,vault,machine,'hostname',identifier)
    with store.connect() as c:c.execute("UPDATE agents SET credential_digest=? WHERE id='shell-agent'",(digest('trial'),))
    heartbeat={'event_id':'probation','version':'0.9.0','telemetry':{},'capabilities':{'shell_commands':True},'update_trial':True}
    headers={'Authorization':'Bearer trial'}
    reply=client.post('/api/agent/heartbeat',json=heartbeat,headers=headers)
    assert reply.status_code==200 and reply.json['commands']==[]
    assert client.post('/api/agent/heartbeat',json=heartbeat,headers=headers).json['commands']==[]
    assert commands.view(store,vault,identifier)['state']=='pending'
    heartbeat.update(event_id='normal',update_trial=False)
    assert client.post('/api/agent/heartbeat',json=heartbeat,headers=headers).json['commands'][0]['id']==identifier
