import ast
import json
import time
from pathlib import Path
import pytest
from aiticket.attention import collect,listing
from aiticket.security import digest
from test_commands import setup


@pytest.mark.parametrize('source,os_name',[('agent/diagnostics.py','Linux'),('agent/windows/backend.py','Windows Server 2025')])
def test_real_agent_capabilities_and_release_contract_match_server(environment,source,os_name):
    app,store,_=environment;setup(store)
    with store.connect() as c:c.execute("UPDATE agents SET credential_digest=?,last_seen=0 WHERE id='shell-agent'",(digest('compatibility-test'),))
    # Run the actual platform capability builder without requiring a native OS.
    node=next(n for n in ast.parse(Path(source).read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='capabilities')
    scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),source,'exec'),scope)
    caps=scope['capabilities']({'container_logs':True,'logs':True,'services':{'web':'Spooler' if os_name.startswith('Windows') else 'web.service'},'recovery':{'enabled':True,'validated':True,'services':['web']},'power':{'enabled':True,'validated':True,'operations':['host_restart','host_shutdown']}})
    headers={'Authorization':'Bearer compatibility-test'};client=app.test_client()
    from agent.update_support import requirements
    contract={'version':'0.12.0+abcdef123456',**requirements(Path('agent'))}
    assert client.post('/api/agent/update-compatibility',json=contract,headers=headers).json['compatible'] is True
    assert store.rows("SELECT last_seen FROM agents WHERE id='shell-agent'")[0]['last_seen']==0
    reply=client.post('/api/agent/heartbeat',json={'event_id':'real-platform-'+os_name,'host_info':{'os':os_name},'telemetry':{'cpu_percent':4,'memory_total_bytes':1000,'memory_available_bytes':500},'capabilities':caps,'network':{'machine_type':'physical','interfaces':[],'neighbors':[]},'discovery':{'docker_installed':True,'containers':[{'name':'plex','target':'plex','state':'running','health':'healthy','restart_count':2,'exit_code':0,'oom_killed':False,'cpu_percent':1.5,'memory_percent':2.5}],'processes':[{'name':'python','target':'python','pid':42,'memory_bytes':1024,'cpu_percent':3}],'warnings':[]}},headers=headers)
    assert reply.status_code==200
    assert client.post('/api/agent/update-compatibility',json={**contract,'protocol':1},headers=headers).json['compatible'] is True
    assert client.post('/api/agent/update-compatibility',json={**contract,'protocol':3},headers=headers).json['compatible'] is False
    assert client.post('/api/agent/update-compatibility',json={**contract,'operations':['unsupported']},headers=headers).json['compatible'] is False
    assert client.post('/api/agent/update-compatibility',json=contract).status_code==401
    with store.connect() as c:c.execute("UPDATE agents SET revoked=1 WHERE id='shell-agent'")
    assert client.post('/api/agent/update-compatibility',json=contract,headers=headers).status_code==401


def test_attention_authenticated_searchable_paginated_and_self_clearing(signed_in):
    client,store,_,_=signed_in;machine=setup(store)
    now=time.time()
    with store.connect() as c:
        c.execute("UPDATE agents SET last_seen=0 WHERE id='shell-agent'")
        c.execute("INSERT INTO agent_updates(agent_id,at,status) VALUES('shell-agent',?,?)",(now,json.dumps({'state':'rolled_back','installed':'0.11.0','available':'0.12.0+abcdef123456'})))
    page=client.get('/attention');assert page.status_code==200
    assert b'Agent is disconnected' in page.data and b'Previous agent restored' in page.data
    assert b'Previous agent restored' not in client.get('/attention?view=agents').data
    assert client.get('/attention?view=invalid').status_code==400
    assert b'No matching items' in client.get('/attention?q=nonexistent').data
    with store.connect() as c:
        c.execute('UPDATE agents SET last_seen=?,sampled_at=? WHERE machine_id=?',(now,now,machine))
        c.execute("UPDATE agent_updates SET status=? WHERE agent_id='shell-agent'",(json.dumps({'state':'current','installed':'0.12.0','available':'0.12.0'}),))
    assert not [i for i in collect(store) if i['category'] in ('agents','updates')]
    assert client.get('/').status_code==200
    for n in range(25):
        with store.connect() as c:
            c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,0)',('attention-'+str(n),'Offline '+str(n)))
            c.execute('INSERT INTO agents(id,machine_id,credential_digest) VALUES(?,?,?)',('agent-'+str(n),'attention-'+str(n),'digest-'+str(n)))
    assert len(listing(store,'agents')['items'])==20
    assert listing(store,'agents')['more'] is True
    assert len(listing(store,'agents',page=2)['items'])==5
    client.post('/logout',data={'csrf':signed_in[3]})
    assert client.get('/attention').status_code==302


def test_expected_offline_and_maintenance_hide_disconnects_but_keep_failed_updates(environment):
    _,store,_=environment;mid=setup(store);now=time.time()
    with store.connect() as c:
        c.execute('UPDATE agents SET last_seen=0')
        c.execute("INSERT INTO maintenance_windows(id,name,machine_id,kind,timezone,start,end,enabled) VALUES('planned','Planned',?,'once','UTC',?,?,1)",(mid,now-10,now+100))
    assert not [i for i in collect(store) if i['category']=='agents']
    with store.connect() as c:
        c.execute("UPDATE maintenance_windows SET enabled=0")
        c.execute('UPDATE machines SET offline_expected=1 WHERE id=?',(mid,))
        c.execute("INSERT INTO agent_updates(agent_id,at,status) VALUES('shell-agent',?,?)",(now,json.dumps({'state':'failed'})))
    assert not [i for i in collect(store) if i['category']=='agents']
    assert [i for i in collect(store) if i['category']=='updates']


def test_attention_flags_latest_failed_ai_and_both_delivery_channels(environment):
    _,store,_=environment;mid=setup(store);now=time.time()
    from aiticket.host_admin import open_ticket
    incident=open_ticket(store,mid,'Investigate Plex','Read-only investigation','high')
    from test_codex_mode import configure
    # This helper enrolls a complete AI job with credentials kept in the fixture vault.
    _,_,vault=environment
    other=configure(store,vault)
    from aiticket import ai
    ai.queue_manual(store,vault,other)
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='unknown' WHERE incident_id=?",(other,))
        c.execute("INSERT INTO deliveries(id,incident_id,event_key,state,next_attempt,created,expires) VALUES('failed-message',?,'failed-message','failed',?,?,?)",(incident,now,now,now+100))
        c.execute("INSERT INTO telegram_outbox(id,event_key,chat_id,text,state,created) VALUES('uncertain','uncertain','fixture','fixture','unknown',?)",(now,))
    items=collect(store)
    assert any(i['category']=='ai' and i['title']=='Investigation outcome is uncertain' for i in items)
    assert any(i['key']=='discord:failed' for i in items)
    assert any(i['key']=='telegram:unknown' for i in items)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='completed' WHERE incident_id=?",(other,))
    assert not any(i['category']=='ai' and i['title']=='Investigation outcome is uncertain' for i in collect(store))
