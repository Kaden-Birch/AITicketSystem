import json,time,uuid,importlib.util
from pathlib import Path
from unittest.mock import patch
import pytest
from aiticket import telegram,diagnostics,discovery,ai
from test_codex_mode import configure
from test_knowledge_status_settings import host

TOKEN='123456789:'+('A'*32)


def configured(store,vault):
    telegram.configure(store,vault,{'token':TOKEN,'enabled':'yes','chats':'101','users':'202','queries':'yes','notifications':'yes'})
    return store.setting('telegram_config')


def message(identifier=7,user=202,text='/status Voyager'):
    return {'update_id':identifier,'message':{'chat':{'id':101},'from':{'id':user},'text':text}}


def test_telegram_allowlist_and_durable_dedup(environment):
    _,store,vault=environment;host(store);cfg=configured(store,vault)
    telegram.receive(store,cfg,[message(user=999),message(),message()])
    rows=store.rows('SELECT * FROM telegram_updates');assert len(rows)==1
    with patch('aiticket.telegram.api',return_value=[]):telegram.tick(store,vault)
    assert store.rows('SELECT state FROM telegram_updates')[0]['state']=='completed'
    assert store.rows('SELECT text FROM telegram_outbox')[0]['text'].startswith('Voyager:')
    assert not store.rows('SELECT * FROM ai_jobs')
    assert store.setting('telegram_secret')!=TOKEN
    with pytest.raises(ValueError):telegram.configure(store,vault,{'enabled':'yes','chats':'anyone','users':'202'})


def test_telegram_ask_is_readonly_and_idempotent(environment):
    _,store,vault=environment;incident=configure(store,vault);cfg=configured(store,vault)
    telegram.receive(store,cfg,[message(text='/ask '+incident+' What is the likely cause?')])
    row=store.rows('SELECT * FROM telegram_updates')[0]
    telegram.handle(store,vault,cfg,row);telegram.handle(store,vault,cfg,row)
    jobs=store.rows('SELECT * FROM ai_jobs')
    assert len(jobs)==1 and jobs[0]['read_only']==1
    assert len(store.rows('SELECT * FROM telegram_outbox'))==1


def test_unknown_delivery_not_replayed_and_pending_notifications_recheck_maintenance(environment):
    _,store,vault=environment;host(store);cfg=configured(store,vault)
    from aiticket.host_admin import open_ticket
    incident=open_ticket(store,'h','Plex inaccessible','Cannot read media','high',notify=True)
    telegram.notifications(store,cfg)
    assert len(store.rows('SELECT * FROM telegram_outbox'))==1
    with store.connect() as c:c.execute('UPDATE incidents SET silence_until=? WHERE id=?',(time.time()+300,incident))
    calls=[]
    def api(*args):calls.append(args[2]);return []
    with patch('aiticket.telegram.api',side_effect=api):telegram.tick(store,vault)
    assert calls==['getUpdates']
    with store.connect() as c:
        c.execute('UPDATE incidents SET silence_until=0 WHERE id=?',(incident,))
        c.execute('UPDATE telegram_outbox SET next_attempt=0')
    cfg=store.setting('telegram_config');cfg['next_poll']=0;store.save('telegram_config',cfg)
    def failed(*args):
        if args[2]=='sendMessage':raise ValueError('ambiguous response')
        return []
    with patch('aiticket.telegram.api',side_effect=failed):telegram.tick(store,vault)
    assert store.rows('SELECT state FROM telegram_outbox')[0]['state']=='unknown'
    cfg=store.setting('telegram_config');cfg['next_poll']=0;store.save('telegram_config',cfg)
    with patch('aiticket.telegram.api',side_effect=api):telegram.tick(store,vault)
    assert calls==['getUpdates','getUpdates']


def test_telegram_config_edit_during_poll_fences_response(environment):
    _,store,vault=environment;host(store);configured(store,vault)
    def edited(*args):
        cfg=store.setting('telegram_config');cfg['enabled']=False;store.save('telegram_config',cfg)
        return [message()]
    with patch('aiticket.telegram.api',side_effect=edited):assert telegram.tick(store,vault) is False
    assert not store.rows('SELECT * FROM telegram_updates')


def test_container_discovery_types_trends_and_safe_log_target(environment):
    _,store,vault=environment;host(store)
    raw={'containers':[{'name':'Plex','target':'plex','state':'running','health':'healthy','restart_count':2,'exit_code':0,'oom_killed':False,'started_at':'2026-10-05T01:00:00Z','image_id':'sha256:image'}]}
    assert discovery.validate(raw)['containers'][0]['oom_killed'] is False
    raw['containers'][0]['restart_count']='two'
    with pytest.raises(ValueError):discovery.validate(raw)
    linux=Path(__file__).parents[1]/'agent/diagnostics.py'
    spec=importlib.util.spec_from_file_location('deep_diagnostics_fixture',linux);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    policy={'services':{},'logs':False,'container_logs':True}
    job={'expires':time.time()+30,'operation':'container_logs','parameters':{'target':'plex'}}
    with patch.object(module,'command',return_value={'status':'completed','output':'safe logs'}) as run:
        assert module.execute(job,policy)['status']=='completed'
        assert run.call_args.args[0]==['docker','logs','--tail','50','--since','15m','--timestamps','plex']
        with pytest.raises(ValueError):module.execute({**job,'parameters':{'target':'plex; shutdown'}},policy)
    with pytest.raises(ValueError):module.execute(job,{**policy,'container_logs':False})


def test_server_diagnostic_requires_current_inventory_and_advertised_operation(environment):
    _,store,vault=environment;host(store)
    from aiticket.host_admin import open_ticket
    incident=open_ticket(store,'h','Inspect Plex','Read recent logs','low',handling_mode='paused')
    with store.connect() as c:
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES(?,?,?,?,?)',('a','h','fixture',time.time(),json.dumps({'operations':['container_logs']})))
        c.execute('INSERT INTO agent_discovery VALUES(?,?,?)',('h',time.time(),json.dumps({'containers':[{'name':'Plex','target':'plex'}]})))
    identifier=diagnostics.request_job(store,'a',incident,'container_logs','plex')
    assert identifier==diagnostics.request_job(store,'a',incident,'container_logs','plex')
    with pytest.raises(ValueError):diagnostics.request_job(store,'a',incident,'container_logs','another-container')
    with store.connect() as c:c.execute('UPDATE agent_discovery SET at=?',(time.time()-300,))
    with pytest.raises(ValueError):diagnostics.request_job(store,'a',incident,'container_logs','plex')


def test_telegram_chat_finder_pairs_only_admin_selected_conversation(signed_in):
    client,store,vault,csrf=signed_in
    telegram.configure(store,vault,{'token':TOKEN,'chats':'','users':''})
    with patch('aiticket.telegram.api',return_value=[message()]):
        response=client.post('/settings/telegram',data={'csrf':csrf,'operation':'find'})
    assert response.status_code==200 and b'Connect this chat' in response.data
    assert client.post('/settings/telegram',data={'csrf':csrf,'operation':'allow','conversation':'101:999'}).status_code==200
    assert not store.setting('telegram_config')['enabled']
    assert client.post('/settings/telegram',data={'csrf':csrf,'operation':'allow','conversation':'101:202'}).status_code==302
    cfg=store.setting('telegram_config');assert cfg['enabled'] and cfg['chats']==['101'] and cfg['users']==['202']


def test_maintenance_paused_notification_does_not_starve_manual_query(environment):
    _,store,vault=environment;host(store);cfg=configured(store,vault)
    from aiticket.host_admin import open_ticket
    incident=open_ticket(store,'h','Plex inaccessible','Cannot read media','high',notify=True)
    telegram.notifications(store,cfg)
    with store.connect() as c:c.execute('UPDATE incidents SET silence_until=? WHERE id=?',(time.time()+300,incident))
    with patch('aiticket.telegram.api',return_value=[message()]):telegram.tick(store,vault)
    cfg=store.setting('telegram_config');cfg['next_poll']=0;store.save('telegram_config',cfg)
    calls=[]
    def api(*args):calls.append(args[2]);return []
    with patch('aiticket.telegram.api',side_effect=api):telegram.tick(store,vault)
    assert calls==['getUpdates','sendMessage']
    rows=store.rows('SELECT state,event_key FROM telegram_outbox ORDER BY created')
    assert rows[0]['state']=='pending' and rows[1]['state']=='completed'


def test_bot_rotation_and_interrupted_send_are_not_replayed(environment):
    _,store,vault=environment;host(store);cfg=configured(store,vault)
    telegram.receive(store,cfg,[message()])
    telegram.configure(store,vault,{'token':'987654321:'+('B'*32),'enabled':'yes','chats':'101','users':'202','queries':'yes'})
    cfg=store.setting('telegram_config');telegram.receive(store,cfg,[message()])
    assert len(store.rows('SELECT * FROM telegram_updates'))==2
    with store.connect() as c:
        c.execute("UPDATE telegram_updates SET state='completed'")
        telegram.enqueue(c,'fixture-interrupted','101','Fixture message')
        c.execute("UPDATE telegram_outbox SET state='sending',next_attempt=?",(time.time()-60,))
    calls=[]
    with patch('aiticket.telegram.api',side_effect=lambda *args:calls.append(args[2]) or []):telegram.tick(store,vault)
    row=store.rows("SELECT * FROM telegram_outbox WHERE event_key='fixture-interrupted'")[0]
    assert row['state']=='unknown' and 'sendMessage' not in calls


def test_selected_container_inspection_fields_and_windows_optout(tmp_path,monkeypatch):
    import sys,types
    root=Path(__file__).parents[1]/'agent'
    spec=importlib.util.spec_from_file_location('fixture_deep_monitoring',root/'monitoring.py');monitoring=importlib.util.module_from_spec(spec);spec.loader.exec_module(monitoring)
    fake=types.ModuleType('diagnostics');fake.redact=lambda text:__import__('re').sub(r'token=[^ ]+', 'token=[REDACTED]',text)
    monkeypatch.setitem(sys.modules,'diagnostics',fake)
    items=[{'name':'Plex','target':'plex'}];calls=[]
    def runner(argv,**kwargs):
        calls.append((argv,kwargs))
        return {'state':'completed','stdout':json.dumps({'name':'/plex','restart_count':2,'exit_code':137,'oom_killed':True,'health':'unhealthy','image_id':'sha256:fixture','started_at':'2026-10-05T01:00:00Z','exit_reason':'token=private'})}
    monitoring.container_facts(items,runner)
    assert items[0]['restart_count']==2 and items[0]['oom_killed'] is True
    assert 'private' not in items[0]['exit_reason'] and '.Config' not in calls[0][0][4]
    assert calls[0][0][-2:]==['--','plex'] and calls[0][1]['limit']==60000
    spec=importlib.util.spec_from_file_location('platform_support',root/'windows/platform_support.py');support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
    monkeypatch.setitem(sys.modules,'platform_support',support)
    spec=importlib.util.spec_from_file_location('fixture_windows_deep_backend',root/'windows/backend.py');backend=importlib.util.module_from_spec(spec);spec.loader.exec_module(backend)
    policy=tmp_path/'policy.json';policy.write_text(json.dumps({'container_logs':False,'power':{'enabled':False,'operations':[]}}))
    shell=types.SimpleNamespace(IsUserAnAdmin=lambda:False)
    monkeypatch.setattr(backend.ctypes,'windll',types.SimpleNamespace(shell32=shell),raising=False)
    loaded=backend.load_policy(policy)
    assert 'container_logs' not in backend.capabilities(loaded)['operations']


def test_namespaced_updates_are_handled_in_receipt_order(environment):
    _,store,vault=environment;host(store);cfg=configured(store,vault)
    telegram.receive(store,cfg,[message(1,text='/status Voyager'),message(2,text='/status all'),message(3,text='/status missing')])
    expected=[r['update_id'] for r in store.rows('SELECT * FROM telegram_updates ORDER BY created')]
    handled=[]
    with patch('aiticket.telegram.api',return_value=[]),patch('aiticket.telegram.handle',side_effect=lambda store,vault,cfg,row:handled.append(row['update_id'])):
        telegram.tick(store,vault)
    assert handled==expected
