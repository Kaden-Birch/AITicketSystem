import json,time
from datetime import datetime,timezone
import pytest
from aiticket import log_problems as problems, log_coverage as coverage, log_archive_ai as history,log_archive as archive,network_logs as logs
from aiticket.engine import observe,claim
from test_troubleshooting import host,feed,cef,connection,AP,MAC
from test_evidence_groups_maintenance import operational,window
from test_log_archive import configure,smb


def rule(store,**values):
    return problems.save_rule(store,{'name':'Frequent disconnects','kind':'disconnect','count':'3','minutes':'15','enabled':'yes','tickets':'yes',**values})


def test_patterns_durable_counts_one_ticket_quiet_not_recovery(environment):
    _,store,_=environment;host(store);now=time.time();rule(store)
    _,collector=feed(store,events=[(cef(),now-60+i*10) for i in range(4)])
    problems.tick(store,now,force=True)
    rows=problems.problems(store);assert len(rows)==1 and rows[0]['event_count']==4 and rows[0]['incident_id']
    problems.tick(store,now+30,force=True)
    assert len(store.rows('SELECT 1 FROM incidents'))==1 and problems.problems(store)[0]['data']['total_observations']==4
    from aiticket.evidence import page
    with store.connect() as c:assert 'seen_keys' not in page(c,'m','network_problems')['items'][0]['data']
    problems.tick(store,now+1000,force=True)
    assert problems.problems(store)[0]['state']=='no recent observations'
    assert store.rows('SELECT status,closed FROM incidents')[0]=={'status':'Open','closed':None}
    assert claim(store,'checks',now)['kind']=='tcp' # Synthetic checks never enter the generic network probe queue.
    assert not store.rows('SELECT 1 FROM ai_jobs') and not store.rows('SELECT 1 FROM command_jobs')


def test_rules_maintenance_delayed_identity_and_disable(environment):
    _,store,_=environment;host(store);now=time.time();identifier=rule(store)
    window(store,'m',now-200,now+100)
    feed(store,events=[(cef(),now-60+i*10) for i in range(4)])
    problems.tick(store,now,force=True);assert not problems.problems(store)
    with store.connect() as c:c.execute('DELETE FROM maintenance_windows')
    problems.tick(store,now+200,force=True)
    assert problems.problems(store) and not store.rows('SELECT 1 FROM incidents') # Old event-time failures cannot open a new incident.
    rule(store,id=identifier,enabled='')
    assert not store.rows('SELECT 1 FROM checks WHERE kind="network_problem" AND enabled=1')


def test_port_flapping_requires_transitions_and_rejects_unknown_names(environment):
    _,store,_=environment;host(store);now=time.time();rule(store,kind='flap',tickets='')
    feed(store,events=[(cef('Port Link '+state),now-50+i*10) for i,state in enumerate(['Down','Down','Up','Down','Up'])])
    problems.tick(store,now,force=True)
    assert problems.problems(store)[0]['event_count']==3
    assert not store.rows('SELECT 1 FROM incidents')
    assert problems.classify(logs.parse('CEF:0|Ubiquiti|UniFi|10|1|Failed Login|7|msg=x'))=='auth'
    assert problems.classify(logs.parse('CEF:0|Ubiquiti|UniFi|10|1|Device Restarted|7|msg=x'))=='restart'
    assert problems.classify(logs.parse('CEF:0|Ubiquiti|UniFi|10|1|WAN Failover|7|msg=x'))=='wan'
    assert problems.classify(logs.parse('plain syslog port down')) is None


def test_coverage_quiet_sources_and_persistent_health_recovery(environment,monkeypatch):
    _,store,_=environment;host(store);now=time.time();logs.save_source(store,{'name':'Quiet console','sender_ip':'192.0.2.1','enabled':'yes'})
    coverage.save(store,{'health_machine':'m','health_enabled':'yes','failure_minutes':'2'})
    collector={'heartbeat':now,'available':True,'storage_errors':0}
    monkeypatch.setattr(logs,'status',lambda _:collector)
    coverage.tick(store,now,force=True);coverage.tick(store,now+30,force=True)
    assert not store.rows('SELECT 1 FROM incidents')
    result=coverage.view(store,now);assert result['matched_hosts']==0 and result['sources'][0]['count']==0
    coverage.tick(store,now+180,force=True)
    incident=store.rows('SELECT * FROM incidents')[0];assert json.loads(incident['report'])['evidence']['heartbeat']==now
    collector['heartbeat']=now+181
    coverage.tick(store,now+181,force=True);collector['heartbeat']=now+212;coverage.tick(store,now+212,force=True)
    assert store.rows('SELECT status FROM incidents')[0]['status']=='Resolved'
    assert not store.rows('SELECT 1 FROM checks WHERE kind="log_health" AND name LIKE "%archive%" AND enabled=1')


def test_upload_failure_backlog_and_worker_staleness_actionable(environment,monkeypatch):
    _,store,vault=environment;host(store);now=time.time();configure(store,vault)
    coverage.save(store,{'health_machine':'m','health_enabled':'yes','failure_minutes':'2'})
    monkeypatch.setattr(logs,'status',lambda _:{'heartbeat':now,'available':True,'storage_errors':0})
    state={'available':True,'heartbeat':now,'pending':3,'error':'Share unavailable','error_since':now-180}
    monkeypatch.setattr(archive,'archive_status',lambda _:state)
    coverage.tick(store,now,force=True)
    assert store.rows('SELECT name FROM checks WHERE health="down"')[0]['name']=='Log collection · archive'
    state.update(error=None,error_since=None,pending=0,last_success=now)
    coverage.tick(store,now+1,force=True);coverage.tick(store,now+2,force=True)
    assert store.rows('SELECT status FROM incidents')[0]['status']=='Resolved'


def test_confirmed_switch_correlation_excludes_candidates_maintenance_and_detached(environment,monkeypatch):
    _,store,_=environment;host(store);host(store,'child');now=time.time()
    for mid in ('m','child'):
        with store.connect() as c:c.execute('UPDATE checks SET fail_after=1 WHERE machine_id=?',(mid,))
        observe(store,'check-'+mid,False,{'reason':'Fresh unreachable'},now)
    def facts(c,machine,at):return {'links':[{'connection_id':'fixture','device_id':'switch','confidence':'candidate','fresh':True}]}
    monkeypatch.setattr('aiticket.topology.context',facts)
    problems.correlate(store,now);assert not store.rows('SELECT 1 FROM ticket_groups')
    monkeypatch.setattr('aiticket.topology.context',lambda c,m,a:{'links':[{'connection_id':'fixture','device_id':'switch','confidence':'confirmed','fresh':True}]})
    window(store,'child',now-1,now+5);problems.correlate(store,now);assert not store.rows('SELECT 1 FROM ticket_groups')
    with store.connect() as c:c.execute('DELETE FROM maintenance_windows')
    problems.correlate(store,now);group=store.rows('SELECT * FROM ticket_groups')[0]
    from aiticket.ticket_groups import detach
    detach(store,group['primary_id'],group['member_id']);problems.correlate(store,now)
    assert not store.rows('SELECT 1 FROM ticket_groups')


def test_problem_health_ui_validation_auth_csrf(signed_in):
    client,store,_,csrf=signed_in;host(store)
    assert client.get('/network-events/problems').status_code==200
    assert client.get('/network-events/coverage').status_code==200
    values={'csrf':csrf,'name':'<script>bad()</script>','kind':'disconnect','count':'3','minutes':'15','enabled':'yes'}
    assert client.post('/network-events/problems',data=values).status_code==302
    assert b'&lt;script&gt;bad()&lt;/script&gt;' in client.get('/network-events/problems').data
    assert client.post('/network-events/problems',data={**values,'count':'0'}).status_code==200
    assert not store.rows('SELECT 1 FROM command_jobs')
    assert client.post('/network-events/problems',data={k:v for k,v in values.items() if k!='csrf'}).status_code==403
    with client.session_transaction() as s:s.clear()
    assert client.get('/network-events/coverage').status_code==302


def dates(now,**extra):
    return {'start':datetime.fromtimestamp(now-300,timezone.utc).isoformat(),'end':datetime.fromtimestamp(now+10,timezone.utc).isoformat(),**extra}


def test_ai_archive_scope_idempotency_real_search_references_and_revocation(environment,smb):
    app,store,vault=environment;incident,job=operational(store,vault);now=time.time();cfg=configure(store,vault)
    with store.connect() as c:c.execute('INSERT INTO network_inventory VALUES(?,?,?)',('m',now,json.dumps({'interfaces':[{'mac':MAC}]})))
    feed(store,events=[(cef(),now-60+i*10) for i in range(4)])
    fake,io=smb;worker=archive.Archiver(store,vault,io);worker.upload(cfg)
    auth={'Authorization':'Bearer '+vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(job,))[0]['credential'])};client=app.test_client();path='/api/hermes/'+job+'/command'
    request={'action':'archive_search',**dates(now),'query':'Disconnected'}
    response=client.post(path,json=request,headers=auth);assert response.status_code==200,response.json
    identifier=response.json['id']
    assert client.post(path,json=request,headers=auth).json['id']==identifier
    assert client.post(path,json={**request,'machine_id':'other'},headers=auth).status_code==403
    assert worker.process_job()
    answer=client.post(path,json={'action':'archive_status','id':identifier},headers=auth).json
    assert answer['state']=='complete' and len(answer['observed_facts'])==4 and not answer['suspected_causes']
    assert '/network-events/archive/'+identifier+'/' in answer['observed_facts'][0]['reference']
    assert 'test-secret' not in json.dumps(answer) and 'connection' not in answer
    with store.connect() as c:c.execute("UPDATE incident_control SET owner='user' WHERE incident_id=?",(incident,))
    assert client.post(path,json={'action':'archive_status','id':identifier},headers=auth).status_code==403


def test_ai_archive_limits_pending_revocation_and_empty_unavailable_are_distinct(environment,smb):
    _,store,vault=environment;incident,job=operational(store,vault);now=time.time();configure(store,vault)
    with pytest.raises(ValueError):history.search(store,vault,job,'m',{'start':'2020-01-01','end':'2020-02-02'})
    ids=[history.search(store,vault,job,'m',dates(now,query=str(i)))['id'] for i in range(4)]
    with pytest.raises(ValueError,match='four'):history.search(store,vault,job,'m',dates(now,query='fifth'))
    with pytest.raises(ValueError,match='different'):history.result(store,'other-job','m',ids[0])
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='cancelled' WHERE id=?",(job,))
    worker=archive.Archiver(store,vault,smb[1]);worker.process_job()
    assert history.result(store,job,'m',ids[0])['state']=='failed'
    assert not store.rows('SELECT 1 FROM command_jobs')


def test_archive_partial_bounds_cache_expiry_and_binding_changes(environment,smb):
    app,store,vault=environment;incident,job=operational(store,vault);now=time.time();cfg=configure(store,vault)
    with store.connect() as c:c.execute('INSERT INTO network_inventory VALUES(?,?,?)',('m',now,json.dumps({'interfaces':[{'mac':MAC}]})))
    source,_=feed(store,events=[(cef(extra='msg='+('x'*1200)),now-180+i) for i in range(65)])
    worker=archive.Archiver(store,vault,smb[1]);worker.upload(cfg)
    identifier=history.search(store,vault,job,'m',dates(now))['id'];worker.process_job()
    answer=history.result(store,job,'m',identifier)
    assert answer['truncated'] and len(answer['observed_facts'])<=50 and len(json.dumps(answer['observed_facts']))<17000
    host(store,'new-owner');logs.bind(store,source,MAC,'new-owner')
    assert not history.result(store,job,'m',identifier)['observed_facts']
    archive.results_path(store,identifier).write_text('broken cache')
    assert history.result(store,job,'m',identifier)['state']=='unavailable'
    archive.results_path(store,identifier).unlink()
    assert history.result(store,job,'m',identifier)['state']=='expired'


def test_collector_health_maintenance_does_not_open_expected_failure(environment,monkeypatch):
    _,store,_=environment;host(store);now=time.time();logs.save_source(store,{'name':'Console','sender_ip':'192.0.2.1','enabled':'yes'})
    coverage.save(store,{'health_machine':'m','health_enabled':'yes','failure_minutes':'2'})
    monkeypatch.setattr(logs,'status',lambda _:{'heartbeat':now-300,'available':False,'storage_errors':0})
    window(store,'m',now-400,now+300);coverage.tick(store,now,force=True)
    assert not store.rows('SELECT 1 FROM incidents')
    assert store.rows('SELECT health FROM checks WHERE kind="log_health" AND name LIKE "%collector%"')[0]['health']=='down'


def test_event_type_identity_scope_restart_and_auth_separate(environment):
    _,store,_=environment;host(store);now=time.time()
    for kind in ('restart','auth','wan'):rule(store,name=kind,kind=kind,tickets='')
    texts=[]
    for i in range(3):
        texts += [(cef('Device Restarted'),now-90+i*10),(cef('Authentication Failed'),now-60+i*10),(cef('WAN Failover'),now-30+i*5)]
    feed(store,events=texts);problems.tick(store,now,force=True)
    assert {p['data']['kind'] for p in problems.problems(store)}=={'restart','auth','wan'}
    assert all(p['event_count']==3 for p in problems.problems(store))
    assert not store.rows('SELECT 1 FROM incidents')


def test_pattern_rebinding_fences_old_host_check(environment):
    _,store,_=environment;host(store);host(store,'new-owner');now=time.time();rule(store)
    source,_=feed(store,events=[(cef(),now-60+i*10) for i in range(4)])
    problems.tick(store,now,force=True)
    old=problems.problems(store)[0];assert store.rows('SELECT machine_id FROM checks WHERE id=?',(old['check_id'],))[0]['machine_id']=='m'
    logs.bind(store,source,MAC,'new-owner');problems.tick(store,now+30,force=True)
    entries=problems.problems(store);assert len(entries)==2
    new=next(p for p in entries if p['id']!=old['id'])
    assert store.rows('SELECT machine_id FROM checks WHERE id=?',(new['check_id'],))[0]['machine_id']=='new-owner'
    assert store.rows('SELECT health FROM checks WHERE id=?',(old['check_id'],))[0]['health']=='unknown'


def test_pattern_counts_survive_local_event_id_reuse(environment):
    app,store,_=environment;host(store);now=time.time();rule(store)
    source,collector=feed(store,events=[(cef(),now-60+i*10) for i in range(4)])
    problems.tick(store,now,force=True)
    old_ref=problems.problems(store)[0]['data']['events'][0]['url']
    with collector.archive.connect() as c:c.execute('DELETE FROM event_hosts');c.execute('DELETE FROM events')
    for i in range(3):
        at=now+i*10
        collector.receive(('<134>1 '+datetime.fromtimestamp(at,timezone.utc).isoformat()+' console - - - '+cef()).encode(),'192.0.2.1',at)
    collector.flush();problems.tick(store,now+30,force=True)
    assert len(problems.problems(store))==1 and problems.problems(store)[0]['data']['total_observations']==7
    client=app.test_client()
    with client.session_transaction() as session:session['admin']=True
    assert client.get(old_ref).status_code==404
    assert client.get(problems.problems(store)[0]['data']['events'][0]['url']).status_code==200
    from aiticket.health_rules import incident_paused
    identifier=problems.rules(store)[0]['id'];rule(store,id=identifier,enabled='')
    with store.connect() as c:assert incident_paused(c,problems.problems(store)[0]['incident_id'])


def test_unrelated_quiet_pattern_does_not_block_verified_ai_resolution(environment):
    from aiticket import engine,ai
    from aiticket.host_admin import open_ticket
    from test_codex_mode import configure
    _,store,vault=environment;configure(store,vault);now=time.time()
    manual=open_ticket(store,'m','Separate host issue','Verify service recovery.','high')
    job=ai.request_job(store,vault,manual)
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='completed',resolution_summary='Service verified.' WHERE id=?",(job,))
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,health) VALUES('quiet-pattern','m','Earlier disconnects','network_problem','{}',30,'unknown')")
    for i in range(3):engine.observe(store,'c',True,{},now=now+10+i)
    engine.resolution_tick(store,now+13)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(manual,))[0]['status']=='Resolved'


def test_disconnect_uses_client_policy_when_infrastructure_is_also_matched(environment):
    _,store,_=environment;host(store);host(store,'switch');now=time.time();rule(store)
    source,collector=feed(store,events=[(cef(),now-60+i*10) for i in range(4)])
    with collector.archive.connect() as c:
        rows=c.execute('SELECT id,associations FROM events').fetchall()
        for row in rows:
            associations=json.loads(row['associations']);associations.insert(0,{'machine_id':'switch','role':'infrastructure','method':'fixture'})
            c.execute('UPDATE events SET associations=? WHERE id=?',(json.dumps(associations),row['id']))
    problems.tick(store,now,force=True)
    entry=problems.problems(store)[0]
    assert set(entry['data']['hosts'])=={'m','switch'}
    assert store.rows('SELECT machine_id FROM incidents WHERE id=?',(entry['incident_id'],))[0]['machine_id']=='m'


def test_requested_local_network_logs_without_smb_scope_and_filters(environment):
    app,store,vault=environment;incident,job=operational(store,vault);now=time.time()
    with store.connect() as c:c.execute('INSERT INTO network_inventory VALUES(?,?,?)',('m',now,json.dumps({'interfaces':[{'mac':MAC}]})))
    feed(store,events=[(cef(),now-60+i) for i in range(15)])
    auth={'Authorization':'Bearer '+vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(job,))[0]['credential'])}
    client=app.test_client();path='/api/hermes/'+job+'/command'
    request={'action':'archive_search','tier':'local',**dates(now),'query':'Disconnected','limit':3}
    response=client.post(path,json=request,headers=auth)
    assert response.status_code==200,response.json
    assert response.json['state']=='complete' and response.json['tier']=='local'
    assert len(response.json['observed_facts'])==3 and response.json['truncated']
    assert all(e['reference'].startswith('/network-events/') for e in response.json['observed_facts'])
    assert not response.json['suspected_causes'] and 'test-secret' not in json.dumps(response.json)
    assert not store.rows('SELECT 1 FROM log_archive_jobs')
    assert client.post(path,json={**request,'machine_id':'other'},headers=auth).status_code==403
    assert client.post(path,json={**request,'limit':21},headers=auth).status_code==400
    assert not store.rows('SELECT 1 FROM command_jobs')


def test_requested_local_telemetry_is_filtered_bounded_and_has_references(environment):
    app,store,vault=environment;incident,job=operational(store,vault);configure(store,vault);now=time.time()
    from aiticket import telemetry_archive as telemetry
    for i in range(12):telemetry.record(store,'metrics','m','m',{'cpu_percent':i,'password':'private-value'},now-60+i)
    telemetry.record(store,'metrics','other','other',{'cpu_percent':999},now)
    answer=history.search(store,vault,job,'m',dates(now,tier='local',archive_type='telemetry',record_type='metrics',limit=2))
    assert answer['state']=='complete' and answer['truncated'] and len(answer['observed_facts'])==2
    assert all(e['machine_id']=='m' and e['kind']=='metrics' and e['reference'].startswith('/telemetry-history/records/') for e in answer['observed_facts'])
    assert 'private-value' not in json.dumps(answer) and not store.rows('SELECT 1 FROM log_archive_jobs')
    assert not history.search(store,vault,job,'m',dates(now,tier='local',archive_type='telemetry',record_type='metrics',query='no matching readings'))['observed_facts']
    auth={'Authorization':'Bearer '+vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(job,))[0]['credential'])}
    request={'action':'archive_search',**dates(now),'tier':'local','archive_type':'telemetry','record_type':'metrics','limit':2}
    response=app.test_client().post('/api/hermes/'+job+'/command',json=request,headers=auth)
    assert response.status_code==200 and len(response.json['observed_facts'])==2
    assert app.test_client().post('/api/hermes/'+job+'/command',json={**request,'machine_id':'other'},headers=auth).status_code==403


def test_local_and_smb_history_share_run_quota_and_duplicate_local_requests(environment):
    _,store,vault=environment;incident,job=operational(store,vault);configure(store,vault);now=time.time()
    request=dates(now,tier='local',archive_type='telemetry',query='first')
    history.search(store,vault,job,'m',request);history.search(store,vault,job,'m',request)
    assert len(store.rows("SELECT 1 FROM audit WHERE action='network_logs.ai_local_search'"))==1
    history.search(store,vault,job,'m',dates(now,query='smb'))
    for q in ('second','third'):history.search(store,vault,job,'m',dates(now,tier='local',query=q))
    with pytest.raises(ValueError,match='four'):history.search(store,vault,job,'m',dates(now,tier='local',query='fifth'))
    with pytest.raises(ValueError,match='four'):history.search(store,vault,job,'m',dates(now,query='fifth'))


def test_local_search_failure_is_unavailable_not_empty_history(environment,monkeypatch):
    _,store,vault=environment;incident,job=operational(store,vault)
    from aiticket import telemetry_archive as telemetry
    def failed(*args,**kwargs):raise OSError('private DB path')
    monkeypatch.setattr(telemetry,'local_search',failed)
    answer=history.search(store,vault,job,'m',dates(time.time(),tier='local',archive_type='telemetry'))
    assert answer['state']=='unavailable' and not answer['observed_facts']
    assert 'private DB path' not in json.dumps(answer)
