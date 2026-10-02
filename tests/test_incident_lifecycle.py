import json,time
from unittest.mock import patch,Mock
from aiticket import ai,engine
from aiticket.host_admin import open_ticket
from test_codex_mode import configure
from test_core import seed


def test_automatic_manual_ticket_and_blocked_incident_do_not_starve_others(environment):
    _,store,vault=environment
    first=configure(store,vault,automatic=True,incident_runs=3,daily_runs=10)
    with store.connect() as c:c.execute("UPDATE incidents SET severity='high' WHERE id=?",(first,))
    manual=open_ticket(store,'m','Restart request','Investigate this machine.','high')
    original=ai.request_job
    def admission(s,v,i,**kwargs):
        if i==first: raise ValueError('Fixture blocked target')
        return original(s,v,i,**kwargs)
    with patch('aiticket.ai.request_job',side_effect=admission): assert ai.automatic_tick(store,vault)==1
    assert store.rows('SELECT incident_id FROM ai_jobs')==[{'incident_id':manual}]
    assert store.rows("SELECT text FROM timeline WHERE incident_id=? AND kind='ai_auto_blocked'",(first,))==[{'text':'Fixture blocked target'}]
    with patch('aiticket.ai.request_job',side_effect=admission): assert ai.automatic_tick(store,vault)==0
    assert len(store.rows("SELECT text FROM timeline WHERE kind='ai_auto_blocked'"))==1


def test_automatic_queue_respects_opt_out(environment):
    _,store,vault=environment;configure(store,vault,automatic=False)
    assert ai.automatic_tick(store,vault)==0 and not store.rows('SELECT id FROM ai_jobs')


def test_ai_resolution_waits_for_successful_run_and_fresh_healthy_checks(environment):
    app,store,vault=environment;incident=configure(store,vault,command_tools=True)
    # Manual tickets have no automatic probe of their own; tagged host checks
    # provide the independent evidence used to verify the repair.
    manual=open_ticket(store,'m','Host issue','Restore host health.','high')
    job=ai.request_job(store,vault,manual)
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
        c.execute("INSERT INTO command_policies VALUES('m',1,'immediate',1,0,120,8192,1)")
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    auth={'Authorization':'Bearer '+vault.decrypt(row['credential'])}
    response=app.test_client().post('/api/hermes/'+job+'/command',json={'action':'resolve','summary':'Restarted the failed service.'},headers=auth)
    assert response.status_code==200 and response.json['state']=='verification_pending'
    engine.resolution_tick(store)
    assert store.rows('SELECT closed FROM incidents WHERE id=?',(manual,))[0]['closed'] is None
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='completed' WHERE id=?",(job,))
    engine.resolution_tick(store)
    assert store.rows('SELECT closed FROM incidents WHERE id=?',(manual,))[0]['closed'] is None
    for n in range(3):engine.observe(store,'c',True,{},now=time.time()+n)
    engine.resolution_tick(store,now=time.time()+3)
    resolved=store.rows('SELECT * FROM incidents WHERE id=?',(manual,))[0]
    assert resolved['status']=='Resolved' and resolved['closed'] is not None
    assert 'Restarted the failed service' in json.loads(resolved['report'])['recovery_summary']
    assert len(store.rows("SELECT id FROM deliveries WHERE event_key=?",(manual+':recovery',)))==1
    engine.resolution_tick(store,now=time.time()+4)
    assert len(store.rows("SELECT id FROM deliveries WHERE event_key=?",(manual+':recovery',)))==1


def test_recovery_discord_includes_brief_summary(environment):
    from aiticket.worker import deliver
    _,store,vault=environment;seed(store,severity='high')
    for n in range(3):engine.observe(store,'c',False,{},now=100+n)
    for n in range(3):engine.observe(store,'c',True,{},now=104+n)
    recovery=store.rows("SELECT id FROM deliveries WHERE event_key LIKE '%:recovery'")[0]['id']
    with store.connect() as c:
        c.execute("UPDATE deliveries SET state='completed' WHERE id<>?",(recovery,))
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/fixture'))
    job=engine.claim(store,'deliveries',now=108)
    with patch('aiticket.worker.requests.post',return_value=Mock(status_code=204)) as post:
        deliver(store,vault,job)
        text=post.call_args.kwargs['json']['content']
        assert 'Resolved' in text and 'Recovered:' in text and 'healthy' in text
