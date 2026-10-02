import time
from unittest.mock import patch,Mock
import pytest
from aiticket import ai,worklog,engine
from aiticket.host_admin import open_ticket
from test_codex_mode import configure


def test_work_sessions_exclude_queue_and_wait_and_resume(environment):
    _,store,vault=environment
    incident=configure(store,vault,command_tools=True)
    job_id=ai.request_job(store,vault,incident)
    job=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job_id,))[0]
    assert not worklog.view(store,incident)['sessions']
    with store.connect() as c:
        worklog.update_job(c,store,job,'running',100)
        worklog.update_job(c,store,job,'running',105)
        worklog.block(c,store,incident,job_id,'Need permission.',110)
        worklog.block(c,store,incident,job_id,'Need permission.',120)
        worklog.update_job(c,store,job,'running',125)
    sessions=store.rows('SELECT * FROM work_sessions')
    assert len(sessions)==1 and sessions[0]['ended']-sessions[0]['started']==10
    assert len(store.rows('SELECT * FROM ticket_blockers'))==1
    assert len(store.rows("SELECT * FROM deliveries WHERE event_key LIKE '%:blocker:%'"))==1
    with store.connect() as c:
        worklog.clear(c,incident,130)
        worklog.update_job(c,store,job,'running',130)
        worklog.update_job(c,store,job,'failed',140,'Adapter failed.')
    assert len(store.rows('SELECT * FROM work_sessions'))==2
    assert worklog.view(store,incident)['totals']['hermes']==20
    assert worklog.view(store,incident)['blocker']['reason']=='Adapter failed.'


def test_blocker_discord_public_link_and_stale_suppression(environment):
    from aiticket.worker import deliver
    _,store,vault=environment;incident=configure(store,vault)
    store.save('public_url','https://tickets.example.com/proxy')
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/fixture'))
    with store.connect() as c:
        worklog.block(c,store,incident,None,'Need the service name.',time.time())
        c.execute("UPDATE deliveries SET state='completed' WHERE event_key NOT LIKE '%:blocker:%'")
    job=engine.claim(store,'deliveries')
    with patch('aiticket.worker.requests.post',return_value=Mock(status_code=204)) as send:
        deliver(store,vault,job)
        text=send.call_args.kwargs['json']['content']
        assert 'Need the service name.' in text and 'https://tickets.example.com/proxy/incidents/'+incident in text
    with store.connect() as c:
        worklog.block(c,store,incident,None,'Need different details.',time.time())
        worklog.clear(c,incident,time.time())
    job=engine.claim(store,'deliveries')
    with patch('aiticket.worker.requests.post') as send:
        deliver(store,vault,job);send.assert_not_called()


def test_modes_optional_human_timer_and_resolution(signed_in):
    client,store,_,csrf=signed_in
    client.post('/hosts',data={'csrf':csrf,'name':'Host'})
    machine=store.rows('SELECT id FROM machines')[0]['id']
    response=client.post('/tickets/new',data={'csrf':csrf,'machine_id':machine,'title':'Issue','description':'Investigate','severity':'high','handling_mode':'paused'})
    incident=response.location.rsplit('/',1)[1]
    page=client.get(response.location)
    assert page.status_code==200 and b'AI handles it' in page.data and b'Work log' in page.data
    assert not store.rows('SELECT * FROM work_sessions')
    assert store.rows('SELECT owner,handling_mode FROM incident_control')[0]=={'owner':'user','handling_mode':'paused'}
    url='/incidents/'+incident+'/work'
    client.post(url,data={'csrf':csrf,'operation':'start'})
    client.post(url,data={'csrf':csrf,'operation':'start'})
    assert len(store.rows('SELECT * FROM work_sessions'))==1
    client.post('/incidents/'+incident+'/note',data={'csrf':csrf,'operation':'resolve','note':'Fixed the issue.'})
    assert store.rows('SELECT outcome,ended FROM work_sessions')[0]['outcome']=='Resolved'
    assert client.post(url,data={'csrf':csrf,'operation':'start'}).status_code==400


def test_public_url_validation():
    assert worklog.public_url('https://tickets.example.com/prefix/')=='https://tickets.example.com/prefix'
    for value in ('https://user:password@example.com','https://example.com/#fragment','javascript:alert(1)','https://example.com/?x=1'):
        with pytest.raises(ValueError):worklog.public_url(value)


def test_authenticated_ai_block_tool(environment):
    app,store,vault=environment;incident=configure(store,vault,command_tools=True)
    job_id=ai.request_job(store,vault,incident)
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job_id,))
    job=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job_id,))[0]
    response=app.test_client().post('/api/hermes/'+job_id+'/command',headers={'Authorization':'Bearer '+vault.decrypt(job['credential'])},json={'action':'block','summary':'What service should I inspect?'})
    assert response.status_code==200 and response.json['state']=='waiting_for_human'
    assert worklog.view(store,incident)['blocker']['reason']=='What service should I inspect?'


def test_reply_resumes_same_ticket_and_new_session(signed_in):
    client,store,vault,csrf=signed_in
    incident=configure(store,vault,command_tools=True,incident_runs=5,daily_runs=10)
    job_id=ai.request_job(store,vault,incident)
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='completed' WHERE id=?",(job_id,))
        worklog.start(c,incident,'hermes',100,job_id)
        worklog.block(c,store,incident,job_id,'Which service?',110)
    import uuid,json
    response=client.post('/incidents/'+incident+'/continue',data={'csrf':csrf,'request_id':str(uuid.uuid4()),'current_task':'Inspect the planner service.'})
    assert response.status_code==302
    jobs=store.rows('SELECT * FROM ai_jobs ORDER BY created')
    assert len(jobs)==2 and jobs[1]['incident_id']==incident
    assert json.loads(jobs[1]['evidence'])['administrator_task']=='Inspect the planner service.'
    assert worklog.view(store,incident)['blocker'] is None
    with store.connect() as c: worklog.update_job(c,store,jobs[1],'running',130)
    assert len(store.rows('SELECT * FROM work_sessions'))==2


def test_settings_save_public_url_and_blocker_opt_out(signed_in):
    client,store,_,csrf=signed_in
    response=client.post('/settings',data={'csrf':csrf,'section':'discord','public_url':'https://tickets.example.com','minimum':'low','recovery':'on'})
    assert response.status_code==302 and store.setting('public_url')=='https://tickets.example.com'
    assert store.setting('discord_blockers') is False
    assert client.post('/settings',data={'csrf':csrf,'section':'discord','public_url':'https://a.com/#bad','minimum':'low'}).status_code==400
    assert store.setting('public_url')=='https://tickets.example.com'
