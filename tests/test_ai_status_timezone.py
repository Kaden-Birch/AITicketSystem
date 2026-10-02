import time
from datetime import datetime,timezone
from aiticket import ai,worklog
from test_codex_mode import configure


def test_no_phantom_sessions_after_resolution(environment):
    _,store,vault=environment;incident=configure(store,vault,command_tools=True)
    job_id=ai.request_job(store,vault,incident)
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job_id,))
        worklog.start(c,incident,'hermes',100,job_id)
        c.execute("UPDATE incidents SET status='Resolved',closed=160 WHERE id=?",(incident,))
        worklog.end(c,incident,'hermes','Resolved',160,'Monitoring confirmed recovery.')
    for moment in (161,162,163):worklog.tick(store,moment)
    assert len(store.rows('SELECT id FROM work_sessions'))==1
    assert worklog.view(store,incident)['totals']['hermes']==60
    with store.connect() as c:
        # Existing bug-generated records remain stored, but do not pollute the UI.
        c.execute("INSERT INTO work_sessions(id,incident_id,job_id,actor,started,ended,outcome) VALUES('legacy-zero',?,?, 'hermes',161,161,'Resolved')",(incident,job_id))
    assert len(worklog.view(store,incident)['sessions'])==1


def test_automatic_reason_and_severity_filter(environment):
    _,store,vault=environment;incident=configure(store,vault)
    row=store.rows('SELECT * FROM incidents WHERE id=?',(incident,))[0]
    bridge=store.setting('hermes_config');bridge.update(enabled=True,automatic=True,minimum='high');store.save('hermes_config',bridge)
    with store.connect() as c:c.execute("UPDATE incidents SET severity='medium' WHERE id=?",(incident,))
    row['severity']='medium'
    assert 'below the High minimum' in ai.automatic_status(store,row)
    assert ai.automatic_tick(store,vault)==0
    bridge['minimum']='medium';store.save('hermes_config',bridge)
    assert ai.automatic_tick(store,vault)==1
    assert 'pending' in ai.automatic_status(store,row)


def test_mountain_time_dst_and_settings(signed_in):
    client,store,_,csrf=signed_in;app=client.application
    timestamp=app.jinja_env.filters['timestamp']
    summer=datetime(2026,10,2,17,32,19,tzinfo=timezone.utc).timestamp()
    winter=datetime(2026,1,2,17,32,19,tzinfo=timezone.utc).timestamp()
    assert timestamp(summer)=='2026-10-02 11:32:19 MDT'
    assert timestamp(winter)=='2026-01-02 10:32:19 MST'
    assert client.post('/settings',data={'csrf':csrf,'section':'appearance','display_timezone':'UTC'}).status_code==302
    assert timestamp(summer)=='2026-10-02 17:32:19 UTC'
    assert client.post('/settings',data={'csrf':csrf,'section':'appearance','display_timezone':'Not/AZone'}).status_code==400
    assert store.setting('display_timezone')=='UTC'
