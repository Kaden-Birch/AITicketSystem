import json
from datetime import datetime,timezone
from unittest.mock import patch
import pytest
from aiticket.policies import add_window,active,instant,notifications
from aiticket.engine import observe,claim
from aiticket.worker import deliver
from test_core import seed


def failure(store,now=100,severity='medium'):
    seed(store,severity=severity)
    for n in range(3):
        observe(store,'c',False,{},now=now+n)
    return store.rows('SELECT id FROM incidents')[0]['id']


def test_one_time_boundaries_and_preserved_observations(environment):
    _,store,_=environment
    seed(store)
    start=instant('2026-10-01T12:00','America/Edmonton')
    wid=add_window(store,'Work','m','once','America/Edmonton',{'start':'2026-10-01T12:00','end':'2026-10-01T13:00'})
    window=store.rows('SELECT * FROM maintenance_windows')[0]
    assert active(window,start) and not active(window,start+3600)
    for n in range(3):
        observe(store,'c',False,{},now=start+n)
    assert len(store.rows('SELECT * FROM observations'))==3 and not store.rows('SELECT * FROM incidents')
    observe(store,'c',False,{},now=start+3600)
    assert len(store.rows('SELECT * FROM incidents'))==1


def test_weekly_timezone_and_nonexistent_time(environment):
    _,store,_=environment
    add_window(store,'Weekly',None,'weekly','America/Edmonton',{'weekday':'3','start_time':'12:00','end_time':'13:00'})
    window=store.rows('SELECT * FROM maintenance_windows')[0]
    assert active(window,datetime(2024,10,3,18,30,tzinfo=timezone.utc).timestamp())
    assert not active(window,datetime(2024,10,4,18,30,tzinfo=timezone.utc).timestamp())
    # Same local schedule after the autumn clock change shifts its UTC time.
    assert active(window,datetime(2024,11,7,19,30,tzinfo=timezone.utc).timestamp())
    with pytest.raises(ValueError,match='does not exist'):
        instant('2024-03-10T02:30','America/Edmonton')


def test_reminders_dedup_coalesce_and_escalation_floor(environment):
    _,store,_=environment
    iid=failure(store)
    store.save('notification_policy',{'reminder_seconds':60,'escalate_after_seconds':60,'escalate_to':'high'})
    notifications(store,now=160)
    notifications(store,now=161)
    assert len(store.rows("SELECT * FROM deliveries WHERE event_key LIKE '%:reminder:%'"))==1
    assert len(store.rows("SELECT * FROM timeline WHERE kind='escalated'"))==1
    assert store.rows('SELECT severity FROM incidents')[0]['severity']=='high'
    observe(store,'c',False,{},now=162)
    assert store.rows('SELECT severity FROM incidents')[0]['severity']=='high'
    notifications(store,now=230)
    reminders=store.rows("SELECT * FROM deliveries WHERE event_key LIKE '%:reminder:%'")
    assert len(reminders)==2 and sum(r['state']=='pending' for r in reminders)==1
    assert len(store.rows("SELECT * FROM deliveries WHERE event_key LIKE '%:escalation-%'"))==1


def test_stale_and_silenced_incidents_do_not_remind(environment):
    _,store,_=environment
    failure(store)
    store.save('notification_policy',{'reminder_seconds':60,'escalate_after_seconds':60,'escalate_to':'critical'})
    notifications(store,now=1000)
    assert len(store.rows('SELECT * FROM deliveries'))==1
    observe(store,'c',False,{},now=1001)
    with store.connect() as c:
        c.execute('UPDATE incidents SET silence_until=2000')
    notifications(store,now=1002)
    assert len(store.rows('SELECT * FROM deliveries'))==1


def test_queued_delivery_pauses_during_maintenance(environment):
    _,store,vault=environment
    failure(store)
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/test'))
    job=claim(store,'deliveries',now=104)
    with store.connect() as c:
        c.execute('UPDATE incidents SET silence_until=200')
    with patch('aiticket.worker.time.time',return_value=105),patch('aiticket.worker.requests.post') as post:
        deliver(store,vault,job)
        post.assert_not_called()
    assert store.rows('SELECT state FROM deliveries')[0]['state']=='pending'


def test_policy_ui_validation_and_audit(signed_in):
    client,store,_,csrf=signed_in
    assert client.get('/policies').status_code==200
    assert client.post('/policies',data={'csrf':csrf,'operation':'notifications','reminder_seconds':'1'}).status_code==400
    assert not store.setting('notification_policy')
    assert client.post('/policies',data={'csrf':csrf,'operation':'notifications','reminder_seconds':'600','escalate_after_seconds':'3600','escalate_to':'critical'}).status_code==302
    assert store.rows("SELECT action FROM audit WHERE action NOT LIKE 'security.%'")[0]['action']=='settings.updated'
    iid=failure(store)
    assert client.post('/incidents/'+iid+'/silence',data={'csrf':csrf,'minutes':'60'}).status_code==302
    assert store.rows('SELECT silence_until FROM incidents')[0]['silence_until']>0
    assert client.post('/incidents/'+iid+'/silence',data={'csrf':csrf,'minutes':'0'}).status_code==302


def test_resolved_incident_supersedes_reminder_and_dispatch_rechecks_filters(environment):
    _,store,vault=environment
    failure(store)
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/test'))
    job=claim(store,'deliveries',now=104)
    store.save('discord_minimum','critical')
    with patch('aiticket.worker.requests.post') as post:
        deliver(store,vault,job)
        post.assert_not_called()
    assert store.rows('SELECT state FROM deliveries')[0]['state']=='superseded'


def test_parent_maintenance_suppresses_child(environment):
    _,store,_=environment
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,parent_id,created) VALUES('parent','Parent',NULL,1)")
    seed(store,parent='parent')
    start=instant('2026-10-01T12:00','UTC')
    add_window(store,'Parent work','parent','once','UTC',{'start':'2026-10-01T12:00','end':'2026-10-01T13:00'})
    for n in range(3):
        observe(store,'c',False,{},now=start+n)
    assert not store.rows('SELECT * FROM incidents')


def test_current_alberta_rules_use_bundled_timezone_data(environment):
    _,store,_=environment
    add_window(store,'Current Alberta',None,'weekly','America/Edmonton',{'weekday':'3','start_time':'12:00','end_time':'13:00'})
    window=store.rows('SELECT * FROM maintenance_windows')[0]
    assert active(window,datetime(2026,11,5,18,30,tzinfo=timezone.utc).timestamp())
    assert not active(window,datetime(2026,11,5,19,30,tzinfo=timezone.utc).timestamp())
