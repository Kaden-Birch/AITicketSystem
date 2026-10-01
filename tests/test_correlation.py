import json
import pytest
from aiticket.engine import observe


def seed(store,guest_severity='high'):
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,parent_id,created) VALUES('m','Guest',NULL,1)")
        for id,kind,config,severity in [('guest','proxmox',{'resource':'qemu/209','expected':'running'},guest_severity),('agent','agent',{'agent_id':'a'},'medium'),('http','http',{'url':'https://192.0.2.10'},'medium')]:
            c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,?,?,60,1,1,?)',(id,'m',id,kind,json.dumps(config),severity))


@pytest.mark.parametrize('order',[('guest','agent'),('agent','guest')])
def test_compatible_sources_one_incident_and_independent_recovery(environment,order):
    _,store,_=environment
    seed(store)
    evidence={'guest':{'status':'stopped'},'agent':{'heartbeat_age_seconds':200}}
    for n,check in enumerate(order):
        observe(store,check,False,evidence[check],now=10+n)
    incidents=store.rows('SELECT * FROM incidents')
    assert len(incidents)==1 and incidents[0]['severity']=='high'
    iid=incidents[0]['id']
    report=json.loads(incidents[0]['report'])
    assert len(report['sources'])==2 and report['cause']=='Unknown'
    assert len(store.rows('SELECT * FROM incident_observations'))==2
    observe(store,'guest',True,{'status':'running'},now=12)
    assert store.rows('SELECT closed FROM incidents')[0]['closed'] is None
    observe(store,'agent',True,{'heartbeat_age_seconds':0},now=13)
    assert store.rows('SELECT closed FROM incidents')[0]['closed']==13
    assert len(store.rows('SELECT * FROM deliveries WHERE event_key LIKE ?',('%:recovery',)))==1


def test_unrelated_http_separate_with_uncertain_link(environment):
    _,store,_=environment
    seed(store)
    observe(store,'guest',False,{'status':'stopped'},now=10)
    observe(store,'http',False,{'status_code':503},now=11)
    assert len(store.rows('SELECT * FROM incidents'))==2
    assert len(store.rows('SELECT * FROM incident_links'))==1


def test_failed_api_not_proof_of_guest_down(environment):
    _,store,_=environment
    seed(store)
    observe(store,'guest',False,{'error_type':'ConnectionError'},now=10)
    observe(store,'agent',False,{'heartbeat_age_seconds':200},now=11)
    assert len(store.rows('SELECT * FROM incidents'))==2


def test_same_addresses_do_not_merge_machines(environment):
    _,store,_=environment
    seed(store)
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,parent_id,created) VALUES('other','Guest',NULL,1)")
        c.execute('UPDATE checks SET machine_id=? WHERE id=?',('other','agent'))
    observe(store,'guest',False,{'status':'stopped'},now=10)
    observe(store,'agent',False,{'heartbeat_age_seconds':200},now=11)
    assert len(store.rows('SELECT * FROM incidents'))==2


def test_stale_source_prevents_premature_resolution(environment):
    _,store,_=environment
    seed(store)
    observe(store,'guest',False,{'status':'stopped'},now=10)
    observe(store,'agent',False,{},now=11)
    observe(store,'guest',True,{'status':'running'},now=12)
    observe(store,'agent',True,{},now=300)
    assert store.rows('SELECT closed FROM incidents')[0]['closed'] is None
    report=json.loads(store.rows('SELECT report FROM incidents')[0]['report'])
    assert report['observed']=='unknown'
    observe(store,'guest',True,{'status':'running'},now=301)
    assert store.rows('SELECT closed FROM incidents')[0]['closed']==301


def test_old_stopped_evidence_does_not_merge_agent_failure(environment):
    _,store,_=environment
    seed(store)
    observe(store,'guest',False,{'status':'stopped'},now=10)
    observe(store,'agent',False,{},now=400)
    assert len(store.rows('SELECT * FROM incidents'))==2


def test_severity_crossing_notification_filter(environment):
    _,store,_=environment
    seed(store)
    store.save('discord_minimum','high')
    observe(store,'agent',False,{},now=10)
    assert not store.rows('SELECT * FROM deliveries')
    observe(store,'guest',False,{'status':'stopped'},now=11)
    assert len(store.rows('SELECT * FROM incidents'))==1
    assert len(store.rows('SELECT * FROM deliveries'))==1
    assert store.rows('SELECT * FROM deliveries')[0]['event_key'].endswith(':severity-high')


def test_uncertain_link_reverse_order(environment):
    _,store,_=environment
    seed(store)
    observe(store,'http',False,{'status_code':503},now=10)
    observe(store,'guest',False,{'status':'stopped'},now=11)
    assert len(store.rows('SELECT * FROM incidents'))==2
    assert len(store.rows('SELECT * FROM incident_links'))==1


def test_correlated_report_renders_both_sources(signed_in):
    client,store,_,_=signed_in
    seed(store)
    observe(store,'guest',False,{'status':'stopped'},now=10)
    observe(store,'agent',False,{'heartbeat_age_seconds':200},now=11)
    iid=store.rows('SELECT id FROM incidents')[0]['id']
    response=client.get('/incidents/'+iid)
    assert response.status_code==200
    assert b'Source-specific evidence' in response.data
    assert b'heartbeat_age_seconds' in response.data and b'stopped' in response.data
