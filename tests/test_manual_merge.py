import json
from unittest.mock import patch
import pytest
from aiticket.engine import observe
from aiticket.correlation import merge
from test_correlation import seed


def pair(store):
    seed(store)
    observe(store,'guest',False,{'status':'stopped'},now=10)
    observe(store,'http',False,{'status_code':503},now=11)
    return {r['check_id']:r['id'] for r in store.rows('SELECT * FROM incidents')}


def test_pressure_relationships_are_bounded_by_identity_and_time(environment):
    _,store,_=environment
    seed(store)
    with store.connect() as c:
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after) VALUES('cpu','m','CPU','agent_metric','{}',60,1)")
    observe(store,'cpu',False,{'sampled_at':10,'value':99},now=10)
    observe(store,'http',False,{'status_code':503},now=11)
    assert len(store.rows('SELECT * FROM incidents'))==2
    assert 'resource pressure' in store.rows('SELECT reason FROM incident_links')[0]['reason']
    observe(store,'agent',False,{},now=400)
    assert len(store.rows('SELECT * FROM incident_links'))==1


def test_merge_preserves_history_and_requires_every_source_recovery(environment):
    _,store,_=environment
    ids=pair(store)
    original=store.rows('SELECT * FROM timeline WHERE incident_id=?',(ids['http'],))
    merge(store,ids['http'],ids['guest'],'Same application outage',now=12)
    assert store.rows('SELECT merged_into FROM incidents WHERE id=?',(ids['http'],))[0]['merged_into']==ids['guest']
    assert len(store.rows('SELECT * FROM incident_sources WHERE incident_id=?',(ids['guest'],)))==2
    assert store.rows('SELECT * FROM timeline WHERE id=?',(original[0]['id'],))==original
    observe(store,'guest',True,{'status':'running'},now=13)
    assert store.rows('SELECT closed FROM incidents WHERE id=?',(ids['guest'],))[0]['closed'] is None
    observe(store,'http',True,{'status_code':200},now=14)
    assert store.rows('SELECT closed FROM incidents WHERE id=?',(ids['guest'],))[0]['closed']==14
    assert len(store.rows('SELECT * FROM incidents'))==2
    with pytest.raises(Exception,match='immutable'):
        with store.connect() as c:
            c.execute('DELETE FROM incident_merges')
    with pytest.raises(ValueError):
        merge(store,ids['http'],ids['guest'],'again')


def test_cross_machine_and_outstanding_work_rejected(environment):
    _,store,_=environment
    ids=pair(store)
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('other','Other',1)")
        c.execute("UPDATE incidents SET machine_id='other' WHERE id=?",(ids['http'],))
    with pytest.raises(ValueError,match='same'):
        merge(store,ids['http'],ids['guest'],'Wrong identity')
    with store.connect() as c:
        c.execute("UPDATE incidents SET machine_id='m' WHERE id=?",(ids['http'],))
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('a','m','fixture')")
        c.execute("INSERT INTO diagnostic_jobs(id,agent_id,incident_id,operation,parameters,state,created,expires) VALUES('d','a',?,'process_summary','{}','pending',1,999)",(ids['http'],))
    with pytest.raises(ValueError,match='outstanding'):
        merge(store,ids['http'],ids['guest'],'Busy',now=12)
    assert not store.rows('SELECT * FROM incident_merges')


def test_merge_ui_requires_confirmation(signed_in):
    client,store,_,csrf=signed_in
    ids=pair(store)
    data={'csrf':csrf,'source_id':ids['http'],'reason':'Related outage'}
    assert client.post('/incidents/'+ids['guest']+'/merge',data=data).status_code==400
    data['confirm']='yes'
    assert client.post('/incidents/'+ids['guest']+'/merge',data=data).status_code==302
    assert b'continuing incident' in client.get('/incidents/'+ids['http']).data


def test_merge_severity_crossing_retains_notification(environment):
    _,store,_=environment
    store.save('discord_minimum','high')
    ids=pair(store)
    merge(store,ids['guest'],ids['http'],'Same failed application',now=12)
    events=store.rows("SELECT * FROM deliveries WHERE incident_id=? AND state='pending'",(ids['http'],))
    assert len(events)==1 and events[0]['event_key'].endswith(':severity-high')
