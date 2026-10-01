import json
import time
from unittest.mock import patch
import pytest
from aiticket.diagnostics import request_job,poll,complete,metric_probe
from aiticket.engine import observe
from aiticket.db import Store
from aiticket.security import digest
from test_core import seed


def agent(store,now):
    seed(store)
    with store.connect() as c:
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,sampled_at,telemetry,capabilities) VALUES(?,?,?,?,?,?,?)',('a','m',digest('fixture-token'),now,now,json.dumps({'cpu_percent':95,'memory_total_bytes':1000,'memory_available_bytes':500,'disk_total_bytes':100,'disk_free_bytes':2,'inode_total':100,'inode_free':2}),json.dumps({'operations':['process_summary','service_status','service_logs'],'services':['web']})))
    for n in range(3):
        observe(store,'c',False,{},now=now+n)
    return store.rows('SELECT id FROM incidents')[0]['id']


def test_jobs_durable_deduplicated_and_results_scoped(environment):
    _,store,_=environment
    iid=agent(store,100)
    job=request_job(store,'a',iid,'process_summary',now=100)
    assert request_job(store,'a',iid,'process_summary',now=101)==job
    resumed=Store(store.path)
    with resumed.connect() as c:
        first=poll(c,'a',102)[0]
    assert first['id']==job
    with resumed.connect() as c:
        assert not poll(c,'a',103)
    with resumed.connect() as c:
        second=poll(c,'a',193)[0]
    with pytest.raises(ValueError,match='superseded'):
        complete(store,'a',{'job_id':job,'lease_token':first['lease_token'],'status':'completed','output':'ok'},now=194)
    payload={'job_id':job,'lease_token':second['lease_token'],'status':'completed','output':'token=secret password=hidden'}
    assert complete(store,'a',payload,now=194)=='accepted'
    assert complete(store,'a',payload,now=195)=='duplicate'
    result=store.rows('SELECT result FROM diagnostic_jobs')[0]['result']
    assert 'secret' not in result and 'hidden' not in result
    assert len(store.rows("SELECT * FROM timeline WHERE kind='diagnostic_result'"))==1


def test_allowlist_expiry_revocation(environment):
    _,store,_=environment
    iid=agent(store,100)
    with pytest.raises(ValueError):
        request_job(store,'a',iid,'shell',now=100)
    with pytest.raises(ValueError):
        request_job(store,'a',iid,'service_logs','other',now=100)
    request_job(store,'a',iid,'service_status','web',now=100)
    with store.connect() as c:
        assert not poll(c,'a',701)
    assert store.rows('SELECT state FROM diagnostic_jobs')[0]['state']=='expired'
    with store.connect() as c:
        c.execute('UPDATE agents SET revoked=1')
    with pytest.raises(ValueError):
        request_job(store,'a',iid,'process_summary',now=702)


def test_metric_hysteresis_staleness_and_cache_semantics(environment):
    _,store,_=environment
    agent(store,100)
    config={'agent_id':'a','metric':'cpu_percent','fail_above':90,'recover_below':80,'sustain_seconds':60,'_check_id':'c'}
    with patch('aiticket.diagnostics.time.time',return_value=100):
        assert metric_probe(store,config)[0] is False
        config['metric']='memory_used_percent'
        assert metric_probe(store,config)[0] is True
        with store.connect() as c:
            c.execute('UPDATE agents SET telemetry=?',(json.dumps({'cpu_percent':85}),))
        config['metric']='cpu_percent'
        assert metric_probe(store,config)[0] is False # existing check is down; hysteresis applies
    with patch('aiticket.diagnostics.time.time',return_value=500):
        assert metric_probe(store,config)[0] is None


def test_sustained_threshold_unique_samples_and_unknown_gap(environment):
    _,store,_=environment
    seed(store)
    with store.connect() as c:
        c.execute('UPDATE checks SET kind=?,config=?,fail_after=1,recover_after=1',('agent_metric',json.dumps({'sustain_seconds':60})))
    observe(store,'c',False,{'sampled_at':100},now=100)
    observe(store,'c',False,{'sampled_at':100},now=160)
    assert not store.rows('SELECT * FROM incidents')
    assert len(store.rows('SELECT * FROM observations'))==1
    observe(store,'c',None,{'reason':'stale'},now=200)
    observe(store,'c',False,{'sampled_at':210},now=210)
    observe(store,'c',False,{'sampled_at':270},now=270)
    assert len(store.rows('SELECT * FROM incidents'))==1


def test_result_api_and_incident_gui(signed_in):
    client,store,_,csrf=signed_in
    now=time.time()
    iid=agent(store,now)
    assert client.get('/resources').status_code==200
    assert client.post('/incidents/'+iid+'/diagnostics',data={'csrf':csrf,'agent_id':'a','operation':'process_summary'}).status_code==302
    response=client.post('/api/agent/heartbeat',headers={'Authorization':'Bearer fixture-token'},json={'event_id':'e','sampled_at':now,'telemetry':{},'capabilities':{'operations':['process_summary'],'services':[]}})
    job=response.json['jobs'][0]
    payload={'job_id':job['id'],'lease_token':job['lease_token'],'status':'completed','output':'processes bounded'}
    assert client.post('/api/agent/result',json=payload).status_code==401
    assert client.post('/api/agent/result',headers={'Authorization':'Bearer fixture-token'},json=payload).status_code==200
    response=client.get('/incidents/'+iid)
    assert response.status_code==200 and b'processes bounded' in response.data


def test_idle_agent_jobs_expire_in_worker(environment):
    from aiticket.worker import tick
    _,store,vault=environment
    iid=agent(store,100)
    request_job(store,'a',iid,'process_summary',now=100)
    with store.connect() as c:
        c.execute('UPDATE checks SET enabled=0')
        c.execute("UPDATE deliveries SET state='completed'")
    with patch('aiticket.worker.time.time',return_value=701):
        tick(store,vault)
    assert store.rows('SELECT state FROM diagnostic_jobs')[0]['state']=='expired'
