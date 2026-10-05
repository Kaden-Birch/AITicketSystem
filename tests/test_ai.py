import concurrent.futures
import json
import time
from unittest.mock import patch
import pytest
from aiticket import ai
from aiticket.app import AI_DEFAULTS
from aiticket.engine import observe
from test_core import seed


def configured(store, vault):
    cfg = {**AI_DEFAULTS, 'model': 'fixture-model', 'triage_tokens': 20000, 'incident_tokens': 40000, 'daily_tokens': 50000, 'monthly_tokens': 100000, 'input_price': 2.0, 'output_price': 4.0}
    store.save_many({'ai_config': cfg, 'hermes_config': {**ai.BRIDGE_DEFAULTS, 'url': 'https://192.0.2.20', 'enabled': True, 'runtime_verified': True}, 'ai_provider': {**ai.PROVIDER_DEFAULTS, 'url': 'https://192.0.2.30/v1', 'verified': True, 'input_overhead': 64, 'verified_model': cfg['model']}, 'hermes_secret': vault.encrypt('bridge-fixture-secret'), 'ai_provider_secret': vault.encrypt('provider-fixture-secret')})
    seed(store)
    for n in range(3):
        observe(store, 'c', False, {'reason': 'fixture failure'}, now=time.time()+n)
    return store.rows('SELECT id FROM incidents')[0]['id'], cfg


def running(store, vault):
    incident, cfg = configured(store, vault)
    job_id = ai.request_job(store, vault, incident)
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='running' WHERE id=?", (job_id,))
    return incident, job_id, cfg


def payload():
    return {'model': 'fixture-model', 'messages': [{'role': 'user', 'content': 'Untrusted evidence'}], 'max_tokens': 100, 'stream': False}


def test_disabled_no_job_or_network(environment):
    _, store, vault = environment
    with patch('aiticket.ai.requests.request') as request:
        with pytest.raises(ValueError, match='disabled'):
            ai.request_job(store, vault, 'missing')
        assert ai.tick(store, vault) is False
        request.assert_not_called()
    assert not store.rows('SELECT * FROM ai_jobs')


def test_runtime_gate_and_zero_allowance(environment):
    _, store, vault = environment
    incident, cfg = configured(store, vault)
    bridge = store.setting('hermes_config')
    bridge['runtime_verified'] = False
    store.save('hermes_config', bridge)
    with pytest.raises(ValueError):
        ai.request_job(store, vault, incident)
    bridge['runtime_verified'] = True
    store.save('hermes_config', bridge)
    for key in ('triage_tokens', 'incident_tokens', 'daily_tokens', 'monthly_tokens', 'daily_cost', 'monthly_cost', 'max_turns', 'input_price', 'output_price'):
        store.save('ai_config', {**cfg, key: 0})
        with pytest.raises(ValueError):
            ai.request_job(store, vault, incident)
    assert not store.rows('SELECT * FROM ai_jobs')


def test_idempotent_queue_and_severity_filter(environment):
    _, store, vault = environment
    incident, _ = configured(store, vault)
    assert ai.request_job(store, vault, incident, automatic=True) is None
    job = ai.request_job(store, vault, incident)
    assert ai.request_job(store, vault, incident)==job
    assert len(store.rows('SELECT * FROM ai_jobs'))==1
    assert 'provider-fixture-secret' not in store.rows('SELECT evidence FROM ai_jobs')[0]['evidence']


def test_atomic_reservations_block_parallel_calls(environment):
    _, store, vault = environment
    _, job, _ = running(store, vault)
    def attempt():
        try:
            return ai.admit(store, job, payload())[0]
        except ValueError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda _: attempt(), range(4)))
    assert sum(r is not None for r in results)==1
    assert ai.meter(store)['held']==1
    assert ai.meter(store)['day']['tokens']>100


@pytest.mark.parametrize('limit,value', [('triage_tokens',1), ('incident_tokens',1), ('daily_tokens',1), ('monthly_tokens',1), ('daily_cost',0.000001), ('monthly_cost',0.000001)])
def test_all_ceiling_types_reject_before_provider(environment, limit, value):
    _, store, vault = environment
    _, job, cfg = running(store, vault)
    store.save('ai_config', {**cfg, limit: value})
    with patch('aiticket.ai.requests.post') as post:
        with pytest.raises(ValueError, match='allowance'):
            ai.model_call(store, vault, job, payload())
        post.assert_not_called()
    assert not store.rows('SELECT * FROM ai_calls')


def test_usage_reconcile_cached_and_turn_limit(environment):
    _, store, vault = environment
    incident, job, cfg = running(store, vault)
    store.save('ai_config', {**cfg, 'max_turns': 1})
    call, _, _, _ = ai.admit(store, job, payload())
    assert ai.reconcile(store, call, {'prompt_tokens': 20, 'completion_tokens': 10, 'prompt_tokens_details': {'cached_tokens': 5}}, cfg)
    meter=ai.meter(store, incident)
    assert meter['incident']['tokens']==30 and meter['incident']['microdollars']==80
    assert meter['held']==0
    with pytest.raises(ValueError, match='count'):
        ai.admit(store, job, payload())


def test_unknown_usage_retained_across_cancel_expiry_and_day(environment):
    _, store, vault = environment
    _, job, cfg = running(store, vault)
    call, _, _, _ = ai.admit(store, job, payload())
    assert not ai.reconcile(store, call, {}, cfg)
    ai.cancel(store, job)
    assert ai.meter(store)['held']==1
    another=ai.request_job(store, vault, store.rows('SELECT id FROM incidents')[0]['id'])
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='running',expires=? WHERE id=?", (time.time()+100000, another))
    with pytest.raises(ValueError, match='unknown usage'):
        ai.admit(store, another, payload(), now=time.time()+86400)


def test_violation_disables_provider_and_preserves_actual_usage(environment):
    _, store, vault = environment
    _, job, cfg = running(store, vault)
    call, _, _, _=ai.admit(store,job,payload())
    assert not ai.reconcile(store,call,{'prompt_tokens':9999,'completion_tokens':1},cfg)
    assert store.setting('ai_provider')['verified'] is False
    assert ai.meter(store)['day']['tokens']==10000
    with pytest.raises(ValueError):
        ai.admit(store,job,payload())


@pytest.mark.parametrize('field,value', [('tools',[{'type':'function'}]),('stream',True),('model','wrong-model'),('messages',[{'role':'user','content':{'image':'x'}}]),('messages',[{'role':'tool','content':'x'}]),('max_tokens',True)])
def test_tool_model_and_payload_restrictions(environment,field,value):
    _,store,vault=environment
    _,job,_=running(store,vault)
    with pytest.raises(ValueError):
        ai.admit(store,job,{**payload(),field:value})
    assert not store.rows('SELECT * FROM ai_calls')


def test_signed_status_freshness_and_duplicate_completion(environment):
    _,store,vault=environment
    incident,job,cfg=running(store,vault)
    call,_,_,_=ai.admit(store,job,payload())
    ai.reconcile(store,call,{'prompt_tokens':20,'completion_tokens':10},cfg)
    document={'execution_id':job,'state':'completed','summary':'Hypothesis only; secret=not-for-output'}
    body=json.dumps(document).encode()
    headers=ai.hermes_headers('fixture-secret',body,job,now=1000)
    assert ai.authenticate('fixture-secret',body,headers,now=1001)
    assert not ai.authenticate('fixture-secret',body+b'x',headers,now=1001)
    assert not ai.authenticate('fixture-secret',body,headers,now=1400)
    ai.apply_status(store,job,document)
    ai.apply_status(store,job,document)
    assert len(store.rows("SELECT * FROM timeline WHERE kind='ai_completed'"))==1
    assert 'not-for-output' not in store.rows('SELECT summary FROM ai_jobs')[0]['summary']
    assert store.rows('SELECT closed FROM incidents')[0]['closed'] is None


def test_ambiguous_dispatch_only_polls(environment):
    _,store,vault=environment
    incident,_=configured(store,vault)
    job=ai.request_job(store,vault,incident,now=1000)
    methods=[]
    def fail(vault,job,method,path,*args,**kwargs):
        methods.append((method,path))
        raise ValueError('Unknown')
    with patch('aiticket.ai.bridge_request',side_effect=fail):
        ai.tick(store,vault,now=1001)
        ai.tick(store,vault,now=1100)
        ai.tick(store,vault,now=1200)
    assert [m[0] for m in methods]==['POST','GET','GET']
    assert store.rows('SELECT state FROM ai_jobs')[0]['state']=='unknown'
    blockers=store.rows('SELECT * FROM ticket_blockers WHERE incident_id=? AND cleared IS NULL',(incident,))
    assert len(blockers)==1 and 'interrupted' in blockers[0]['reason']


def test_bridge_not_found_fences_late_execution(environment):
    _,store,vault=environment
    _,job,_=running(store,vault)
    ai.apply_status(store,job,{'execution_id':job,'state':'not_found'})
    with pytest.raises(ValueError):
        ai.admit(store,job,payload())


def test_completion_requires_metered_call(environment):
    _,store,vault=environment
    _,job,_=running(store,vault)
    with pytest.raises(ValueError,match='metered'):
        ai.apply_status(store,job,{'execution_id':job,'state':'completed','summary':'invented'})


def test_gateway_auth_and_ui(signed_in):
    client,store,vault,csrf=signed_in
    incident,job,cfg=running(store,vault)
    assert client.get('/hermes').status_code==200
    assert client.get('/incidents/'+incident).status_code==200
    assert client.post('/api/hermes/'+job+'/v1/chat/completions',json=payload()).status_code==401
    token=vault.decrypt(store.rows('SELECT credential FROM ai_jobs')[0]['credential'])
    headers={'Authorization':'Bearer '+token}
    assert client.get('/api/hermes/'+job+'/v1/models',headers=headers).json['data'][0]['id']=='fixture-model'
    assert client.post('/hermes',data={'operation':'disable'}).status_code==403
    assert client.post('/hermes',data={'operation':'disable','csrf':csrf}).status_code==302
    assert client.post('/api/hermes/'+job+'/v1/chat/completions',json=payload(),headers=headers).status_code==400


def test_model_response_missing_usage_does_not_release(environment):
    _,store,vault=environment
    _,job,_=running(store,vault)
    with patch('aiticket.ai.requests.post') as post:
        response=post.return_value.__enter__.return_value
        response.status_code=200
        response.iter_content.return_value=[json.dumps({'choices':[{'message':{'content':'hypothesis'}}]}).encode()]
        with pytest.raises(ValueError):
            ai.model_call(store,vault,job,payload())
    assert ai.meter(store)['held']==1
    assert post.call_args.kwargs['allow_redirects'] is False
    assert post.call_args.kwargs['verify'] is True


def test_key_rotation_preserves_ai_credentials(environment,tmp_path):
    from aiticket.administration import rotate_key
    _,store,vault=environment
    _,job,_=running(store,vault)
    token=vault.decrypt(store.rows('SELECT credential FROM ai_jobs')[0]['credential'])
    new=rotate_key(store,vault,tmp_path/'next.key')
    assert new.decrypt(store.setting('hermes_secret'))=='bridge-fixture-secret'
    assert new.decrypt(store.setting('ai_provider_secret'))=='provider-fixture-secret'
    assert new.decrypt(store.rows('SELECT credential FROM ai_jobs')[0]['credential'])==token
    assert new.decrypt(store.rows('SELECT bridge_secret FROM ai_jobs')[0]['bridge_secret'])=='bridge-fixture-secret'


def test_gateway_success_reconciles_and_redacts(environment):
    _,store,vault=environment
    _,job,_=running(store,vault)
    with patch('aiticket.ai.requests.post') as post:
        response=post.return_value.__enter__.return_value
        response.status_code=200
        response.iter_content.return_value=[json.dumps({'choices':[{'message':{'content':'Hypothesis token=secret-value'}}],'usage':{'prompt_tokens':20,'completion_tokens':10,'prompt_tokens_details':{'cached_tokens':5}}}).encode()]
        result=ai.model_call(store,vault,job,payload())
    assert result['usage']['prompt_tokens']==20
    assert 'secret-value' not in result['choices'][0]['message']['content']
    assert ai.meter(store)['held']==0


def test_manual_usage_reconciliation_requires_inactive_execution(environment):
    _,store,vault=environment
    _,job,cfg=running(store,vault)
    call,_,_,_=ai.admit(store,job,payload(),now=time.time()-100)
    reported={'prompt_tokens':20,'completion_tokens':10}
    assert not ai.reconcile(store,call,reported,{},manual=True)
    ai.cancel(store,job)
    assert ai.reconcile(store,call,reported,{},manual=True)
    assert store.rows("SELECT * FROM audit WHERE action='ai.manual_usage_override'")


def test_expired_and_resolved_jobs_do_not_call_bridge(environment):
    _,store,vault=environment
    incident,_=configured(store,vault)
    job=ai.request_job(store,vault,incident,now=1000)
    with patch('aiticket.ai.bridge_request') as request:
        ai.tick(store,vault,now=5000)
        request.assert_not_called()
    assert store.rows('SELECT state FROM ai_jobs')[0]['state']=='expired'
    assert store.rows('SELECT * FROM ticket_blockers WHERE incident_id=? AND cleared IS NULL',(incident,))
    job=ai.request_job(store,vault,incident)
    with store.connect() as c:
        c.execute("UPDATE incidents SET status='Resolved' WHERE id=?",(incident,))
    with patch('aiticket.ai.bridge_request') as request:
        ai.tick(store,vault)
        request.assert_not_called()
    assert store.rows('SELECT state FROM ai_jobs WHERE id=?',(job,))[0]['state']=='cancelled'


def test_unknown_status_does_not_storm_timeline(environment):
    _,store,vault=environment
    _,job,_=running(store,vault)
    document={'execution_id':job,'state':'interrupted','summary':'Interrupted'}
    ai.apply_status(store,job,document)
    ai.apply_status(store,job,document)
    assert len(store.rows("SELECT * FROM timeline WHERE kind='ai_unknown'"))==1


def test_evidence_snapshot_redacts_structured_secrets():
    snapshot=ai.evidence_snapshot({'evidence':{'api_key':'secret-value','reason':'token=another-secret'},'check':'normal'})
    assert 'secret-value' not in json.dumps(snapshot)
    assert 'another-secret' not in json.dumps(snapshot)


def test_enable_checks_connection_automatically(signed_in):
    client,store,vault,csrf=signed_in
    configured(store,vault)
    bridge={**store.setting('hermes_config'),'enabled':False,'runtime_verified':False}
    store.save('hermes_config',bridge)
    with patch('aiticket.ai.bridge_request',side_effect=ValueError('offline')):
        response=client.post('/hermes',data={'csrf':csrf,'operation':'enable'},follow_redirects=True)
    assert response.status_code==200 and b'Cannot connect' in response.data
    assert store.setting('hermes_config')['enabled'] is False
    capability={'version':1,'tools':[],'compatible':True,'model_gateway':True,'workspace_modes':['advice']}
    with patch('aiticket.ai.bridge_request',return_value=capability):
        assert client.post('/hermes',data={'csrf':csrf,'operation':'enable'}).status_code==302
    assert store.setting('hermes_config')['enabled'] is True
    assert store.setting('hermes_validation')['workspace_modes']==['advice']


def test_model_change_requires_provider_reverification(environment):
    _,store,vault=environment
    _,job,cfg=running(store,vault)
    store.save('ai_config',{**cfg,'model':'another-model'})
    with pytest.raises(ValueError,match='Revalidate'):
        ai.admit(store,job,payload())


def test_manual_reconcile_uses_original_prices(environment):
    _,store,vault=environment
    _,job,cfg=running(store,vault)
    call,_,_,_=ai.admit(store,job,payload(),now=time.time()-100)
    ai.cancel(store,job)
    store.save('ai_config',{**cfg,'input_price':999,'output_price':999})
    assert ai.reconcile(store,call,{'prompt_tokens':20,'completion_tokens':10},{},manual=True)
    assert store.rows('SELECT cost_actual FROM ai_calls')[0]['cost_actual']==80


def test_schema_seven_upgrade_preserves_settings(tmp_path):
    import sqlite3
    from aiticket.db import SCHEMA,Store
    from aiticket.migrations import MIGRATIONS
    path=tmp_path/'seven.db'
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        for version in range(2,8):
            for statement in MIGRATIONS[version]:
                c.execute(statement)
        c.execute('INSERT INTO schema_version VALUES(7)')
        c.execute('INSERT INTO settings VALUES(?,?)',('existing',json.dumps('preserved')))
    store=Store(path)
    assert store.setting('existing')=='preserved'
    assert store.rows('SELECT version FROM schema_version')==[{'version': __import__('aiticket.migrations',fromlist=['CURRENT_VERSION']).CURRENT_VERSION}]
    assert store.rows('SELECT * FROM ai_calls')==[]


def test_signed_status_round_trip_with_bridge_fixture(environment,tmp_path):
    from aiticket.hermes_bridge import Ledger,create_bridge
    _,store,vault=environment
    incident,_=configured(store,vault)
    job=ai.request_job(store,vault,incident)
    bridge=create_bridge(Ledger(tmp_path/'bridge'),'bridge-fixture-secret',compatible=True).test_client()
    class Reply:
        def __init__(self,response):
            self.status_code=response.status_code
            self.headers=response.headers
            self.data=response.data
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def iter_content(self,size): return [self.data]
    def route(method,url,**kwargs):
        path=url.removeprefix('https://192.0.2.20')
        return Reply(bridge.open(path,method=method,data=kwargs['data'],headers=kwargs['headers']))
    with patch('aiticket.ai.requests.request',side_effect=route):
        ai.tick(store,vault)
        assert store.rows('SELECT state FROM ai_jobs')[0]['state']=='running'
        # Bridge accepted is not completion, and remains durable on the application side.
        assert not store.rows("SELECT * FROM timeline WHERE kind='ai_completed'")


def test_provider_timeout_keeps_reservation(environment):
    import requests
    _,store,vault=environment
    _,job,_=running(store,vault)
    with patch('aiticket.ai.requests.post',side_effect=requests.Timeout):
        with pytest.raises(ValueError,match='unknown'):
            ai.model_call(store,vault,job,payload())
    assert ai.meter(store)['held']==1
