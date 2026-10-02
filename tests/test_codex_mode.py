import json
import time
import secrets
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
import pytest
from aiticket import ai,codex_mode
from aiticket.hermes_bridge import Ledger,create_bridge,isolated_environment,run_child
from aiticket.hermes_runner import execute,codex_runtime
from aiticket.security import hermes_headers
from test_ai import configured,payload


def configure(store,vault,**limits):
    incident,cfg=configured(store,vault)
    cfg['model']='gpt-6.1-sol';store.save('ai_config',cfg)
    bridge={**store.setting('hermes_config'),'execution_mode':'codex',**codex_mode.DEFAULTS,**limits}
    store.save_many({'hermes_config':bridge,'ai_provider_secret':None,'ai_provider':{},'hermes_validation':{'at':time.time(),'url':bridge['url'],'execution_mode':'codex','workspace_modes':['advice','exploration','recovery_proposal']}})
    return incident


def test_codex_no_api_key_count_limits_and_snapshot(environment):
    _,store,vault=environment
    incident=configure(store,vault,incident_runs=1)
    job=ai.request_job(store,vault,incident)
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    assert row['execution_mode']=='codex' and row['reasoning_effort']=='low' and row['model']=='gpt-6.1-sol'
    assert row['max_calls']==1 and row['allowance']==0
    ai.cancel(store,job)
    with pytest.raises(ValueError,match='limit'): ai.request_job(store,vault,incident)
    assert not store.rows('SELECT * FROM ai_calls')


def test_codex_permission_fences_takeover_and_paid_gateway(environment):
    app,store,vault=environment
    incident=configure(store,vault)
    job=ai.request_job(store,vault,incident)
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    headers={'Authorization':'Bearer '+vault.decrypt(row['credential'])}
    client=app.test_client()
    assert client.get('/api/hermes/'+job+'/permission').status_code==401
    assert client.get('/api/hermes/'+job+'/permission',headers=headers).json=={'allowed':True}
    with pytest.raises(ValueError,match='subscription'): ai.admit(store,job,{**payload(),'model':'gpt-6.1-sol'})
    ai.cancel(store,job)
    assert client.get('/api/hermes/'+job+'/permission',headers=headers).json=={'allowed':False}


def test_codex_gui_save_and_signed_mode_matching(signed_in):
    client,store,vault,csrf=signed_in
    fields={'csrf':csrf,'operation':'save','execution_mode':'codex','url':'https://192.0.2.39:8090','minimum':'high','secret':'fixture-shared-secret','codex_model':'gpt-6.1-sol','reasoning':'low'}
    assert client.post('/hermes',data=fields).status_code==302
    assert store.setting('hermes_config')['execution_mode']=='codex'
    assert not store.setting('ai_provider_secret')
    assert b'Codex subscription settings' in client.get('/hermes').data
    result={'version':1,'tools':[],'compatible':True,'model_gateway':False,'execution_mode':'codex','workspace_modes':['advice','exploration']}
    with patch('aiticket.ai.bridge_request',return_value=result):
        assert client.post('/hermes',data={'csrf':csrf,'operation':'test'}).status_code==302
    assert store.setting('hermes_validation')['execution_mode']=='codex'
    with patch('aiticket.ai.bridge_request',return_value={**result,'execution_mode':'gateway','model_gateway':True}):
        assert client.post('/hermes',data={'csrf':csrf,'operation':'test'}).status_code==400


def test_codex_result_requires_matching_signed_metadata(environment):
    _,store,vault=environment
    incident=configure(store,vault)
    job=ai.request_job(store,vault,incident)
    document={'execution_id':job,'state':'completed','summary':'Hypothesis','execution_mode':'codex','model':'gpt-6.1-sol','reasoning':'low'}
    with pytest.raises(ValueError,match='match'): ai.apply_status(store,job,{**document,'reasoning':'high'})
    ai.apply_status(store,job,document)
    assert store.rows('SELECT state FROM ai_jobs WHERE id=?',(job,))[0]['state']=='completed'
    assert not store.rows('SELECT * FROM ai_calls')


def test_codex_bridge_rejects_other_mode_and_persists_metadata(tmp_path):
    ledger=Ledger(tmp_path);client=create_bridge(ledger,'fixture-secret',True,'codex').test_client()
    job={'version':1,'execution_id':'660ba100-7771-4c64-a1c1-1376a1d958c3','model':'gpt-6.1-sol','evidence':'Untrusted evidence','credential':'scoped-fixture-token','max_calls':1,'expires':time.time()+300}
    body=json.dumps(job).encode()
    assert client.post('/v1/executions',data=body,content_type='application/json',headers=hermes_headers('fixture-secret',body,job['execution_id'])).status_code==400
    job.update(execution_mode='codex',reasoning='low',timeout_seconds=30);body=json.dumps(job).encode()
    response=client.post('/v1/executions',data=body,content_type='application/json',headers=hermes_headers('fixture-secret',body,job['execution_id']))
    assert response.status_code==200 and response.json['reasoning']=='low'
    assert response.json['model']=='gpt-6.1-sol'
    with pytest.raises(ValueError): ledger.accept({**job,'reasoning':'high'})


def test_codex_runner_fixed_route_reasoning_no_tools(monkeypatch):
    monkeypatch.setenv('AITICKET_EXECUTION_MODE','codex')
    route={'provider':'openai-codex','api_mode':'codex_responses','base_url':'https://chatgpt.com/backend-api/codex','api_key':'fixture-oauth-token'}
    class Agent:
        def __init__(self,**kwargs):
            assert kwargs['model']=='gpt-6.1-sol' and kwargs['reasoning_config']=={'enabled':True,'effort':'low'}
            assert kwargs['provider']=='openai-codex' and kwargs['api_key']=='fixture-oauth-token'
            assert kwargs['enabled_toolsets']==[] and kwargs['skip_background_review']
            assert kwargs['fallback_model'] is None
            # Codex rejects a Chat Completions stream override in Responses requests.
            assert 'stream' not in kwargs['request_overrides']
            self.tools=[];self.client=SimpleNamespace(base_url=route['base_url'])
        def run_conversation(self,prompt):
            assert self.client.max_retries==0
            return {'completed':True,'final_response':'Hypothesis'}
    job={'execution_mode':'codex','model':'gpt-6.1-sol','reasoning':'low','execution_id':'job','credential':'app-only','max_calls':1,'evidence':'fixture'}
    with patch('aiticket.hermes_runner.codex_runtime',return_value=route):
        assert execute(Agent,job,'http://192.0.2.10:8080')['state']=='completed'


def test_codex_supervisor_denial_prevents_process(tmp_path,monkeypatch):
    monkeypatch.setenv('AITICKET_EXECUTION_MODE','codex')
    job={'execution_mode':'codex','execution_id':'job','credential':'app-only','expires':time.time()+30,'timeout_seconds':30}
    with patch('aiticket.hermes_bridge.execution_permission',return_value=False),patch('aiticket.hermes_bridge.subprocess.Popen') as process:
        assert run_child(job,'/python','/source','http://192.0.2.10')['state']=='failed'
        process.assert_not_called()


def test_codex_isolated_environment_only_explicit_auth_profile(tmp_path,monkeypatch):
    monkeypatch.setenv('AITICKET_EXECUTION_MODE','codex');monkeypatch.setenv('AITICKET_CODEX_HOME','/dedicated/oauth')
    monkeypatch.setenv('OPENAI_API_KEY','must-not-inherit');monkeypatch.setenv('CODEX_HOME','/normal/codex')
    env=isolated_environment('/restricted',tmp_path,'http://192.0.2.10')
    assert env['AITICKET_CODEX_HOME']=='/dedicated/oauth' and env['HERMES_HOME']==str(tmp_path)
    assert 'CODEX_HOME' not in env and 'OPENAI_API_KEY' not in env


def test_codex_auth_route_rejects_proxy_and_preserves_profile(tmp_path,monkeypatch):
    import sys
    profile=tmp_path/'oauth';profile.mkdir(mode=0o700)
    auth=profile/'auth.json';auth.write_text('{}');auth.chmod(0o600)
    monkeypatch.setenv('AITICKET_CODEX_HOME',str(profile));monkeypatch.setenv('HERMES_HOME',str(tmp_path/'isolated'))
    resolver=Mock(return_value={'provider':'openai-codex','api_mode':'codex_responses','base_url':'https://chatgpt.com/backend-api/codex','api_key':'fixture-token'})
    monkeypatch.setitem(sys.modules,'hermes_cli.runtime_provider',SimpleNamespace(resolve_runtime_provider=resolver))
    assert codex_runtime('gpt-6.1-sol')['api_key']=='fixture-token'
    resolver.assert_called_with(requested='openai-codex',target_model='gpt-6.1-sol')
    import os
    assert os.environ['HERMES_HOME']==str(tmp_path/'isolated')
    resolver.return_value['base_url']='https://attacker.invalid'
    with pytest.raises(RuntimeError,match='route'): codex_runtime('gpt-6.1-sol')
    auth.chmod(0o644)
    with pytest.raises(RuntimeError,match='private'): codex_runtime('gpt-6.1-sol')


def test_codex_daily_limit_is_transactional_and_survives_restart(environment):
    import concurrent.futures
    _,store,vault=environment
    incident=configure(store,vault,daily_runs=1)
    def queue():
        try:return ai.request_job(store,vault,incident)
        except ValueError:return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:queue(),range(2)))
    assert len(store.rows("SELECT * FROM ai_jobs WHERE execution_mode='codex'"))==1
    job=next(r for r in results if r)
    ai.cancel(store,job)
    from aiticket.db import Store
    reopened=Store(store.path)
    with pytest.raises(ValueError,match='daily'): ai.request_job(reopened,vault,incident)


def test_codex_supervisor_cancellation_kills_entire_child_group(monkeypatch):
    import subprocess,signal
    monkeypatch.setenv('AITICKET_EXECUTION_MODE','codex')
    job={'execution_mode':'codex','execution_id':'job','credential':'app-only','expires':time.time()+60,'timeout_seconds':30}
    process=Mock(pid=12345)
    process.wait.side_effect=[subprocess.TimeoutExpired('fixture',1),None]
    with patch('aiticket.hermes_bridge.execution_permission',side_effect=[True,False]),patch('aiticket.hermes_bridge.subprocess.Popen',return_value=process) as spawn,patch('aiticket.hermes_bridge.os.killpg') as kill:
        result=run_child(job,'/python','/source','http://192.0.2.10')
        assert result['state']=='interrupted' and 'unknown' in result['summary']
        assert spawn.call_args.kwargs['start_new_session'] is True
        kill.assert_called_once_with(12345,signal.SIGKILL)
        assert process.wait.call_count==2
