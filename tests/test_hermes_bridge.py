import json
import time
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from aiticket.hermes_bridge import Ledger, create_bridge, isolated_environment, run_child
from aiticket.hermes_runner import execute
from aiticket.security import hermes_headers
from aiticket.ai import authenticate
from aiticket.db import uid


def envelope():
    return {'version':1,'execution_id':uid(),'model':'fixture-model','evidence':'untrusted incident text','credential':'scoped-fixture-token','max_calls':2,'expires':time.time()+600}


def signed_post(client,secret,document):
    body=json.dumps(document,separators=(',',':'),sort_keys=True).encode()
    return client.post('/v1/executions',data=body,headers=hermes_headers(secret,body,document['execution_id']))


def test_authentication_signed_response_and_idempotency(tmp_path):
    ledger=Ledger(tmp_path)
    secret='fixture-bridge-secret'
    client=create_bridge(ledger,secret,compatible=True).test_client()
    job=envelope()
    assert client.post('/v1/executions',json=job).status_code==401
    result=signed_post(client,secret,job)
    assert result.status_code==200 and result.json['state']=='accepted'
    assert authenticate(secret,result.data,result.headers)
    assert signed_post(client,secret,job).json==result.json
    assert signed_post(client,secret,{**job,'model':'changed-model'}).status_code==400
    assert ledger.claim()['execution_id']==job['execution_id']
    assert ledger.claim() is None
    assert job['credential'].encode() not in ledger.path.read_bytes()


def test_restart_never_replays_running_execution(tmp_path):
    ledger=Ledger(tmp_path)
    job=envelope()
    ledger.accept(job)
    ledger.claim()
    recovered=Ledger(tmp_path)
    assert recovered.status(job['execution_id'])['state']=='interrupted'
    assert recovered.claim() is None
    # Even a repeated identical POST cannot revive a started job.
    assert recovered.accept(job)['state']=='interrupted'


def test_accepted_survives_restart_and_duplicate_completion(tmp_path):
    ledger=Ledger(tmp_path)
    job=envelope()
    ledger.accept(job)
    recovered=Ledger(tmp_path)
    assert recovered.claim()['execution_id']==job['execution_id']
    recovered.complete(job['execution_id'],{'state':'completed','summary':'findings'})
    recovered.complete(job['execution_id'],{'state':'failed','summary':'late failure'})
    assert recovered.status(job['execution_id'])['summary']=='findings'


def test_incompatible_bridge_and_missing_status(tmp_path):
    ledger=Ledger(tmp_path)
    secret='fixture-bridge-secret'
    client=create_bridge(ledger,secret,compatible=False).test_client()
    assert signed_post(client,secret,envelope()).status_code==503
    headers=hermes_headers(secret,b'','status')
    result=client.get('/v1/executions/missing',headers=headers)
    assert result.json['state']=='not_found'
    assert authenticate(secret,result.data,result.headers)


def test_child_environment_excludes_provider_and_profile_secrets(tmp_path,monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','must-not-inherit')
    monkeypatch.setenv('ANTHROPIC_API_KEY','must-not-inherit')
    monkeypatch.setenv('HERMES_HOME','/normal/profile')
    env=isolated_environment('/dedicated/source',tmp_path,'https://192.0.2.10')
    assert 'OPENAI_API_KEY' not in env and 'ANTHROPIC_API_KEY' not in env
    assert env['HERMES_HOME']==str(tmp_path)
    assert env['AITICKET_GATEWAY']=='https://192.0.2.10'


class FakeAgent:
    loaded_tools=[]
    bypass=False
    def __init__(self,**kwargs):
        self.options=kwargs
        self.tools=self.loaded_tools
        self.client=SimpleNamespace(base_url='https://bypass.invalid' if self.bypass else kwargs['base_url'])
    def run_conversation(self,prompt):
        assert self.options['enabled_toolsets']==[]
        assert self.options['skip_memory'] is True
        assert self.options['skip_background_review'] is True
        assert self.options['request_overrides']['stream'] is False
        assert 'untrusted' in prompt
        return {'completed':True,'final_response':'A hypothesis'}
    def close(self):
        pass


def test_restricted_runner_conversation_and_tool_rejection(monkeypatch):
    assert execute(FakeAgent,envelope(),'https://192.0.2.10')['state']=='completed'
    monkeypatch.setattr(FakeAgent,'loaded_tools',[{'name':'terminal'}])
    with pytest.raises(RuntimeError,match='tools'):
        execute(FakeAgent,envelope(),'https://192.0.2.10')


def test_restricted_runner_detects_routing_bypass(monkeypatch):
    monkeypatch.setattr(FakeAgent,'bypass',True)
    with pytest.raises(RuntimeError,match='routing'):
        execute(FakeAgent,envelope(),'https://192.0.2.10')


def test_runner_fixed_argv_no_shell(tmp_path):
    job=envelope()
    with patch('aiticket.hermes_bridge.subprocess.Popen') as launch:
        launch.return_value.returncode=1
        result=run_child(job,'/python','/source','https://192.0.2.10')
        argv=launch.call_args.args[0]
        assert argv[:3]==['/python','-m','aiticket.hermes_runner']
        assert launch.call_args.kwargs.get('shell',False) is False
        assert launch.call_args.kwargs['start_new_session'] is True
        assert 'scoped-fixture-token' not in ' '.join(argv)
        assert result['state']=='failed'


def test_adapter_static_check_rejects_missing_interface(tmp_path,monkeypatch):
    import sys
    from aiticket.hermes_runner import installed_agent
    monkeypatch.setenv('AITICKET_HERMES_SOURCE',str(tmp_path))
    monkeypatch.setitem(sys.modules,'run_agent',SimpleNamespace(AIAgent=lambda model: None))
    with pytest.raises(RuntimeError,match='interface'):
        installed_agent()
    (tmp_path/'.env').write_text('DO_NOT_LOAD=fixture')
    with pytest.raises(RuntimeError,match='.env'):
        installed_agent()
