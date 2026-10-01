import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT=Path(__file__).resolve().parents[1]/'agent'
spec=importlib.util.spec_from_file_location('fixture_agent_actions',ROOT/'actions.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
spec=importlib.util.spec_from_file_location('fixture_action_runner',ROOT/'agent.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


def job():
    return {'id':'action-identity','operation':'service_restart','parameters':{'service_id':'web','unit':'nginx.service'},'expires':time.time()+60,'dispatch_token':'scoped-token','proposal_hash':'immutable-hash'}


def policy():
    return {'services':{'web':'nginx.service'},'recovery':{'enabled':True,'validated':True,'services':['web']}}


def test_local_policy_denies_without_subprocess():
    with patch.object(module.subprocess,'run') as command:
        with pytest.raises(ValueError): module.execute(job(),{'services':{},'recovery':{}})
        malicious=job();malicious['parameters']['unit']='nginx.service; reboot'
        with pytest.raises(ValueError): module.execute(malicious,policy())
        command.assert_not_called()


def test_fixed_service_restart_and_local_failure_precondition():
    with patch.object(module.subprocess,'run',side_effect=[SimpleNamespace(returncode=0,stdout=b'Id=nginx.service\nLoadState=loaded\nActiveState=failed'),SimpleNamespace(returncode=0)]) as command:
        result=module.execute(job(),policy())
        assert result['status']=='completed'
        assert command.call_args.args[0]==['/usr/bin/systemctl','restart','--','nginx.service']
        assert command.call_args.kwargs['shell'] is False
    with patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'Id=nginx.service\nLoadState=loaded\nActiveState=active')) as command:
        assert module.execute(job(),policy())['status']=='failed'
        assert command.call_count==1


def test_timeout_unknown_never_claims_failure_success():
    with patch.object(module.subprocess,'run',side_effect=subprocess.TimeoutExpired(['systemctl'],10)):
        assert module.execute(job(),policy())['status']=='unknown'


def test_durable_action_identity_executes_at_most_once(tmp_path,monkeypatch):
    state={};path=tmp_path/'identity.json';calls=[]
    monkeypatch.setitem(sys.modules,'actions',SimpleNamespace(execute=lambda j,p:(calls.append(j['id']) or {'status':'completed','output':'Accepted'})))
    def authorize(payload):
        return {'status':'authorized','proposal_hash':payload['proposal_hash'],'operation':'service_restart','parameters':job()['parameters']}
    runner.process_actions(state,path,[job()],policy(),authorize)
    recovered=json.loads(path.read_text())
    runner.process_actions(recovered,path,[job()],policy(),authorize)
    assert calls==['action-identity']
    assert recovered['action_result']['status']=='completed'
    assert path.stat().st_mode&0o777==0o600


def test_crash_and_changed_authorized_parameters_never_execute(tmp_path,monkeypatch):
    execution=SimpleNamespace(execute=lambda *args:pytest.fail('Must not execute'))
    monkeypatch.setitem(sys.modules,'actions',execution)
    state={'action_ledger':{'action-identity':{'status':'running','output':''}}}
    runner.process_actions(state,tmp_path/'identity.json',[job()],policy(),lambda _:pytest.fail('Must not authorize again'))
    assert state['action_result']['status']=='unknown'
    state={}
    runner.process_actions(state,tmp_path/'identity2.json',[job()],policy(),lambda payload:{'status':'authorized','proposal_hash':payload['proposal_hash'],'operation':'service_restart','parameters':{'unit':'changed.service'}})
    assert state['action_result']['status']=='unknown'
