import importlib.util
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT=Path(__file__).resolve().parents[1]/'agent'
spec=importlib.util.spec_from_file_location('agent_diagnostics',ROOT/'diagnostics.py')
diag=importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def job(operation,parameters=None):
    return {'operation':operation,'parameters':parameters or {},'expires':time.time()+60}


def test_local_policy_no_command_escape(tmp_path):
    path=tmp_path/'policy.json'
    path.write_text(json.dumps({'services':{'web':'nginx.service'},'logs':False}))
    policy=diag.load_policy(path)
    with pytest.raises(ValueError):
        diag.execute(job('service_logs',{'service_id':'web'}),policy)
    with pytest.raises(ValueError):
        diag.execute(job('service_status',{'service_id':'nginx.service; reboot'}),policy)
    with patch.object(diag,'command',return_value={'status':'completed','output':'active'}) as command:
        diag.execute(job('service_status',{'service_id':'web'}),policy)
        assert command.call_args.args[0][-1]=='nginx.service'
    path.write_text(json.dumps({'services':{'bad':'--malicious.service'}}))
    with pytest.raises(ValueError):
        diag.load_policy(path)


def test_process_summary_omits_arguments_and_bounds(tmp_path):
    for n in range(120):
        path=tmp_path/str(n)
        path.mkdir()
        (path/'comm').write_text('worker')
        (path/'cmdline').write_text('token=secret')
    result=diag.execute(job('process_summary'),{'services':{},'logs':False},tmp_path)
    data=json.loads(result['output'])
    assert len(data['processes'])==100 and 'secret' not in result['output']


def test_agent_ledger_does_not_replay_completed_or_interrupted(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    spec=importlib.util.spec_from_file_location('runtime_agent',ROOT/'agent.py')
    runtime=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    state={}
    identity=tmp_path/'identity.json'
    task={'id':'stable-job','lease_token':'one',**job('process_summary')}
    with patch('diagnostics.execute',return_value={'status':'completed','output':'ok'}) as execute:
        runtime.process_jobs(state,identity,[task],{'services':{},'logs':False})
        state=json.loads(identity.read_text())
        task['lease_token']='two'
        runtime.process_jobs(state,identity,[task],{'services':{},'logs':False})
        execute.assert_called_once()
        assert state['diagnostic_result']['lease_token']=='two'
        state['diagnostic_ledger']['interrupted']={'status':'running','output':''}
        task['id']='interrupted'
        runtime.process_jobs(state,identity,[task],{'services':{},'logs':False})
        assert state['diagnostic_result']['status']=='failed'
        execute.assert_called_once()


def test_command_output_is_bounded_and_redacted():
    result=diag.command([sys.executable,'-c',"import sys; sys.stdout.write('token=secret\\n'+'x'*20000)"])
    assert len(result['output'])<=16000 and 'token=secret' not in result['output']


def test_command_timeout_kills_provider():
    started=time.monotonic()
    result=diag.command([sys.executable,'-c','import time; time.sleep(10)'])
    assert time.monotonic()-started<7 and result['status']=='failed'


def test_telemetry_cpu_deltas_available_memory_and_inodes():
    from types import SimpleNamespace
    spec=importlib.util.spec_from_file_location('telemetry_agent',ROOT/'agent.py')
    runtime=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    values={'/proc/meminfo':'MemTotal: 1000 kB\nMemAvailable: 500 kB\n','/proc/uptime':'100 0','/proc/stat':'cpu  100 0 0 100 0 0 0 0','/proc/pressure/memory':'full avg10=1.50 avg60=0.00 avg300=0.00 total=100'}
    disk=SimpleNamespace(f_favail=10,f_files=100,f_bavail=5,f_frsize=4096,f_blocks=100)
    with patch.object(runtime.Path,'read_text',lambda p:values[str(p)]),patch.object(runtime.Path,'exists',return_value=True),patch.object(runtime.os,'statvfs',return_value=disk),patch.object(runtime.os,'getloadavg',return_value=(1,0,0)):
        state={}
        first=runtime.telemetry(state)
        assert 'cpu_percent' not in first
        values['/proc/stat']='cpu  150 0 0 150 0 0 0 0'
        second=runtime.telemetry(state)
        assert second['cpu_percent']==50
        assert second['memory_available_bytes']==512000
        assert second['inode_free']==10 and second['memory_pressure_percent']==1.5


@pytest.mark.parametrize('failure',['missing_module','http_404','http_500'])
def test_optional_checks_failure_does_not_suppress_following_heartbeats(tmp_path,monkeypatch,failure,capsys):
    import urllib.error
    from agent import agent as runtime
    monkeypatch.syspath_prepend(str(ROOT))
    identity=tmp_path/'identity.json'
    identity.write_text(json.dumps({'server':'http://10.0.0.1:8080','allow_http':True,'credential':'test'}))
    monkeypatch.setattr(sys,'argv',['agent.py','run','--state',str(identity),'--policy',str(tmp_path/'absent.json')])
    if failure=='missing_module':monkeypatch.setitem(sys.modules,'monitoring',None)
    routes=[]
    def send(base,route,*args,**kwargs):
        routes.append(route)
        if route=='/api/agent/checks':raise urllib.error.HTTPError('redacted',404 if failure=='http_404' else 500,'test',{},None)
        return {'poll_interval_seconds':20,'commands':[],'jobs':[],'actions':[]}
    sleeps=0
    def sleep(seconds):
        nonlocal sleeps
        sleeps+=1
        if sleeps>20:raise SystemExit
    with patch.object(runtime,'post',side_effect=send),patch.object(runtime,'telemetry',return_value={}),patch.object(runtime,'host_info',return_value={}),patch.object(runtime.time,'sleep',side_effect=sleep),patch.object(runtime.signal,'signal'),patch('commands.recover'),patch('commands.drain'),patch('commands.start'):
        with pytest.raises(SystemExit):runtime.main()
    assert routes.count('/api/agent/heartbeat')==2
    assert routes[0]=='/api/agent/heartbeat'
    assert 'heartbeat continues' in capsys.readouterr().out
