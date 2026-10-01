import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock
import pytest
from aiticket.app import create_app
from aiticket.security import validate_url
from aiticket.hermes_bridge import isolated_environment

spec=importlib.util.spec_from_file_location('http_agent',Path(__file__).resolve().parents[1]/'agent/agent.py')
agent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def test_application_http_is_opt_in(environment,monkeypatch):
    _,store,_=environment
    monkeypatch.delenv('AITICKET_LOCAL_HTTP',raising=False)
    monkeypatch.delenv('AITICKET_ALLOW_INSECURE_HTTP',raising=False)
    assert create_app(Path(store.path).parent).config['SESSION_COOKIE_SECURE']
    with pytest.raises(ValueError): validate_url('http://192.0.2.20',('https',))
    monkeypatch.setenv('AITICKET_ALLOW_INSECURE_HTTP','1')
    assert not create_app(Path(store.path).parent).config['SESSION_COOKIE_SECURE']
    assert validate_url('http://192.0.2.20',('https',))=='http://192.0.2.20'
    for url in ('ftp://192.0.2.20','http://user:secret@192.0.2.20'):
        with pytest.raises(ValueError): validate_url(url,('https',))


def test_agent_http_requires_opt_in_and_disallows_redirect_credentials(monkeypatch):
    with pytest.raises(ValueError): agent.endpoint('http://192.0.2.10:8080')
    assert agent.endpoint('http://192.0.2.10:8080',True)=='http://192.0.2.10:8080'
    for url in ('http://user:secret@host','http://host?token=secret','http://host#fragment','ftp://host'):
        with pytest.raises(ValueError): agent.endpoint(url,True)
    tls=Mock(side_effect=AssertionError('HTTP must not load TLS/CA files'))
    monkeypatch.setattr(agent.ssl,'create_default_context',tls)
    response=Mock();response.read.return_value=b'{"status":"ok"}'
    response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
    opener=Mock();opener.open.return_value=response
    monkeypatch.setattr(agent.urllib.request,'build_opener',Mock(return_value=opener))
    assert agent.post('http://192.0.2.10:8080','/api/agent/heartbeat',{'event_id':'e'},credential='fixture-token',allow_http=True)['status']=='ok'
    sent=opener.open.call_args.args[0]
    assert sent.get_header('Authorization')=='Bearer fixture-token'
    assert agent.NoRedirect().redirect_request(sent,None,302,'Found',{},'http://elsewhere') is None


def test_agent_enrollment_persists_http_choice(tmp_path,monkeypatch):
    path=tmp_path/'identity.json'
    monkeypatch.setattr('sys.argv',['agent','enroll','--state',str(path),'--server','http://192.0.2.10:8080','--allow-http'])
    monkeypatch.setattr(agent.getpass,'getpass',lambda _: 'fixture-enrollment-token')
    send=Mock(return_value={'agent_id':'a','credential':'fixture-agent-credential'})
    monkeypatch.setattr(agent,'post',send)
    agent.main()
    state=json.loads(path.read_text())
    assert state['allow_http'] is True and state['server']=='http://192.0.2.10:8080'
    assert send.call_args.kwargs['allow_http'] is True
    assert path.stat().st_mode&0o777==0o600


def test_https_still_verifies_even_in_http_mode(monkeypatch):
    monkeypatch.setattr(agent.ssl,'create_default_context',Mock(side_effect=ValueError('invalid CA')))
    with pytest.raises(ValueError,match='invalid CA'):
        agent.post('https://192.0.2.10','/health',{},ca='invalid',allow_http=True)


def test_hermes_http_mode_explicitly_propagates(monkeypatch,tmp_path):
    monkeypatch.delenv('AITICKET_ALLOW_INSECURE_HTTP',raising=False)
    assert 'AITICKET_ALLOW_INSECURE_HTTP' not in isolated_environment('/source',tmp_path,'https://192.0.2.10')
    monkeypatch.setenv('AITICKET_ALLOW_INSECURE_HTTP','1')
    assert isolated_environment('/source',tmp_path,'http://192.0.2.10:8080')['AITICKET_ALLOW_INSECURE_HTTP']=='1'
