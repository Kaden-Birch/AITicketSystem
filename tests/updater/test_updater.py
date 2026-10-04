import base64,fcntl,hashlib,io,json,subprocess,sys,tarfile,time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from agent import updater as u

@pytest.fixture
def keys(tmp_path):
    private=tmp_path/'private.pem';public=tmp_path/'public.pem'
    subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(private)],check=True,capture_output=True)
    subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],check=True,capture_output=True)
    return private,public


def signed(keys,tmp_path,doc):
    payload=json.dumps(doc).encode();path=tmp_path/'payload';sig=tmp_path/'signature';path.write_bytes(payload)
    subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(keys[0]),'-rawin','-in',str(path),'-out',str(sig)],check=True,capture_output=True)
    return json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(sig.read_bytes()).decode()}).encode()


def bundle():
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz') as archive:
        for name in u.FILES:
            data=Path('agent',name).read_bytes();info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
    return output.getvalue()

@pytest.fixture
def installation(tmp_path,keys,monkeypatch):
    root=tmp_path/'root';state=tmp_path/'state';root.mkdir();state.mkdir();(root/'releases').mkdir()
    previous=root/'releases'/'previous';previous.mkdir();(previous/'agent.py').write_text('previous')
    (root/'current').symlink_to(previous);(root/'release-public.pem').write_bytes(keys[1].read_bytes())
    identity={'agent_id':'fixture','credential':'preserved','server':'http://127.0.0.1:1','allow_http':True,'command_ledger':{}}
    (state/'identity.json').write_text(json.dumps(identity));(state/'update-status.json').write_text(json.dumps({'installed':'0.8.0'}))
    config=tmp_path/'config.json';config.write_text('{"automatic":true}')
    updater=u.Updater(root,state,config);updater.report=Mock(return_value=None)
    # Extract/import logic has separate real compilation coverage; don't require Linux Python path for transactions.
    monkeypatch.setattr(u,'extract',lambda body,path:(path.mkdir(),[(path/name).write_bytes(Path('agent',name).read_bytes()) for name in u.FILES]))
    data=bundle();doc={'version':'0.9.0+123456789abc','url':'https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-0.9.0+123456789abc/agent.tar.gz','sha256':hashlib.sha256(data).hexdigest(),'published':int(time.time())-4000,'rollout_minutes':30}
    envelope=signed(keys,tmp_path,doc)
    monkeypatch.setattr(u,'fetch',lambda url,limit:envelope if url==u.FEED else data)
    updater.service=Mock();updater.healthy=Mock(return_value=True)
    return updater,doc,data,keys,tmp_path


def test_success_independent_of_agent_and_preserves_identity(installation):
    updater,doc,*_=installation;identity=(updater.state/'identity.json').read_bytes()
    updater.run()
    assert updater.status['state']=='updated'
    assert updater.status['installed']==doc['version']
    assert (updater.root/'current').resolve().name==doc['version']
    assert (updater.state/'identity.json').read_bytes()==identity
    assert [c.args[0] for c in updater.service.call_args_list]==['stop','start']
    updater.run();assert updater.status['state']=='current' and updater.service.call_count==2


def test_failed_heartbeat_rolls_back_and_never_retries_same_release(installation,monkeypatch):
    updater,doc,*_=installation;updater.healthy.return_value=False
    ticks=iter([0,121]);monkeypatch.setattr(u,'time',SimpleNamespace(time=time.time,monotonic=lambda:next(ticks),sleep=lambda _:None))
    updater.run();assert updater.status['state']=='rolled_back'
    assert (updater.root/'current').resolve().name=='previous'
    assert updater.status['installed']=='0.8.0'
    updater.service.reset_mock();updater.run();updater.service.assert_not_called()


def test_bad_signature_or_checksum_cannot_activate(installation,monkeypatch):
    updater,doc,data,keys,tmp=installation
    other=tmp/'other.pem';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(other)],check=True,capture_output=True)
    envelope=signed((other,keys[1]),tmp,doc);monkeypatch.setattr(u,'fetch',lambda *a:envelope)
    updater.run();assert 'signature' in updater.status['detail'];updater.service.assert_not_called()
    envelope=signed(keys,tmp,doc);monkeypatch.setattr(u,'fetch',lambda url,limit:envelope if url==u.FEED else b'tampered')
    updater.run();assert 'checksum' in updater.status['detail'];updater.service.assert_not_called()


def test_active_work_defers_installation(installation):
    updater,*_=installation
    with open(updater.state/'execution.lock','a') as work:
        fcntl.flock(work,fcntl.LOCK_SH);updater.run()
    assert updater.status['state']=='waiting';updater.service.assert_not_called()
    identity=json.loads((updater.state/'identity.json').read_text());identity['command_ledger']={'job':{'state':'running'}}
    (updater.state/'identity.json').write_text(json.dumps(identity));updater.run()
    assert updater.status['state']=='waiting';updater.service.assert_not_called()


def test_manual_request_bypasses_schedule_but_not_signatures(installation,monkeypatch):
    updater,doc,data,keys,tmp=installation;doc['published']=int(time.time());doc['rollout_minutes']=1440
    updater.identity['agent_id']='fixture' # fixture is outside initial ten percent
    envelope=signed(keys,tmp,doc);monkeypatch.setattr(u,'fetch',lambda url,limit:envelope if url==u.FEED else data)
    updater.run();assert updater.status['state']=='scheduled'
    updater.report.return_value='12345678-1234-1234-1234-123456789abc';updater.run()
    assert updater.status['state']=='updated' and updater.status['handled_request']==updater.report.return_value


def test_interrupted_activation_recovers_and_rejects_older_feed(installation):
    updater,doc,*_=installation
    updater.status.update(state='installing',available=doc['version'],previous=str(updater.root/'releases'/'previous'),previous_version='0.8.0')
    updater.run();assert (updater.root/'current').resolve().name=='previous'
    assert updater.status['failed_release']==doc['version']
    updater.status['highest_published']=doc['published']+10;updater.run()
    assert updater.status['state']=='failed' and 'Older' in updater.status['detail']


def test_archive_rejects_links_and_traversal(tmp_path):
    for name,kind in (('../escape',tarfile.REGTYPE),('agent.py',tarfile.SYMTYPE)):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as archive:
            for item in u.FILES:
                info=tarfile.TarInfo(name if item=='agent.py' else item);info.type=kind if item=='agent.py' else tarfile.REGTYPE
                info.size=0;archive.addfile(info,io.BytesIO())
        with pytest.raises(ValueError):u.extract(output.getvalue(),tmp_path/'bundle')


def test_archive_compiles_and_imports_actual_modules(tmp_path,monkeypatch):
    run=subprocess.run
    def portable(args,**kwargs):
        args[0]=sys.executable;return run(args,**kwargs)
    monkeypatch.setattr(u.subprocess,'run',portable)
    u.extract(bundle(),tmp_path/'bundle')
    assert (tmp_path/'bundle'/'agent.py').exists()


def test_newer_corrective_release_recovers_a_broken_agent(installation,monkeypatch):
    updater,doc,data,keys,tmp=installation
    updater.status.update(failed_release=doc['version'],installed='0.8.0',state='rolled_back')
    newer={**doc,'version':'0.9.0+abcdef123456','url':doc['url'].replace('123456789abc','abcdef123456'),'published':int(time.time())-1900}
    envelope=signed(keys,tmp,newer)
    monkeypatch.setattr(u,'fetch',lambda url,limit:envelope if url==u.FEED else data)
    updater.run()
    assert updater.status['state']=='updated' and updater.status['installed']==newer['version']


def test_local_pause_still_allows_explicit_manual_update(installation):
    updater,*_=installation;updater.config['automatic']=False
    updater.run();assert updater.status['state']=='available';updater.service.assert_not_called()
    updater.report.return_value='12345678-1234-1234-1234-123456789abc'
    updater.run();assert updater.status['state']=='updated'


def test_crashed_activation_is_recovered_on_next_independent_cycle(installation,monkeypatch):
    updater,doc,*_=installation
    def crash(action):
        if action=='start': raise KeyboardInterrupt('simulated process interruption')
    updater.service.side_effect=crash
    with pytest.raises(KeyboardInterrupt):updater.run()
    assert (updater.root/'current').resolve().name==doc['version']
    assert json.loads(updater.path.read_text())['state']=='installing'
    resumed=u.Updater(updater.root,updater.state,Path(updater.root).parent/'config.json')
    resumed.report=Mock(return_value=None);resumed.service=Mock();resumed.run()
    assert resumed.status['state']=='rolled_back'
    assert (updater.root/'current').resolve().name=='previous'


def test_application_reporting_failure_cannot_stop_release_recovery(installation):
    updater,doc,*_=installation
    updater.report=u.Updater.report.__get__(updater)
    updater.run()
    assert updater.status['state']=='updated' and updater.status['installed']==doc['version']
