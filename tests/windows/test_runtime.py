"""Runs on real Windows, independently of application and Linux test fixtures."""
import base64,importlib.util,io,json,os,subprocess,sys,tarfile,time
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
WINDOWS=ROOT/'agent'/'windows'
pytestmark=pytest.mark.skipif(os.name!='nt',reason='Native Windows APIs required')

@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.syspath_prepend(str(WINDOWS))
    import platform_support,backend
    return platform_support,backend


def test_powershell_output_limits_exit_and_permission(runtime):
    support,backend=runtime
    assert support.ps("'hello ✓'")== 'hello ✓'
    failure=support.run(support.ps_argv("throw 'fixture failure'"),10)
    assert failure['state']=='failed' and 'fixture failure' in failure['stderr']
    output=support.run(support.ps_argv("[Console]::Write('x'*20000)"),10,1024)
    assert output['state']=='completed' and output['truncated'] and len(output['stdout'].encode())<=1024
    cancelled=support.run(support.ps_argv('Start-Sleep -Seconds 30'),10,allowed=lambda:False)
    assert cancelled['state']=='cancelled'
    job={'command':"'hello'",'timeout':10,'output_limit':1024}
    assert backend.execute_command(job,lambda:False,lambda:{'enabled':True})['state']=='cancelled'


def test_timeout_kills_entire_process_tree(runtime,tmp_path):
    support,_=runtime;pid_file=tmp_path/'child.pid'
    script="$p=Start-Process -FilePath "+support.literal(sys.executable)+" -ArgumentList '-c \"import time; time.sleep(60)\"' -PassThru;[IO.File]::WriteAllText("+support.literal(str(pid_file))+",[string]$p.Id);Start-Sleep -Seconds 60"
    started=time.monotonic();result=support.run(support.ps_argv(script),4)
    assert result['state']=='unknown' and time.monotonic()-started<12
    assert pid_file.exists()
    pid=int(pid_file.read_text())
    assert support.ps("if(Get-Process -Id "+str(pid)+" -ErrorAction SilentlyContinue){'alive'}else{'gone'}")=='gone'


def test_file_locks_and_pointer(runtime,tmp_path):
    support,_=runtime;path=tmp_path/'execution.lock'
    with path.open('a') as first,path.open('a') as second:
        support.locks.flock(first,support.locks.LOCK_SH)
        support.locks.flock(second,support.locks.LOCK_SH)
        with path.open('a') as third:
            with pytest.raises(BlockingIOError):support.locks.flock(third,support.locks.LOCK_EX|support.locks.LOCK_NB)
    with path.open('a') as exclusive:support.locks.flock(exclusive,support.locks.LOCK_EX|support.locks.LOCK_NB)
    release=tmp_path/'releases'/'test';release.mkdir(parents=True)
    support.activate(tmp_path,release);assert support.current(tmp_path)==release
    support.activate(tmp_path,tmp_path)
    with pytest.raises(ValueError):support.current(tmp_path)


def test_real_telemetry_network_and_diagnostics(runtime):
    support,backend=runtime;state={}
    first=backend.telemetry(state);time.sleep(.1);second=backend.telemetry(state)
    assert first['memory_total_bytes']>first['memory_available_bytes']>0
    assert first['disk_total_bytes']>=first['disk_free_bytes']>0
    assert second['uptime_seconds']>0 and 0<=second['cpu_percent']<=100
    assert backend.host_info()['os'].startswith('Windows')
    assert 'inode_total' not in first and 'load_1' not in first
    network=backend.inventory();assert network['interfaces'] and network['machine_type'] in ('physical','vm','unknown')
    assert all(isinstance(i['addresses'],list) and 'name' in i for i in network['interfaces'])
    p={'services':{'scheduler':'Schedule'},'logs':False}
    result=backend.diagnostic({'operation':'service_status','parameters':{'service_id':'scheduler'},'expires':time.time()+60},p)
    assert 'Id=Schedule' in result['output'] and 'ActiveState=active' in result['output']
    assert backend.evaluate({'id':'test','kind':'process','config':{'target':'service:Schedule'}})['healthy'] is True
    assert backend.evaluate({'id':'test','kind':'process','config':{'target':'definitely_absent_fixture'}})['healthy'] is False


def test_durable_shared_command_recovery(runtime,tmp_path,monkeypatch):
    support,_=runtime
    monkeypatch.syspath_prepend(str(ROOT/'agent'))
    monkeypatch.setitem(sys.modules,'fcntl',support.locks)
    spec=importlib.util.spec_from_file_location('windows_shared_commands',ROOT/'agent'/'commands.py');commands=importlib.util.module_from_spec(spec);spec.loader.exec_module(commands)
    state={'command_ledger':{'fixture':{'state':'running','dispatch_token':'token'}}}
    commands.recover(state);commands.recover(state)
    assert state['command_ledger']['fixture']['state']=='unknown' and len(state['command_results'])==1


def test_windows_manifest_validation_and_archive(runtime,tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import updater
    key=Ed25519PrivateKey.generate();public=tmp_path/'public.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    doc={'version':'0.10.0+abcdefabcdef','url':'https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-0.10.0+abcdefabcdef/windows-agent.tar.gz','sha256':'a'*64,'published':int(time.time()),'rollout_minutes':30}
    def sign(document):
        payload=json.dumps(document).encode();return json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(key.sign(payload)).decode()}).encode()
    assert updater.verify(sign(doc),public)==doc
    with pytest.raises(ValueError):updater.verify(sign({**doc,'url':'http://insecure.example/archive'}),public)
    envelope=json.loads(sign(doc));envelope['payload']=base64.b64encode(b'tampered').decode()
    with pytest.raises(Exception):updater.verify(json.dumps(envelope).encode(),public)
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w:gz') as archive:
        for name in updater.FILES:
            data=(ROOT/'agent'/name).read_bytes();info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
    updater.extract(raw.getvalue(),tmp_path/'valid')
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w:gz') as archive:
        item=tarfile.TarInfo('../escape');item.size=1;archive.addfile(item,io.BytesIO(b'x'))
    with pytest.raises(ValueError):updater.extract(raw.getvalue(),tmp_path/'invalid')


def test_fleet_windows_user_key_lifecycle(runtime):
    """Create a real disposable local user; preserve/revoke one public key."""
    import uuid
    from aiticket.windows_fleet import command
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    support,_=runtime;user='aitest_'+uuid.uuid4().hex[:12]
    public=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
    class Store:
        def rows(self,*args):return [{'public':public}]
    store=Store();home=None
    try:
        script=command(store,{'kind':'user','username':user,'access':'standard','key_id':'key'})
        support.ps(script,timeout=30)
        info=support.query("$u=Get-LocalUser -Name '"+user+"';$p=Get-ItemProperty -LiteralPath ('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\'+$u.SID.Value);[pscustomobject]@{sid=$u.SID.Value;home=$p.ProfileImagePath}")
        home=Path(info['home']);authorized=home/'.ssh'/'authorized_keys'
        assert public in authorized.read_text()
        support.ps(command(store,{'kind':'key','username':user,'key_id':'key'}),timeout=20)
        assert authorized.read_text().count(public)==1
        support.ps(command(store,{'kind':'revoke','username':user,'key_id':'key'}),timeout=20)
        assert public not in authorized.read_text()
        with pytest.raises(ValueError):support.ps(script,timeout=20)
    finally:
        support.ps("$u=Get-LocalUser -Name '"+user+"' -ErrorAction SilentlyContinue;if($u){Get-CimInstance Win32_UserProfile | Where-Object {$_.SID -eq $u.SID.Value} | Remove-CimInstance;Remove-LocalUser -Name '"+user+"'}",timeout=30)
