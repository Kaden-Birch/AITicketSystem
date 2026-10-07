"""Runs on real Windows, independently of application and Linux test fixtures."""
import base64,importlib.util,io,json,os,subprocess,sys,tarfile,time
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
WINDOWS=ROOT/'agent'/'windows'
pytestmark=pytest.mark.skipif(os.name!='nt',reason='Native Windows APIs required')

@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/'agent'))
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
    from aiticket.topology import validate
    assert validate(network)==network
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


def test_fleet_windows_user_key_lifecycle(runtime,tmp_path):
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
    task='AITicketFleetTest'
    def system(script):
        script_file=tmp_path/'fleet-step.ps1';output=tmp_path/'fleet-output.txt'
        script_file.write_text("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';try {\n"+script+"\n$result='__PASSED__' } catch { $result=$_ | Out-String };$result | Out-File -LiteralPath '"+str(output)+".tmp' -Encoding utf8;Move-Item -LiteralPath '"+str(output)+".tmp' -Destination '"+str(output)+"' -Force",encoding='utf-8-sig')
        if output.exists():output.unlink()
        path=support.literal(str(script_file))
        args=support.literal('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+str(script_file)+'"')
        support.ps("$a=New-ScheduledTaskAction -Execute "+support.literal(support.powershell())+" -Argument "+args+";$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;Register-ScheduledTask -TaskName '"+task+"' -Action $a -Principal $p -Force | Out-Null;Start-ScheduledTask -TaskName '"+task+"'",timeout=15)
        deadline=time.monotonic()+45
        while time.monotonic()<deadline and not output.exists():time.sleep(.2)
        assert output.exists(),'SYSTEM fleet task did not finish'
        text=output.read_text(encoding='utf-8-sig');assert '__PASSED__' in text,text
    try:
        script=command(store,{'kind':'user','username':user,'access':'standard','key_id':'key'})
        system(script)
        info=support.query("$u=Get-LocalUser -Name '"+user+"';$p=Get-ItemProperty -LiteralPath ('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\'+$u.SID.Value);[pscustomobject]@{sid=$u.SID.Value;home=$p.ProfileImagePath}")
        home=Path(info['home']);authorized=home/'.ssh'/'authorized_keys'
        assert public in authorized.read_text()
        system(command(store,{'kind':'key','username':user,'key_id':'key'}))
        assert authorized.read_text().count(public)==1
        system(command(store,{'kind':'revoke','username':user,'key_id':'key'}))
        assert public not in authorized.read_text()
        with pytest.raises(AssertionError):system(script)
    finally:
        support.ps("Unregister-ScheduledTask -TaskName '"+task+"' -Confirm:$false -ErrorAction SilentlyContinue")
        support.ps("$u=Get-LocalUser -Name '"+user+"' -ErrorAction SilentlyContinue;if($u){Get-CimInstance Win32_UserProfile | Where-Object {$_.SID -eq $u.SID.Value} | Remove-CimInstance;Remove-LocalUser -Name '"+user+"'}",timeout=30)


def test_independent_update_activation_and_interrupted_rollback(runtime,tmp_path,monkeypatch):
    """Signed bundle activates, work defers, and interrupted probation restores it."""
    import hashlib
    import updater
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    support,_=runtime
    root=tmp_path/'agent';state=root/'state';state.mkdir(parents=True)
    (root/'config').mkdir();(root/'releases').mkdir()
    previous=root/'releases'/'bootstrap';previous.mkdir();support.activate(root,previous)
    (state/'identity.json').write_text(json.dumps({'agent_id':'fixture','credential':'fixture','server':'http://unavailable.invalid','allow_http':True}))
    (root/'config'/'updater.json').write_text('{"automatic":true}')
    key=Ed25519PrivateKey.generate()
    (root/'release-public.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w:gz') as tar:
        for name in updater.FILES:
            body=(ROOT/'agent'/name).read_bytes();info=tarfile.TarInfo(name);info.size=len(body);tar.addfile(info,io.BytesIO(body))
    body=archive.getvalue();version='0.10.0+123456abcdef'
    doc={'version':version,'url':'https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-'+version+'/windows-agent.tar.gz','sha256':hashlib.sha256(body).hexdigest(),'published':int(time.time()),'rollout_minutes':0}
    payload=json.dumps(doc).encode();manifest=json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(key.sign(payload)).decode()}).encode()
    monkeypatch.setattr(updater,'download',lambda url,limit:manifest if url==updater.FEED else body)
    monkeypatch.setattr(updater.Updater,'report',lambda self:None)
    monkeypatch.setattr(updater.Updater,'compatible',lambda self,version,stage:None)
    tasks=[]
    def task(self,action):
        tasks.append(action)
        if action=='start':(state/'health.json').write_text(json.dumps({'version':version,'at':time.time()}))
    monkeypatch.setattr(updater.Updater,'task',task)
    update=updater.Updater(root)
    from update_support import CompatibilityError
    def incompatible(*args):raise CompatibilityError('Update the main application first.')
    monkeypatch.setattr(update,'compatible',incompatible)
    update.run(now=True)
    assert update.status['state']=='blocked' and support.current(root)==previous and not tasks
    monkeypatch.setattr(update,'compatible',lambda *args:None)
    with (state/'execution.lock').open('a') as work:
        support.locks.flock(work,support.locks.LOCK_SH)
        update.run()
    assert update.status['state']=='waiting' and support.current(root)==previous and not tasks
    update.run()
    assert update.status['state']=='updated' and update.status['installed']==version
    installed=support.current(root);assert installed.name==version and tasks==['stop','start']
    # The app can remain unavailable: an interrupted update is rolled back before
    # consulting the feed, and the failed release is suppressed until a newer fix.
    broken=root/'releases'/'broken';broken.mkdir();support.activate(root,broken)
    failed_version='0.10.0+000000abcdef'
    doc.update(version=failed_version,url='https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-'+failed_version+'/windows-agent.tar.gz')
    payload=json.dumps(doc).encode();manifest=json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(key.sign(payload)).decode()}).encode()
    update.record('installing',previous=str(installed),previous_version=version,available=failed_version)
    recovered=updater.Updater(root);recovered.run()
    assert support.current(root)==installed and recovered.status['state']=='rolled_back'
    assert recovered.status['failed_release']==failed_version
    version=failed_version
    recovered.run(now=True,retry_failed=True)
    assert recovered.status['state']=='updated' and support.current(root).name==failed_version
    with pytest.raises(ValueError):recovered.run(retry_failed=True)


def test_power_defaults_use_elevated_identity_and_honor_local_restriction(runtime,tmp_path,monkeypatch):
    _,backend=runtime
    policy=tmp_path/'policy.json';policy.write_text('{}')
    monkeypatch.setattr(backend.ctypes.windll.shell32,'IsUserAnAdmin',lambda:True)
    p=backend.load_policy(policy)
    assert backend.capabilities(p)['power_operations']==['host_restart','host_shutdown']
    calls=[]
    monkeypatch.setattr(backend,'run',lambda argv,timeout:calls.append(argv) or {'state':'completed'})
    backend.action({'operation':'host_restart','parameters':{},'expires':time.time()+60},p)
    assert '/r' in calls[0] and '/t' in calls[0]
    policy.write_text('{"power":{"enabled":false}}')
    assert 'power_operations' not in backend.capabilities(backend.load_policy(policy))
    policy.write_text('{}');monkeypatch.setattr(backend.ctypes.windll.shell32,'IsUserAnAdmin',lambda:False)
    assert 'power_operations' not in backend.capabilities(backend.load_policy(policy))


def test_process_discovery_is_read_only_and_named(runtime):
    _,backend=runtime
    state={};inventory=backend.discovery(state)
    assert inventory['processes'] and len(inventory['processes'])<=200
    assert all(p['name'] and p['target'] and p['memory_bytes']>=0 for p in inventory['processes'])
    assert all('commandline' not in p and 'cpu_seconds' not in p for p in inventory['processes'])


def test_fixed_local_drive_capacity_and_volume_identity(runtime):
    _,backend=runtime
    values=backend.filesystems()
    assert values and len(values)<=64
    assert all(v['mount'].endswith('\\') and v['id'].startswith('\\\\?\\Volume{') for v in values)
    assert all(0<=v['free_bytes']<=v['total_bytes'] and v['total_bytes']>0 for v in values)
    from aiticket.host_storage import validate
    assert validate(values)==values
