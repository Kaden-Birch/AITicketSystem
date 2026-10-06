import gzip
import errno
import socket
import hashlib
import json
import time
from pathlib import Path
from unittest.mock import Mock
import pytest
from aiticket import log_archive as archive, network_logs as logs, smb_archive_io
from aiticket.log_receiver import Collector


@pytest.fixture(autouse=True)
def local_archive(monkeypatch):
    monkeypatch.delenv('AITICKET_LOG_DATA', raising=False)


def settings(**changes):
    return {'smb_server':'192.0.2.10','smb_share':'Logs','smb_folder':'tickets/network',
            'smb_username':'monitor','smb_domain':'','smb_password':'test-secret-not-in-output',
            'smb_enabled':'yes','smb_days':'365','smb_buffer_mb':'16', **changes}


def configure(store, vault, **changes):
    cfg = archive.validate(store,vault,settings(**changes)); archive.save(store,cfg)
    return archive.connection(store,vault)


def receive(store, now=None, count=1):
    if not store.rows('SELECT id FROM log_sources'):
        logs.save_source(store,{'name':'Console','sender_ip':'192.0.2.1','enabled':'yes'})
    collector = Collector(store); now = time.time() if now is None else now
    for index in range(count):
        collector.receive(f'CEF:0|Ubiquiti|UniFi|10|401|Disconnect|5|msg=sample {index}'.encode(),'192.0.2.1',now)
    collector.flush(now)
    return collector


class FakeSMB:
    """Exercise the real helper operations with a filesystem implementing SMB file calls."""
    def __init__(self, root):
        self.root = root; self.sessions = []; self.calls = []
    def ClientConfig(self, **kwargs): assert kwargs['skip_dfs']
    def register_session(self, server, **kwargs): self.sessions.append((server,kwargs))
    def path(self, path):
        parts = path.lstrip('\\').split('\\')
        assert '..' not in parts
        return self.root.joinpath(*parts)
    def makedirs(self, path, **kwargs): self.path(path).mkdir(parents=True, **kwargs)
    def open_file(self, path, mode): self.calls.append(('open',path,mode)); return self.path(path).open(mode)
    def rename(self, old, new): self.calls.append(('rename',old,new)); self.path(old).rename(self.path(new))
    def remove(self, path): self.calls.append(('remove',path)); self.path(path).unlink()
    def scandir(self, path):
        import os
        return os.scandir(self.path(path))


@pytest.fixture
def smb(monkeypatch, tmp_path):
    import smbclient
    fake = FakeSMB(tmp_path/'remote')
    for name in ('ClientConfig','register_session','makedirs','open_file','rename','remove','scandir'):
        monkeypatch.setattr(smbclient,name,getattr(fake,name))
    def io(cfg, action, timeout=30, **kwargs):
        return {'ok':True, **smb_archive_io.execute({'connection':cfg,'operation':action,**kwargs})}
    return fake, io


def test_local_first_outage_restart_and_expiry_preserve_pending(environment, smb):
    _,store,vault = environment; cfg = configure(store,vault)
    fake, io = smb; now = time.time()
    collector = receive(store,now)
    assert collector.archive.backlog()['pending'] == 1
    failing = Mock(side_effect=OSError('Share disconnected'))
    worker = archive.Archiver(store,vault,failing)
    worker.step()
    assert logs.status(store)['available'] and worker.state['error'] == 'Share disconnected'
    assert collector.archive.backlog()['pending'] == 1
    collector.archive.retain({'days':7,'rows':10000,'megabytes':10},now+8*86400,mirrored=True)
    assert logs.status(store)['events'] == 0
    assert collector.archive.backlog()['pending'] == 1 and collector.archive.backlog()['gaps'] == 0
    restarted = archive.Archiver(store,vault,io); restarted.upload(cfg)
    assert restarted.archive.backlog()['pending'] == 0
    files = io(cfg,'catalog')['files']; assert len(files) == 1
    output = Path(store.path).parent/'search.json'
    params = {'start':now-10,'end':now+10}
    result = io(cfg,'search',names=[f['name'] for f in files],params=params,file=str(output))
    assert result['count'] == 1 and json.loads(output.read_text())[0]['message'] == 'sample 0'
    assert not store.rows('SELECT 1 FROM ai_jobs') and not store.rows('SELECT 1 FROM incidents')


def test_upload_retry_is_idempotent_after_remote_success_before_local_ack(environment, smb):
    _,store,vault=environment;cfg=configure(store,vault);receive(store,count=3)
    fake, io = smb
    def crash(cfg, action, **kwargs):
        io(cfg,action,**kwargs)
        raise OSError('Interrupted before acknowledgment')
    worker = archive.Archiver(store,vault,crash)
    with pytest.raises(OSError): worker.upload(cfg)
    first = io(cfg,'catalog')['files'][0]['name']
    assert worker.archive.backlog()['pending'] == 3
    restarted=archive.Archiver(store,vault,io); restarted.upload(cfg)
    assert io(cfg,'catalog')['files'] == [smb_archive_io.metadata(first)]
    assert restarted.archive.backlog()['pending'] == 0
    with restarted.archive.connect() as c: assert c.execute('SELECT sum(archived) FROM events').fetchone()[0]==3


def test_destination_change_copies_current_local_history_without_deleting_old_share(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);receive(store)
    fake,io=smb;worker=archive.Archiver(store,vault,io);worker.upload(cfg)
    previous=io(cfg,'catalog')['files'];assert len(previous)==1
    changed=configure(store,vault,smb_share='AnotherShare')
    worker.upload(changed)
    assert len(io(changed,'catalog')['files'])==1
    assert io(cfg,'catalog')['files']==previous


def test_existing_history_backfills_and_independent_smb_retention(environment,smb):
    _,store,vault=environment;now=time.time();collector=receive(store,now-10*86400)
    cfg=configure(store,vault);fake,io=smb
    worker=archive.Archiver(store,vault,io);worker.upload(cfg)
    assert len(io(cfg,'catalog')['files'])==1
    cfg['days']=0;worker.cleanup(cfg);assert len(io(cfg,'catalog')['files'])==1
    cfg['days']=7;worker.cleanup(cfg);assert not io(cfg,'catalog')['files']
    with collector.archive.connect() as c: assert c.execute('SELECT count(*) FROM events').fetchone()[0]==1


def test_buffer_pressure_never_stops_collection_and_reports_expired_unqueued_events(environment):
    _,store,vault=environment;configure(store,vault);collector=receive(store)
    # Simulate a full buffer without allocating sixteen megabytes in a fixture.
    with collector.archive.connect() as c:c.execute('UPDATE smb_outbox SET size=?',(16*1048576,))
    now=time.time();collector.receive(b'new local event','192.0.2.1',now);collector.flush(now)
    assert logs.status(store)['events']==2
    assert collector.archive.backlog()['pending']==1 and collector.archive.backlog()['waiting_local']==1
    collector.archive.retain({'days':7,'rows':10000,'megabytes':10},now+8*86400,mirrored=True)
    assert collector.archive.backlog()['pending']==1 and collector.archive.backlog()['gaps']==1


def test_local_indefinite_retention_still_honors_explicit_size_and_count_limits(environment):
    _,store,_=environment;collector=receive(store,count=3)
    collector.archive.retain({'days':0,'rows':1000,'megabytes':10},time.time()+900*86400)
    assert logs.status(store)['events']==3
    collector.archive.retain({'days':0,'rows':1,'megabytes':10})
    assert logs.status(store)['events']==1


def test_connection_validation_credentials_ui_and_encryption_rotation(signed_in,smb,tmp_path):
    client,store,vault,csrf=signed_in
    bad=settings(smb_folder='../other',smb_password='DO-NOT-RENDER')
    response=client.post('/settings/network-logs',data={**bad,'csrf':csrf,'operation':'smb_save'})
    assert response.status_code==200 and b'parent-directory' in response.data
    assert b'192.0.2.10' in response.data and b'DO-NOT-RENDER' not in response.data
    response=client.post('/settings/network-logs',data={**settings(),'csrf':csrf,'operation':'smb_test'})
    assert response.status_code==302
    task=store.rows('SELECT * FROM log_archive_jobs')[0]
    assert 'test-secret-not-in-output' not in task['connection']
    assert vault.decrypt(store.setting('network_log_smb_secret'))=='test-secret-not-in-output'
    assert 'password' not in archive.config(store)
    configure(store,vault,smb_password='')
    with pytest.raises(ValueError):archive.validate(store,vault,settings(smb_password='',smb_server='192.0.2.99'))
    from aiticket.administration import rotate_key
    from aiticket.security import Vault
    rotate_key(store,vault,tmp_path/'rotated.key');new=Vault(tmp_path/'rotated.key')
    assert archive.connection(store,new)['password']=='test-secret-not-in-output'
    assert json.loads(new.decrypt(store.rows('SELECT connection FROM log_archive_jobs')[0]['connection']))['password']=='test-secret-not-in-output'
    fake,io=smb;worker=archive.Archiver(store,new,io);worker.process_job()
    assert archive.job(store,task['id'])['state']=='complete'
    assert not store.rows('SELECT connection FROM log_archive_jobs')[0]['connection']
    assert 'test-secret-not-in-output' not in str(archive.job(store,task['id']))


def test_historical_search_details_filters_and_csrf(signed_in,smb):
    client,store,vault,csrf=signed_in;cfg=configure(store,vault);collector=receive(store,count=4)
    fake,io=smb;worker=archive.Archiver(store,vault,io);worker.upload(cfg)
    now=time.time();identifier=archive.submit(store,vault,'search',cfg,{'start':now-60,'end':now+60,'q':'sample 2'})
    assert worker.process_job()
    items=archive.search_results(store,identifier);assert len(items)==1 and items[0]['message']=='sample 2'
    collector.archive.retain({'days':7,'rows':0,'megabytes':10})
    response=client.get('/network-events/archive?job='+identifier)
    assert response.status_code==200 and b'sample 2' in response.data
    path='/network-events/archive/'+identifier+'/'+items[0]['event_key']
    assert client.get(path).status_code==200
    assert client.post('/network-events/archive',data={'start':'bad'}).status_code==403
    assert client.post('/network-events/archive',data={'csrf':csrf,'start':'bad'}).status_code==200
    with client.session_transaction() as session:session.clear()
    assert client.get(path).status_code==302


def test_archive_manual_host_mapping_and_search_result_cache_is_bounded(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);collector=receive(store)
    with collector.archive.connect() as c:
        c.execute("UPDATE smb_outbox SET payload=json_set(payload,'$.client_mac','aa:bb:cc:dd:ee:ff')")
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',('host','Host',time.time()))
    source=store.rows('SELECT id FROM log_sources')[0]['id']
    logs.bind(store,source,'aa:bb:cc:dd:ee:ff','host')
    fake,io=smb;worker=archive.Archiver(store,vault,io);worker.upload(cfg)
    tasks=[]
    for _ in range(10):
        task=archive.submit(store,vault,'search',cfg,{'start':time.time()-60,'end':time.time()+60,'machine':'host'})
        worker.process_job();tasks.append(task)
    worker.expire_jobs()
    assert archive.job(store,tasks[0])['state']=='expired'
    assert len(list((Path(store.path).parent/'log-archive-results').glob('*.json')))==8
    assert archive.search_results(store,tasks[-1])[0]['associations'][0]['machine_id']=='host'


def test_corrupt_upload_and_remote_checksum_never_acknowledge(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);receive(store)
    fake,io=smb;worker=archive.Archiver(store,vault,io)
    data,path=worker.pending_batch();path.write_bytes(b'corrupted')
    with pytest.raises(OSError,match='checksum'):worker.upload(cfg)
    assert worker.archive.backlog()['pending']==1
    with pytest.raises(ValueError):io(cfg,'delete',names=['../../other-file'])


def test_smb_timeout_is_bounded_and_never_puts_secrets_in_arguments(monkeypatch):
    import subprocess
    captured={}
    def run(args,**kwargs):
        captured.update(args=args,**kwargs)
        raise subprocess.TimeoutExpired(args,kwargs['timeout'])
    monkeypatch.setattr(archive.subprocess,'run',run)
    with pytest.raises(OSError,match='timed out'):archive.operation({'password':'hidden-secret'},'test')
    assert 'hidden-secret' not in ' '.join(captured['args'])
    assert captured['timeout']==30 and json.loads(captured['input'])['connection']['password']=='hidden-secret'


@pytest.mark.parametrize('failure, expected', [
    (TimeoutError('secret timeout details'), 'timed out'),
    (ConnectionRefusedError(errno.ECONNREFUSED, 'secret connection details'), 'connection refused'),
    (socket.gaierror(-2, 'secret DNS details'), 'hostname could not be resolved'),
    (OSError(errno.EHOSTUNREACH, 'secret routing details'), 'server is unreachable'),
    (ConnectionResetError(errno.ECONNRESET, 'secret reset details'), 'closed the connection'),
])
def test_real_smb_transport_wrapped_errors_reach_worker_output(monkeypatch, capsys, failure, expected):
    import io
    import socket
    from smbprotocol.transport import Tcp
    def fail(*args, **kwargs): raise failure
    monkeypatch.setattr(socket, 'create_connection', fail)
    def execute(request): Tcp('private-server.example', 445, timeout=5).connect()
    monkeypatch.setattr(smb_archive_io, 'execute', execute)
    monkeypatch.setattr(smb_archive_io.sys, 'stdin', io.StringIO(json.dumps({'connection':{'password':'secret'}})))
    with pytest.raises(SystemExit) as result: smb_archive_io.main()
    assert result.value.code == 1
    output = json.loads(capsys.readouterr().out)
    assert not output['ok'] and expected in output['error']
    assert 'secret' not in output['error'] and 'private-server' not in output['error']


@pytest.mark.parametrize('status, expected', [
    ('STATUS_ACCESS_DENIED', 'access denied'),
    ('STATUS_LOGON_FAILURE', 'login failed'),
    ('STATUS_WRONG_PASSWORD', 'login failed'),
    ('STATUS_BAD_NETWORK_NAME', 'share not found'),
    ('STATUS_DISK_FULL', 'storage is full'),
])
def test_smb_file_status_errors_are_classified_without_paths(status, expected):
    from smbprotocol.header import NtStatus
    from smbprotocol.exceptions import SMBOSError
    error = SMBOSError(getattr(NtStatus,status), r'\\private-server\private-share\secret')
    result = smb_archive_io.error_message(error)
    assert expected in result
    assert 'private' not in result and 'secret' not in result


def test_unknown_smb_errors_remain_redacted():
    result = smb_archive_io.error_message(ValueError('password=secret username=private'))
    assert result.startswith('SMB operation failed.') and 'secret' not in result and 'private' not in result
