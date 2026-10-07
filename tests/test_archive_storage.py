import os,time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from aiticket import archive_storage as capacity,log_archive as archive,smb_archive_io
from test_log_archive import configure,smb,receive
from test_telemetry_archive import exporter
from aiticket import telemetry_archive as telemetry


def test_meter_reserved_space_thresholds_and_invalid_reports():
    assert capacity.meter(1000,800,700)=={'used':200,'total':1000,'available':700,'percent':20.0,'color':'good'}
    assert capacity.meter(1000,200,100)['color']=='moderate'
    assert capacity.meter(1000,50,25)['color']=='high'
    for values in [(0,0,0),(100,101,0),(100,50,-1),(100.0,50,50)]:
        with pytest.raises(ValueError):capacity.meter(*values)


def test_local_shared_volume_exact_database_sizes_and_separate_volumes(environment,monkeypatch,tmp_path):
    _,store,_=environment;path=Path(store.path);network=path.parent/'logs'/'archive.db';network.parent.mkdir();network.write_bytes(b'abc')
    Path(str(network)+'-wal').write_bytes(b'wal')
    monkeypatch.setenv('AITICKET_LOG_DATA',str(network))
    monkeypatch.setattr(os,'statvfs',lambda p:SimpleNamespace(f_blocks=1000,f_frsize=4096,f_bsize=4096,f_bfree=250,f_bavail=200))
    values=capacity.local(store);assert len(values)==1 and values[0]['used']==750*4096
    assert values[0]['database_bytes']>=path.stat().st_size+6
    stat=Path.stat
    def separated(self,*args,**kwargs):
        value=stat(self,*args,**kwargs)
        if self==network.parent:return SimpleNamespace(st_dev=value.st_dev+1)
        return value
    monkeypatch.setattr(Path,'stat',separated)
    assert len(capacity.local(store))==2


def test_remote_capacity_file_sizes_and_no_foreign_namespace_count(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault,smb_folder='aiticket-network-logs/nested')
    receive(store);worker=archive.Archiver(store,vault,smb[1]);worker.upload(cfg)
    telemetry.record(store,'metrics','m','m',{'cpu_percent':2});exporter(store,smb[1]).step(cfg)
    root=smb[0].root;files=list(root.rglob('*.jsonl.gz'));assert files
    foreign=root/'unrelated.txt';foreign.write_bytes(b'not counted')
    result=smb[1](cfg,'capacity')
    assert result['total']==1024**4 and result['used']==424*1024**3
    assert result['available']==500*1024**3
    assert result['archive_bytes']==sum(p.stat().st_size for p in files)
    assert not result['archive_partial']
    result2=smb[1](cfg,'capacity',dataset='telemetry')
    assert result2['archive_bytes']==result['archive_bytes']


def test_background_poll_stale_errors_and_destination_change(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);worker=archive.Archiver(store,vault,smb[1])
    worker.refresh_storage(cfg);saved=capacity.remote(store,cfg);assert saved['total'] and not saved['stale']
    worker.io=Mock(side_effect=OSError('secret account error'))
    worker.refresh_storage(cfg);assert not worker.io.called
    worker.next_storage=0;worker.refresh_storage(cfg)
    stale=capacity.remote(store,cfg);assert stale['used']==saved['used'] and stale['stale'] and 'secret' not in stale['error']
    assert 'used' not in capacity.remote(store,{**cfg,'share':'NewShare'})
    worker.io=smb[1];worker.next_storage=0;worker.refresh_storage({**cfg,'enabled':False})
    assert not capacity.remote(store,cfg)['stale']


def test_capacity_failure_does_not_stop_uploads(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);receive(store)
    def io(cfg,action,**kw):
        if action=='capacity':raise OSError('Unsupported capacity')
        return smb[1](cfg,action,**kw)
    worker=archive.Archiver(store,vault,io);worker.step()
    assert smb[1](cfg,'catalog')['files']
    assert capacity.remote(store,cfg)['error']
    assert not store.setting('network_log_archive_status')['error']


def test_settings_usage_bars_exact_counts_unavailable_stale_and_auth(signed_in):
    client,store,vault,_=signed_in;cfg=configure(store,vault)
    response=client.get('/settings/network-logs');assert response.status_code==200
    assert b'Archive storage usage' in response.data and b'Capacity unavailable' in response.data
    store.save('archive_storage',{'target':capacity.identity(cfg),'at':time.time()-1000,**capacity.meter(1000000000,250000000,200000000),'archive_bytes':123456,'archive_partial':False,'error':'SMB capacity could not be read.'})
    page=client.get('/settings/network-logs').data
    assert b'750,000,000 used / 1,000,000,000 total bytes' in page
    assert b'123,456 bytes' in page and b'stale' in page
    assert b'aria-label="SMB storage used space"' in page
    assert b'data-capacity-percent="75.0"' in page and b'/static/archive-storage.js' in page
    assert b'style="width:' not in page
    with client.session_transaction() as s:s.clear()
    assert client.get('/settings/network-logs').status_code==302
