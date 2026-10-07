import time
from pathlib import Path
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


def test_local_counts_only_evidence_and_deduplicates_pending_copies(environment):
    _,store,vault=environment;configure(store,vault);receive(store)
    telemetry.record(store,'metrics','m','m',{'cpu_percent':2,'interface':'réseau'})
    expected=store.rows('SELECT coalesce(sum(length(cast(payload AS BLOB))),0) used FROM telemetry_records')[0]['used']
    from aiticket import network_logs as logs
    with logs.reader(store) as c:
        network=c.execute('SELECT sum(size-512) FROM events').fetchone()[0]
        queued=c.execute('SELECT sum(size-256) FROM smb_outbox').fetchone()[0]
    values=capacity.local(store)
    assert values['telemetry_bytes']==expected and values['network_bytes']==network
    assert values['record_bytes']==expected+network
    # Unrelated settings, journals and indexes cannot inflate the meter.
    store.save('unrelated_large_setting','x'*100000)
    assert capacity.local(store)==values
    with logs.Archive(logs.database(store)).connect() as c:c.execute('DELETE FROM events')
    assert capacity.local(store)['network_bytes']==queued


def test_decimal_storage_units_never_display_bytes_or_binary_units():
    assert capacity.human(123456)=='0.123 MB'
    assert capacity.human(1_234_567_890)=='1.235 GB'
    assert capacity.human(0)=='0.000 MB'
    assert capacity.human(12)=='<0.001 MB'
    assert capacity.human(None)=='Unavailable'


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
    worker.refresh_storage(cfg);saved=capacity.remote(store,cfg);assert saved['archive_bytes']==0 and not saved['stale']
    worker.io=Mock(side_effect=OSError('secret account error'))
    worker.refresh_storage(cfg);assert not worker.io.called
    worker.next_storage=0;worker.refresh_storage(cfg)
    stale=capacity.remote(store,cfg);assert stale['archive_bytes']==saved['archive_bytes'] and stale['stale'] and 'secret' not in stale['error']
    assert 'archive_bytes' not in capacity.remote(store,{**cfg,'share':'NewShare'})
    worker.io=smb[1];worker.next_storage=0;worker.refresh_storage({**cfg,'enabled':False})
    assert not capacity.remote(store,cfg)['stale']


def test_capacity_failure_does_not_stop_uploads(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);receive(store)
    def io(cfg,action,**kw):
        if action=='usage':raise OSError('Unsupported capacity')
        return smb[1](cfg,action,**kw)
    worker=archive.Archiver(store,vault,io);worker.step()
    assert smb[1](cfg,'catalog')['files']
    assert capacity.remote(store,cfg)['error']
    assert not store.setting('network_log_archive_status')['error']


def test_settings_and_history_show_only_record_usage_in_mb_gb(signed_in):
    client,store,vault,_=signed_in;cfg=configure(store,vault)
    response=client.get('/telemetry-history');assert response.status_code==200
    assert b'Collected evidence storage' in response.data and b'Archive usage unavailable' in response.data
    store.save('archive_storage',{'target':capacity.identity(cfg),'at':time.time()-1000,**capacity.meter(1000000000,250000000,200000000),'archive_bytes':123456,'network_bytes':23456,'telemetry_bytes':100000,'archive_partial':False,'error':'SMB archive file usage could not be read.'})
    for path in ('/settings/network-logs','/telemetry-history'):
        page=client.get(path).data
        assert b'0.123 MB' in page and b'stale' in page
        assert b'750,000,000' not in page and b'123,456 bytes' not in page and b'GiB' not in page
        assert b'aria-label="SMB record data"' in page
        assert b'data-capacity-percent="100.0"' in page and b'/static/archive-storage.js' in page
        assert b'style="width:' not in page
    with client.session_transaction() as s:s.clear()
    assert client.get('/telemetry-history').status_code==302


def test_usage_ignores_incomplete_files_and_does_not_need_volume_stats(environment,smb,monkeypatch):
    _,store,vault=environment;cfg=configure(store,vault);receive(store)
    worker=archive.Archiver(store,vault,smb[1]);worker.upload(cfg)
    files=list(smb[0].root.rglob('*.jsonl.gz'));assert files
    Path(str(files[0])+'.partial').write_bytes(b'x'*10000)
    import smbclient
    volume=Mock(side_effect=OSError('unsupported'))
    monkeypatch.setattr(smbclient,'stat_volume',volume)
    result=smb[1](cfg,'usage')
    assert result['archive_bytes']==sum(p.stat().st_size for p in files)
    assert result['network_bytes']==result['archive_bytes'] and result['telemetry_bytes']==0
    assert 'total' not in result and not volume.called
