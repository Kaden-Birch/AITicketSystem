import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import pytest
from aiticket import telemetry_archive as telemetry
from aiticket import telemetry_recovery as recovery
from aiticket.sqlite_runtime import patched,require_patched


def fixture_source(store,tmp_path):
    store.save('telemetry_capture_enabled',True)
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('server','Protected host',1)")
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('agent','server','protected-credential')")
        store.audit(c,'fixture','server',{'evidence':'preserved'})
    telemetry.record(store,'metrics','server','server',{'cpu':10},at=100)
    source=tmp_path/'working.db'
    with store.connect() as src,sqlite3.connect(source) as dst:src.backup(dst)
    return source


def test_construct_preserves_other_tables_and_rebuilds_telemetry(environment,tmp_path):
    _,store,_=environment;source=fixture_source(store,tmp_path);salvage=tmp_path/'salvage.db';shutil.copy2(source,salvage)
    with sqlite3.connect(salvage) as c:
        c.execute('DROP TRIGGER telemetry_added')
        c.execute("INSERT INTO telemetry_records VALUES('bad','metrics',NULL,NULL,1,1,'not-json',200,0)")
    original_hash=hashlib.sha256(source.read_bytes()).hexdigest();output=tmp_path/'candidate.db'
    report=recovery.construct(source,output,salvage)
    assert report['ready_for_review'] and report['telemetry_rejected']==1
    assert report['integrity']==['ok'] and report['foreign_key_errors']==0
    assert hashlib.sha256(source.read_bytes()).hexdigest()==original_hash
    with sqlite3.connect(output) as db:
        assert db.execute('SELECT name FROM machines').fetchone()[0]=='Protected host'
        assert db.execute('SELECT credential_digest FROM agents').fetchone()[0]=='protected-credential'
        pending=db.execute('SELECT sum(size) FROM telemetry_records WHERE uploaded=0').fetchone()[0]
        assert db.execute('SELECT pending_bytes FROM telemetry_archive_meta').fetchone()[0]==pending
        with pytest.raises(sqlite3.IntegrityError):db.execute("DELETE FROM audit")
    assert not report['installed']


def test_does_not_copy_salvaged_configuration(environment,tmp_path):
    _,store,_=environment;source=fixture_source(store,tmp_path);salvage=tmp_path/'salvage.db';shutil.copy2(source,salvage)
    with sqlite3.connect(salvage) as c:c.execute("UPDATE machines SET name='Untrusted recovered data'")
    output=tmp_path/'candidate.db';recovery.construct(source,output,salvage)
    with sqlite3.connect(output) as c:assert c.execute('SELECT name FROM machines').fetchone()[0]=='Protected host'


def test_patched_version_guard_before_opening_database(monkeypatch,tmp_path):
    assert patched((3,54,0)) and patched((3,51,3)) and patched((3,50,7)) and patched((3,44,6))
    assert not patched((3,46,1)) and not patched((3,51,2))
    monkeypatch.setenv('AITICKET_REQUIRE_PATCHED_SQLITE','1');monkeypatch.setattr(sqlite3,'sqlite_version_info',(3,46,1))
    with pytest.raises(RuntimeError,match='WAL-reset'):require_patched()
    from aiticket.db import Store
    path=tmp_path/'must-not-create.db'
    with pytest.raises(RuntimeError):Store(path)
    assert not path.exists()


def test_recovery_refuses_originals_and_existing_targets(tmp_path):
    source=tmp_path/'original'/'app.db';source.parent.mkdir();source.touch()
    with pytest.raises(ValueError,match='protected original'):recovery.recover(source,tmp_path/'candidate.db','unused')
    source=tmp_path/'working.db';source.touch();output=tmp_path/'candidate.db';output.touch()
    with pytest.raises(ValueError,match='new, separate'):recovery.recover(source,output,'unused')


def test_real_recover_reorders_damaged_telemetry_tree(environment,tmp_path):
    import os
    shell=os.environ.get('AITICKET_TEST_SQLITE_SHELL')
    if not shell:pytest.skip('Native patched SQLite shell not installed')
    _,store,_=environment;source=fixture_source(store,tmp_path)
    with sqlite3.connect(source) as db:
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        page=db.execute("SELECT rootpage FROM sqlite_schema WHERE name='telemetry_records'").fetchone()[0]
        size=db.execute('PRAGMA page_size').fetchone()[0]
        expected=db.execute('SELECT count(*) FROM telemetry_records').fetchone()[0]
    # Swap two leaf cell pointers in this disposable fixture, reproducing rowid ordering damage.
    data=bytearray(source.read_bytes());offset=(page-1)*size
    assert data[offset]==13
    count=int.from_bytes(data[offset+3:offset+5],'big');assert count>=2
    a=offset+8;b=a+2
    data[a:a+2],data[b:b+2]=data[b:b+2],data[a:a+2]
    source.write_bytes(data);source_hash=hashlib.sha256(data).hexdigest()
    output=tmp_path/'recovered.db'
    report=recovery.recover(source,output,shell)
    assert report['integrity']==['ok'] and report['telemetry_recovered']==expected
    assert report['telemetry_rejected']==0 and not report['installed']
    assert source_hash==hashlib.sha256(source.read_bytes()).hexdigest()
    assert output.with_name(output.name+'.report.json').is_file()


def test_archive_corruption_halts_retry_and_error_details_are_safe(environment):
    from aiticket.log_archive import Archiver
    _,store,vault=environment;worker=Archiver(store,vault)
    error=sqlite3.DatabaseError('private user/path/credential')
    error.sqlite_errorcode=sqlite3.SQLITE_CORRUPT
    worker.stage='telemetry upload';worker.failure(error)
    assert worker.halted and worker.state['next_retry'] is None
    assert 'corruption' in worker.state['error'] and 'private' not in worker.state['error']
    assert worker.state['error_stage']=='telemetry upload'


def test_temporary_workspace_uses_candidate_volume_and_restores_environment(tmp_path,monkeypatch):
    import os
    import subprocess
    import sys
    monkeypatch.setenv('SQLITE_TMPDIR','/previous-sqlite')
    monkeypatch.delenv('TMPDIR',raising=False)
    with pytest.raises(RuntimeError,match='simulated failure'):
        with recovery.temporary_workspace(tmp_path) as temporary:
            assert temporary.parent==tmp_path and temporary.is_dir()
            assert temporary.stat().st_mode&0o777==0o700
            assert os.environ['SQLITE_TMPDIR']==os.environ['TMPDIR']==str(temporary)
            child=subprocess.check_output([sys.executable,'-c',"import os;print(os.environ['SQLITE_TMPDIR']);print(os.environ['TMPDIR'])"],text=True)
            assert child.splitlines()==[str(temporary)]*2
            raise RuntimeError('simulated failure')
    assert not temporary.exists()
    assert os.environ['SQLITE_TMPDIR']=='/previous-sqlite' and 'TMPDIR' not in os.environ
