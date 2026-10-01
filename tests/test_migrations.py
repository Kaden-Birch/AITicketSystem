import sqlite3
import pytest
from aiticket.db import Store, SCHEMA
from aiticket.migrations import MIGRATIONS


def legacy(path):
    c=sqlite3.connect(path)
    c.executescript(SCHEMA)
    c.execute('INSERT INTO schema_version VALUES(1)')
    c.execute("INSERT INTO machines VALUES('m','Existing machine',NULL,1)")
    c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('c','m','App','http','{}',60)")
    c.execute("INSERT INTO incidents VALUES('i','m','c','medium','Open',1,2,'{}',NULL)")
    c.execute("INSERT INTO timeline VALUES('t','i',1,'monitor','opened','Existing evidence')")
    c.commit()
    c.close()


def test_schema_one_upgrade_preserves_history(tmp_path):
    path=tmp_path/'legacy.db'
    legacy(path)
    store=Store(path)
    assert store.rows('SELECT version FROM schema_version')==[{'version':3}]
    assert store.rows('SELECT * FROM timeline')[0]['text']=='Existing evidence'
    assert store.rows('SELECT * FROM machines')[0]['name']=='Existing machine'
    Store(path)
    assert len(store.rows('SELECT * FROM schema_version'))==1


def test_failed_upgrade_rolls_back_all_changes(tmp_path,monkeypatch):
    path=tmp_path/'legacy.db'
    legacy(path)
    monkeypatch.setitem(MIGRATIONS,2,('CREATE TABLE tentative(x INTEGER)','INVALID SQL'))
    with pytest.raises(sqlite3.OperationalError):
        Store(path)
    with sqlite3.connect(path) as c:
        assert c.execute('SELECT version FROM schema_version').fetchone()[0]==1
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='tentative'").fetchone()
        assert c.execute('SELECT count(*) FROM timeline').fetchone()[0]==1


def test_newer_database_rejected(environment):
    _,store,_=environment
    with store.connect() as c:
        c.execute('UPDATE schema_version SET version=999')
    with pytest.raises(RuntimeError,match='newer'):
        Store(store.path)
    assert store.rows('SELECT version FROM schema_version')[0]['version']==999


def test_audit_and_timeline_immutable(environment):
    _,store,_=environment
    with store.connect() as c:
        c.execute("INSERT INTO machines VALUES('m','Machine',NULL,1)")
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('c','m','App','http','{}',60)")
        c.execute("INSERT INTO incidents VALUES('i','m','c','medium','Open',1,2,'{}',NULL)")
        store.timeline(c,'i','note','Original')
        store.audit(c,'test.event','m')
    for statement in ('UPDATE timeline SET text=\'Changed\'','DELETE FROM timeline','UPDATE audit SET action=\'changed\'','DELETE FROM audit'):
        with pytest.raises(sqlite3.IntegrityError,match='immutable'):
            with store.connect() as c:
                c.execute(statement)


def test_settings_transaction_rolls_back(environment):
    _,store,_=environment
    store.save('existing',1)
    with pytest.raises(TypeError):
        store.save_many({'existing':2,'invalid':object()},actor='user')
    assert store.setting('existing')==1
    assert not store.rows('SELECT * FROM audit')
