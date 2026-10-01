import json
import sqlite3
import pytest
from aiticket.administration import change_password, export_preferences, import_preferences, prune, rotate_key
from aiticket.security import Vault, digest


def test_preferences_roundtrip_and_reject_secrets(environment):
    _, store, _ = environment
    store.save_many({'discord_secret': 'hidden', 'retention_days': 30, 'discord_minimum': 'high'})
    document = export_preferences(store)
    assert 'hidden' not in json.dumps(document)
    import_preferences(store, document)
    document['settings']['admin_hash'] = 'bad'
    with pytest.raises(ValueError):
        import_preferences(store, document)
    assert store.setting('retention_days') == 30
    for value in (True, 0, 3651, '30'):
        with pytest.raises(ValueError):
            import_preferences(store, {'format': 'aiticket-preferences', 'version': 1, 'settings': {'discord_minimum': 'info', 'retention_days': value}})
        assert store.setting('discord_minimum') == 'high'


def test_retention_preserves_incident_evidence(environment):
    _, store, _ = environment
    with store.connect() as c:
        c.execute("INSERT INTO machines VALUES('m','Machine',NULL,1)")
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('c','m','App','http','{}',60)")
        c.execute("INSERT INTO incidents(id,machine_id,check_id,severity,status,first_seen,last_seen,report) VALUES('i','m','c','medium','Open',1,2,'{}')")
        c.execute("INSERT INTO observations VALUES('attached','c',1,'down','{}')")
        c.execute("INSERT INTO observations VALUES('routine','c',1,'up','{}')")
        c.execute("INSERT INTO observations VALUES('fresh','c',99999999,'up','{}')")
        c.execute("INSERT INTO incident_observations VALUES('i','attached')")
        store.timeline(c, 'i', 'note', 'Retain')
    prune(store, now=10000000)
    assert {r['id'] for r in store.rows('SELECT * FROM observations')} == {'attached', 'fresh'}
    assert len(store.rows('SELECT * FROM timeline')) == 1
    assert len(store.rows('SELECT * FROM audit')) == 1
    prune(store, now=10000001)
    assert len(store.rows('SELECT * FROM audit')) == 1


def test_password_invalidates_other_sessions(signed_in, environment):
    client, store, _, csrf = signed_in
    other = environment[0].test_client()
    other.get('/login')
    with other.session_transaction() as session:
        token = session['csrf']
    other.post('/login', data={'csrf': token, 'password': 'test-password-long'})
    assert client.post('/administration', data={'csrf': csrf, 'operation': 'password', 'current': 'wrong', 'password': 'new-password-long', 'confirm': 'new-password-long'}).status_code == 400
    assert client.post('/administration', data={'csrf': csrf, 'operation': 'password', 'current': 'test-password-long', 'password': 'new-password-long', 'confirm': 'new-password-long'}).status_code == 302
    assert other.get('/').status_code == 302
    assert client.get('/').status_code == 302
    assert 'new-password-long' not in json.dumps(store.rows('SELECT * FROM audit'))


def test_key_rotation_all_credentials_and_rollback(environment, tmp_path):
    _, store, old = environment
    store.save('discord_secret', old.encrypt('discord-value'))
    with store.connect() as c:
        c.execute("INSERT INTO machines VALUES('m','Machine',NULL,1)")
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('c','m','PVE','proxmox',?,60)", (json.dumps({'token_secret': old.encrypt('legacy-value')}),))
        c.execute("INSERT INTO proxmox_clusters VALUES('cluster','Cluster')")
        c.execute("INSERT INTO proxmox_connections VALUES('p','cluster','PVE','https://192.0.2.1','id',?,NULL,NULL,NULL)", (old.encrypt('connection-value'),))
    old_session = old.decrypt(store.setting('session_secret'))
    destination = tmp_path / 'new.key'
    new = rotate_key(store, old, destination)
    assert new.decrypt(store.setting('session_secret')) == old_session
    assert new.decrypt(store.setting('discord_secret')) == 'discord-value'
    assert new.decrypt(store.rows('SELECT token_secret FROM proxmox_connections')[0]['token_secret']) == 'connection-value'
    assert new.decrypt(json.loads(store.rows('SELECT config FROM checks')[0]['config'])['token_secret']) == 'legacy-value'
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        rotate_key(store, new, destination)
    # Corrupt a stored secret: re-encryption rolls back the entire database.
    store.save('discord_secret', 'corrupt')
    before = store.setting('session_secret')
    with pytest.raises(Exception):
        rotate_key(store, new, tmp_path / 'failed.key')
    assert store.setting('session_secret') == before
    assert len(store.rows("SELECT * FROM audit WHERE action='encryption.rotated'")) == 1


def test_rotation_revokes_old_token_preserves_identity(signed_in):
    client, store, _, csrf = signed_in
    with store.connect() as c:
        c.execute("INSERT INTO machines VALUES('m','Machine',NULL,1)")
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('a','m',?)", (digest('old-token'),))
    response = client.post('/agents/a/rotate', data={'csrf': csrf})
    assert response.status_code == 200
    assert store.rows('SELECT * FROM agents')[0]['revoked'] == 1
    assert client.post('/api/agent/heartbeat', headers={'Authorization': 'Bearer old-token'}, json={'event_id': 'test'}).status_code == 401
    token = __import__('re').search(r'<pre>([^<]+)</pre>', response.text).group(1)
    result = client.post('/api/agent/enroll', json={'token': token})
    assert result.status_code == 200
    assert result.json['agent_id'] == 'a'
    assert store.rows('SELECT * FROM agents')[0]['credential_digest'] != digest('old-token')


def test_administration_requires_login_and_csrf(signed_in, environment):
    client, store, _, csrf = signed_in
    assert environment[0].test_client().get('/administration/export').status_code == 302
    assert client.post('/administration', data={'operation': 'retention', 'days': 30}).status_code == 403
    assert client.get('/administration').status_code == 200
    assert client.get('/administration/export').json['format'] == 'aiticket-preferences'


def test_schema_six_migrates_without_losing_data(tmp_path):
    from aiticket.db import SCHEMA, Store
    from aiticket.migrations import MIGRATIONS
    path = tmp_path / 'six.db'
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        for version in range(2, 7):
            for sql in MIGRATIONS[version]:
                c.execute(sql)
        c.execute('INSERT INTO schema_version VALUES(6)')
        c.execute("INSERT INTO machines VALUES('existing','Preserved',NULL,1)")
    store = Store(path)
    assert store.rows('SELECT version FROM schema_version') == [{'version': 7}]
    assert store.rows('SELECT name FROM machines') == [{'name': 'Preserved'}]
    assert store.rows("SELECT name FROM sqlite_master WHERE name='incident_observation_lookup'")


def test_notification_transfer_accepts_ui_limits(environment):
    _, store, _ = environment
    document = {'format': 'aiticket-preferences', 'version': 1, 'settings': {'notification_policy': {'reminder_seconds': 2592000, 'escalate_after_seconds': 0, 'escalate_to': 'high'}}}
    import_preferences(store, document)
    assert store.setting('notification_policy')['reminder_seconds'] == 2592000
    document['settings']['notification_policy']['reminder_seconds'] = 1
    with pytest.raises(ValueError):
        import_preferences(store, document)


def test_console_password_recovery(environment, monkeypatch):
    from aiticket.__main__ import main
    from werkzeug.security import check_password_hash
    _, store, _ = environment
    from pathlib import Path
    monkeypatch.setattr('sys.argv', ['aiticket', 'reset-password', '--data', str(Path(store.path).parent)])
    monkeypatch.setattr('getpass.getpass', lambda prompt: 'console-password-new')
    main()
    assert check_password_hash(store.setting('admin_hash'), 'console-password-new')
    assert store.setting('auth_generation')
    assert store.rows('SELECT actor FROM audit') == [{'actor': 'console'}]
