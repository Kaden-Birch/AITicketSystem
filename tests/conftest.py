import secrets
import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash
from aiticket.db import Store
from aiticket.security import Vault
from aiticket.app import create_app

@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.delenv('AITICKET_KEY_FILE', raising=False)
    (tmp_path / 'encryption.key').write_bytes(Fernet.generate_key())
    store = Store(tmp_path / 'app.db')
    vault = Vault(tmp_path / 'encryption.key')
    store.save('session_secret', vault.encrypt(secrets.token_urlsafe(32)))
    store.save('admin_hash', generate_password_hash('test-password-long'))
    app = create_app(tmp_path, testing=True)
    return app, store, vault

@pytest.fixture
def signed_in(environment):
    app, store, vault = environment
    client = app.test_client()
    client.get('/login')
    with client.session_transaction() as s:
        csrf = s['csrf']
    assert client.post('/login', data={'csrf': csrf, 'password': 'test-password-long'}).status_code == 302
    with client.session_transaction() as s:
        csrf = s['csrf']
    return client, store, vault, csrf


def remove_schema44(c):
    for row in c.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'telemetry_%'").fetchall():c.execute('DROP TRIGGER '+row[0])
    for table in ('telemetry_records','telemetry_archive_meta'):c.execute('DROP TABLE IF EXISTS '+table)


def remove_schema38(c):
    """Reconstruct old fixtures by removing the new schema before lowering its marker."""
    remove_schema44(c)
    for table in ('log_host_bindings','log_sources'):c.execute('DROP TABLE '+table)
    for table in ('kb_workflow_events','kb_workflow_runs','kb_workflows'):c.execute('DROP TABLE '+table)
    for table in ('kb_requests','kb_versions','kb_articles','kb_folders','change_events','telegram_updates','telegram_outbox'):c.execute('DROP TABLE '+table)
    c.execute('ALTER TABLE ai_jobs DROP COLUMN read_only')
    for table in ('ticket_targets','ticket_group_exclusions','ticket_groups'):c.execute('DROP TABLE '+table)
    c.execute('ALTER TABLE command_jobs DROP COLUMN read_only_command')
    for column in ('automatic','maintenance_changes','maintenance_paused_at'):c.execute('ALTER TABLE ai_jobs DROP COLUMN '+column)
