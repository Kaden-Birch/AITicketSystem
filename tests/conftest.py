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
