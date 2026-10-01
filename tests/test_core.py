import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from aiticket.db import Store
from aiticket.engine import observe, claim
from aiticket.security import hermes_headers
from aiticket.worker import deliver


def seed(store, parent=None, severity='medium'):
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,parent_id,created) VALUES(?,?,?,?)', ('m', 'Machine', parent, 1))
        c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,severity) VALUES(?,?,?,?,?,?,?)', ('c', 'm', 'App', 'http', '{}', 60, severity))


def test_threshold_dedup_recovery_and_restart(environment):
    _, store, _ = environment
    seed(store)
    for i in range(1, 3):
        observe(store, 'c', False, {'status': 503}, now=i)
    assert not store.rows('SELECT * FROM incidents')
    observe(store, 'c', False, {'status': 503}, now=3)
    resumed = Store(store.path)
    observe(resumed, 'c', False, {'status': 503}, now=4)
    assert len(store.rows('SELECT * FROM incidents')) == 1
    assert len(store.rows('SELECT * FROM deliveries')) == 1
    report = json.loads(store.rows('SELECT * FROM incidents')[0]['report'])
    assert report['cause'] == 'Unknown' and report['ai_status'] == 'disabled'
    observe(resumed, 'c', True, {'status': 200}, now=5)
    assert store.rows('SELECT * FROM incidents')[0]['closed'] is None
    observe(resumed, 'c', True, {'status': 200}, now=6)
    assert store.rows('SELECT * FROM incidents')[0]['closed'] == 6
    assert len(store.rows('SELECT * FROM deliveries')) == 2


def test_atomic_leases_and_abandoned_recovery(environment):
    _, store, _ = environment
    seed(store)
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = list(pool.map(lambda _: claim(store, 'checks', now=10), range(4)))
    assert sum(j is not None for j in jobs) == 1
    first = next(j for j in jobs if j)
    assert claim(Store(store.path), 'checks', now=69) is None
    second = claim(store, 'checks', now=71)
    assert second['lease_token'] != first['lease_token']
    observe(store, 'c', False, {}, now=72, lease_token=first['lease_token'])
    assert not store.rows('SELECT * FROM observations')


def test_parent_failure_preserves_child_observations(environment):
    _, store, _ = environment
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,parent_id,created) VALUES(?,?,NULL,?)', ('p', 'Parent', 1))
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,health) VALUES('pc','p','Parent','tcp','{}',60,'down')")
    seed(store, parent='p')
    for i in range(3):
        observe(store, 'c', False, {}, now=i+1)
    assert len(store.rows('SELECT * FROM observations')) == 3
    assert not store.rows('SELECT * FROM incidents')


def test_maintenance_and_severity_filter(environment):
    _, store, _ = environment
    seed(store, severity='low')
    with store.connect() as c:
        c.execute('UPDATE checks SET maintenance_until=10')
    for i in range(3):
        observe(store, 'c', False, {}, now=i+1)
    assert not store.rows('SELECT * FROM incidents')
    observe(store, 'c', False, {}, now=11)
    assert len(store.rows('SELECT * FROM incidents')) == 1
    assert not store.rows('SELECT * FROM deliveries')


def test_notification_superseded_and_safe_mentions(environment):
    _, store, vault = environment
    seed(store)
    store.save('discord_secret', vault.encrypt('https://discord.com/api/webhooks/example'))
    for i in range(3):
        observe(store, 'c', False, {}, now=i+1)
    job = claim(store, 'deliveries', now=4)
    with patch('aiticket.worker.requests.post') as post:
        post.return_value.status_code = 204
        deliver(store, vault, job)
        assert post.call_args.kwargs['json']['allowed_mentions'] == {'parse': []}
    assert store.rows('SELECT * FROM deliveries')[0]['state'] == 'completed'
    observe(store, 'c', True, {}, now=5)
    observe(store, 'c', True, {}, now=6)


def test_queue_expiry_and_restart(environment):
    _, store, _ = environment
    seed(store)
    for i in range(3):
        observe(store, 'c', False, {}, now=i+1)
    first = claim(store, 'deliveries', now=4)
    assert first
    assert not claim(Store(store.path), 'deliveries', now=5)
    assert claim(Store(store.path), 'deliveries', now=65)
    assert not claim(store, 'deliveries', now=90000)
    assert store.rows('SELECT * FROM deliveries')[0]['state'] == 'expired'


def test_hermes_v2_signature_and_fresh_retry_timestamp():
    body = b'{"event":"one"}'
    headers = hermes_headers('secret', body, 'stable-id', now=100)
    assert headers['X-Webhook-Signature-V2'] == hmac.new(b'secret', b'100.'+body, hashlib.sha256).hexdigest()
    retry = hermes_headers('secret', body, 'stable-id', now=200)
    assert retry['X-Request-ID'] == headers['X-Request-ID']
    assert retry['X-Webhook-Signature-V2'] != headers['X-Webhook-Signature-V2']
