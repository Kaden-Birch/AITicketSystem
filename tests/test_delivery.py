from unittest.mock import patch
from aiticket.engine import observe, claim
from aiticket.worker import deliver
from test_core import seed


def test_recovered_incident_skips_old_opening(environment):
    _, store, vault = environment
    seed(store)
    store.save('discord_secret', vault.encrypt('https://discord.com/api/webhooks/test'))
    for i in range(3):
        observe(store, 'c', False, {}, now=i+1)
    observe(store, 'c', True, {}, now=4)
    observe(store, 'c', True, {}, now=5)
    job = claim(store, 'deliveries', now=6)
    with patch('aiticket.worker.requests.post') as post:
        deliver(store,vault,job)
        post.assert_not_called()
    assert store.rows('SELECT * FROM deliveries WHERE id=?',(job['id'],))[0]['state'] == 'superseded'


def test_rate_limit_and_safe_retry(environment):
    _, store, vault = environment
    seed(store)
    store.save('discord_secret', vault.encrypt('https://discord.com/api/webhooks/test'))
    for i in range(3):
        observe(store,'c',False,{},now=i+1)
    job = claim(store,'deliveries',now=4)
    with patch('aiticket.worker.requests.post') as post:
        post.return_value.status_code = 429
        post.return_value.headers = {'Retry-After':'120'}
        with patch('aiticket.worker.time.time', return_value=10):
            deliver(store,vault,job)
    result = store.rows('SELECT * FROM deliveries')[0]
    assert result['state']=='pending' and result['next_attempt']>=130
    assert result['lease_token'] is None
