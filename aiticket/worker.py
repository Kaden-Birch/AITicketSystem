import json
import logging
import random
import time
import requests
from .adapters import probe
from .engine import claim, observe

log = logging.getLogger(__name__)


def tick(store, vault):
    with store.connect() as c:
        c.execute("UPDATE diagnostic_jobs SET state='expired',lease_until=NULL,lease_token=NULL WHERE expires<=? AND state IN ('pending','leased')",(time.time(),))
    job = claim(store, 'checks')
    if job:
        try:
            healthy, evidence = probe(job['kind'], {**json.loads(job['config']), '_check_id':job['id']}, vault, store)
        except Exception as exc:
            # Do not put URLs, tokens or raw upstream error bodies in evidence.
            healthy, evidence = (None if job['kind']=='agent_metric' else False), {'reason': 'Check could not complete', 'error_type': type(exc).__name__}
        observe(store, job['id'], healthy, evidence, lease_token=job['lease_token'])
    delivery = claim(store, 'deliveries')
    if delivery:
        deliver(store, vault, delivery)
    return bool(job or delivery)


def deliver(store, vault, job):
    configured = store.setting('discord_secret')
    if not configured:
        outcome(store, job, 'pending', 'Discord webhook has not been configured.', 60)
        return
    incident = store.rows('SELECT * FROM incidents WHERE id=?', (job['incident_id'],))[0]
    if incident['closed'] and job['event_key'].endswith(':opened'):
        outcome(store, job, 'superseded', None)
        return
    report = json.loads(incident['report'])
    text = f"{incident['severity'].upper()} · {report['target']} · {report['check']}\n{incident['status']} · Cause: {report['cause']}\nIncident {incident['id']}"
    url = vault.decrypt(configured)
    try:
        r = requests.post(url, json={'content': text[:1900], 'allowed_mentions': {'parse': []}}, timeout=(3, 8), allow_redirects=False)
        if 200 <= r.status_code < 300:
            outcome(store, job, 'completed', None)
        elif r.status_code == 429 or r.status_code >= 500:
            try:
                delay = min(3600, max(5, float(r.headers.get('Retry-After', 0))))
            except ValueError:
                delay = 10
            outcome(store, job, 'pending', f'HTTP {r.status_code}', max(delay, backoff(job)))
        else:
            outcome(store, job, 'failed', f'HTTP {r.status_code}; review destination settings.')
    except requests.RequestException:
        outcome(store, job, 'pending', 'Delivery failed or acceptance is unknown; duplicate notifications are possible.', backoff(job))


def backoff(job):
    return min(3600, 10 * 2 ** min(job['attempts'], 8)) + random.uniform(0, 5)


def outcome(store, job, state, error, delay=0):
    with store.connect() as c:
        c.execute('UPDATE deliveries SET state=?,last_error=?,next_attempt=?,lease_until=NULL,lease_token=NULL WHERE id=? AND lease_token=?',
                  (state, error, time.time() + delay, job['id'], job['lease_token']))


def run(store, vault, stop):
    while not stop.is_set():
        try:
            busy = tick(store, vault)
        except Exception:
            log.exception('Worker failed; persisted leases will recover')
            busy = False
        stop.wait(0.2 if busy else 2)
