import json
import logging
import random
import time
import requests
from .adapters import probe
from .engine import claim, observe

log = logging.getLogger(__name__)


def tick(store, vault):
    from .policies import notifications
    from .administration import prune
    prune(store)
    from .health_rules import sync as sync_health
    sync_health(store)
    from .worklog import tick as work_tick
    work_tick(store)
    from .actions import tick as action_tick
    action_tick(store)
    from .power import tick as power_tick
    powered=power_tick(store,vault)
    notifications(store)
    from .proxmox import scheduled_refresh
    refreshed=scheduled_refresh(store,vault)
    with store.connect() as c:
        c.execute("UPDATE diagnostic_jobs SET state='expired',lease_until=NULL,lease_token=NULL WHERE expires<=? AND state IN ('pending','leased')",(time.time(),))
    job = claim(store, 'checks')
    if job:
        try:
            healthy, evidence = probe(job['kind'], {**json.loads(job['config']), '_check_id':job['id']}, vault, store)
        except Exception as exc:
            # Do not put URLs, tokens or raw upstream error bodies in evidence.
            healthy, evidence = (None if job['kind'] in ('agent_metric','unifi','unifi_device','truenas','plex') else False), {'reason': 'Check could not complete', 'error_type': type(exc).__name__}
        observe(store, job['id'], healthy, evidence, lease_token=job['lease_token'])
    from .engine import resolution_tick
    resolution_tick(store)
    from .ticket_groups import tick as group_tick
    group_tick(store)
    delivery = claim(store, 'deliveries')
    if delivery:
        deliver(store, vault, delivery)
    return bool(job or delivery or refreshed or powered)


def deliver(store, vault, job):
    ownership=store.rows('SELECT state,lease_token FROM deliveries WHERE id=?',(job['id'],))
    if not ownership or ownership[0]['state']!='leased' or ownership[0]['lease_token']!=job['lease_token']:
        return
    configured = store.setting('discord_secret')
    if not configured:
        outcome(store, job, 'pending', 'Discord webhook has not been configured.', 60)
        return
    incident = store.rows('SELECT * FROM incidents WHERE id=?', (job['incident_id'],))[0]
    from .ticket_groups import active_primary,context as group_context
    with store.connect() as c:
        primary=active_primary(c,incident['id'])
        primary_row=c.execute('SELECT machine_id,severity FROM incidents WHERE id=?',(primary,)).fetchone() if primary else None
        from .policies import effective
        from .engine import SEVERITIES
        primary_policy=effective(c,primary_row['machine_id']) if primary_row else None
    if primary and primary_policy['enabled'] and SEVERITIES.index(primary_row['severity'])>=SEVERITIES.index(primary_policy['minimum']) and job['event_key'].endswith(':opened'):
        outcome(store,job,'superseded','Related failure is included in the primary investigation. Recovery remains independent.');return
    from .applications import upstream_incident
    with store.connect() as c: root=upstream_incident(c,incident['id'],time.time())
    from .policies import effective
    from .engine import SEVERITIES
    with store.connect() as c:
        root_row=c.execute('SELECT machine_id,severity FROM incidents WHERE id=?',(root,)).fetchone() if root else None
        root_policy=effective(c,root_row['machine_id']) if root_row else None
    if root and root_policy['enabled'] and SEVERITIES.index(root_row['severity'])>=SEVERITIES.index(root_policy['minimum']) and job['event_key'].endswith(':opened'):
        outcome(store,job,'pending','Grouped with an active upstream application incident.',60);return
    from .health_rules import incident_paused
    with store.connect() as c: health_paused=incident_paused(c,incident['id'])
    if health_paused and not job['event_key'].endswith(':recovery'):
        outcome(store,job,'superseded',None);return
    if (incident['closed'] or incident['status']=='Resolved') and not job['event_key'].endswith(':recovery'):
        outcome(store, job, 'superseded', None)
        return
    from .engine import SEVERITIES
    from .policies import effective
    with store.connect() as c:
        policy=effective(c,incident['machine_id'])
    if not policy['enabled'] or SEVERITIES.index(incident['severity'])<SEVERITIES.index(policy['minimum']) or (job['event_key'].endswith(':recovery') and not policy['recovery']):
        outcome(store,job,'superseded',None)
        return
    if ':blocker:' in job['event_key'] and not store.setting('discord_blockers',True):
        outcome(store,job,'superseded',None);return
    if ':reminder:' in job['event_key'] and not policy['reminder_seconds']:
        outcome(store,job,'superseded',None)
        return
    from .policies import maintained
    with store.connect() as c:
        paused=incident['silence_until']>time.time() or maintained(c,incident['machine_id'],time.time()) or bool(c.execute('SELECT 1 FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=? AND c.maintenance_until>?',(incident['id'],time.time())).fetchone())
    if paused:
        outcome(store,job,'pending','Delivery paused by maintenance or incident silence.',60)
        return
    report = json.loads(incident['report'])
    event=job['event_key'].split(':',1)[1]
    text = f"{event} · {incident['severity'].upper()} · {report['target']} · {report['check']}\n{incident['status']} · Cause: {report['cause']}\nIncident {incident['id']}"
    if event=='recovery': text+='\n'+report.get('recovery_summary','Monitoring independently confirmed recovery.')
    with store.connect() as c:group=group_context(c,incident['id'])
    if len(group['tickets'])>1:text+='\nAffected: '+', '.join(x['host']+' ('+x['status']+')' for x in group['tickets'][:10])+'. Each ticket retains independent recovery.'
    from .worklog import ticket_url
    link=ticket_url(store,incident['id'])
    if event.startswith('blocker:'):
        blockers=store.rows('SELECT reason FROM ticket_blockers WHERE id=? AND cleared IS NULL',(event.split(':',1)[1],))
        if not blockers:
            outcome(store,job,'superseded',None);return
        text=f"Needs your attention · {report['target']} · {report['check']}\n{blockers[0]['reason']}"
    if link: text=text[:1500]+'\nOpen ticket: '+link
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
    # API subscriptions can wait for their first event. Keep one-second ping and
    # existing command/notification queues independent from those waits.
    from threading import Thread
    from .integrations import tick as integration_tick
    def poll_integrations():
        while not stop.is_set():
            try:integration_tick(store,vault)
            except Exception:log.exception('Integration polling failed; durable leases recover')
            stop.wait(.5)
    Thread(target=poll_integrations,name='integration-poller',daemon=True).start()
    while not stop.is_set():
        try:
            busy = tick(store, vault)
        except Exception:
            log.exception('Worker failed; persisted leases will recover')
            busy = False
        stop.wait(0.2)
