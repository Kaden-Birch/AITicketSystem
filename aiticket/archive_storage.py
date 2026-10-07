"""Evidence payload usage, excluding database and filesystem overhead."""
import hashlib
import json
import sqlite3
import time
from . import network_logs as logs


def identity(cfg):
    return hashlib.sha256(json.dumps({k:cfg.get(k) for k in ('server','share','folder','namespace','username','domain')},sort_keys=True).encode()).hexdigest()


def meter(total,free,available):
    if any(type(v) is not int for v in (total,free,available)) or total<=0 or not 0<=free<=total or not 0<=available<=total:
        raise ValueError('Storage server did not report valid capacity.')
    used=total-free;percent=used/total*100
    return {'total':total,'used':used,'available':available,'percent':percent,'color':'high' if percent>=90 else 'moderate' if percent>=75 else 'good'}


def human(value):
    if value is None:return 'Unavailable'
    unit,divisor=('GB',1_000_000_000) if value>=1_000_000_000 else ('MB',1_000_000)
    if 0<value/divisor<0.001:return '<0.001 '+unit
    return f'{value/divisor:,.3f} {unit}'


def local(store):
    # Persisted telemetry size includes a fixed queue-budget allowance. Remove it;
    # counting that allowance would misrepresent the collected JSON payload.
    telemetry=store.rows('SELECT coalesce(sum(max(size-128,0)),0) used FROM telemetry_records')[0]['used']
    network=0;error=None
    if logs.database(store).exists():
        try:
            with logs.reader(store) as c:
                c.execute('BEGIN')  # One snapshot prevents expiry/upload races from double counting.
                # SIEM's persisted serialized-record size adds a 512-byte budget allowance.
                network=c.execute('SELECT coalesce(sum(max(size-512,0)),0) FROM events').fetchone()[0]
                # Expired events can still await upload. Count their queued payload
                # once, without counting a second copy of retained events.
                network+=c.execute('SELECT coalesce(sum(max(size-256,0)),0) FROM smb_outbox q WHERE NOT EXISTS (SELECT 1 FROM events e WHERE e.event_key=q.event_key)').fetchone()[0]
        except sqlite3.Error:error='Local SIEM record usage is temporarily unavailable.';network=None
    return {'telemetry_bytes':telemetry,'network_bytes':network,'record_bytes':None if network is None else telemetry+network,'error':error}


def comparison(store,cfg):
    local_data=local(store);remote_data=remote(store,cfg)
    largest=max(local_data.get('record_bytes') or 0,remote_data.get('archive_bytes') or 0,1)
    local_data['percent']=(local_data.get('record_bytes') or 0)/largest*100
    remote_data['percent']=(remote_data.get('archive_bytes') or 0)/largest*100
    return {'local_storage':local_data,'smb_storage':remote_data}


def remote(store,cfg):
    data=store.setting('archive_storage',{})
    if data.get('target')!=identity(cfg):return {'configured':bool(cfg.get('server'))}
    return {**data,'configured':bool(cfg.get('server')),'stale':bool(data.get('error') or not data.get('at') or time.time()-data['at']>600)}
