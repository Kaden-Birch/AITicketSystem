"""Coverage is evidence availability; silence is never a host/source health check."""
import json
import sqlite3
import time
from . import network_logs as logs
from . import log_archive as archive
from .log_problems import classify,snapshot,KINDS
from .engine import observe


def view(store,now=None):
    now=time.time() if now is None else now
    events,capped,available=snapshot(store,now);collector=logs.status(store);transfer=archive.archive_status(store)
    with store.connect() as c:
        names={r['id']:r['name'] for r in c.execute('SELECT id,name FROM machines')}
        sources=[dict(r) for r in c.execute('SELECT id,name,enabled FROM log_sources ORDER BY name')]
    matched={};unassigned=[];wholly_unassigned=0;types={};formats={};source_counts={}
    for e in events:
        kind=KINDS.get(classify(e),'Other / generic');types[kind]=types.get(kind,0)+1;formats[e['format']]=formats.get(e['format'],0)+1
        source_counts[e['source_id']]=source_counts.get(e['source_id'],0)+1
        clients=[a for a in e['associations'] if a['role']=='client' and a['machine_id'] in names]
        if not any(a['machine_id'] in names for a in e['associations']):wholly_unassigned+=1
        if not clients:unassigned.append({'id':e['id'],'name':e['name'],'client_mac':e['client_mac'],'at':e['at']})
        for a in e['associations']:
            if a['machine_id'] not in names:continue
            item=matched.setdefault(a['machine_id'],{'name':names[a['machine_id']],'count':0,'last_at':0,'roles':set()})
            item['count']+=1;item['last_at']=max(item['last_at'],e['at']);item['roles'].add(a['role'])
    hosts=[{'id':k,**v,'roles':sorted(v['roles'])} for k,v in matched.items()]
    hosts.sort(key=lambda h:h['count'],reverse=True)
    settings=store.setting('network_log_health',{})
    return {'collector':collector,'archive':transfer,'available':available,'capped':capped,'events':len(events),'hosts':hosts[:100],
            'matched_hosts':len(hosts),'without_events':len(names)-len(hosts),'unassigned':len(unassigned),'wholly_unassigned':wholly_unassigned,'unassigned_samples':unassigned[:10],
            'types':types,'formats':formats,'sources':[s|{'count':source_counts.get(s['id'],0),'last_at':collector.get('sources',{}).get(s['id'],{}).get('at')} for s in sources],
            'smb_enabled':archive.config(store)['enabled'],'settings':settings,
            'health_tickets':store.rows("SELECT i.id,i.status,ch.name AS issue,json_extract(i.report,'$.evidence.reason') AS reason,m.name FROM incidents i JOIN checks ch ON ch.id=i.check_id JOIN machines m ON m.id=i.machine_id WHERE ch.kind='log_health' AND i.closed IS NULL AND i.status!='Resolved' ORDER BY i.first_seen DESC LIMIT 10")}


def save(store,values):
    machine=values.get('health_machine') or None
    try:delay=int(values.get('failure_minutes',15))*60
    except (TypeError,ValueError):raise ValueError('Enter a whole-number failure duration.')
    if not 120<=delay<=86400:raise ValueError('Persistent failures must last 2–1,440 minutes.')
    enabled=values.get('health_enabled')=='yes'
    if enabled and not machine:raise ValueError('Select the application server host for collection-health tickets.')
    with store.connect() as c:
        if machine and not c.execute('SELECT 1 FROM machines WHERE id=?',(machine,)).fetchone():raise ValueError('Choose an existing application server host.')
        c.execute("UPDATE checks SET enabled=0 WHERE kind='log_health'")
    store.save_many({'network_log_health':{'enabled':enabled,'machine':machine,'delay':delay,'configured_at':time.time()},
                     'network_log_correlation':values.get('correlation')=='yes'},actor='administrator')


def tick(store,now=None,force=False):
    now=time.time() if now is None else now
    if not force and now-store.setting('network_log_health_last_tick',0)<30:return
    store.save('network_log_health_last_tick',now)
    cfg=store.setting('network_log_health',{})
    if not cfg.get('enabled') or not cfg.get('machine'):return
    machine=cfg['machine'];collector=logs.status(store);transfer=archive.archive_status(store)
    heartbeat=collector.get('heartbeat');enabled_sources=bool(store.rows('SELECT 1 FROM log_sources WHERE enabled=1 LIMIT 1'))
    origin=heartbeat or cfg['configured_at'];collector_failed=enabled_sources and now-origin>=cfg['delay']
    previous=store.setting('network_log_storage_health',{})
    errors=collector.get('storage_errors',0)
    # An old cumulative error count alone must not permanently mark a recovered writer unhealthy.
    increasing=errors>previous.get('errors',0) and heartbeat!=previous.get('heartbeat')
    error_since=previous.get('error_since') if increasing else None
    if increasing and not error_since:error_since=now
    storage_failed=bool(error_since and now-error_since>=cfg['delay'])
    store.save('network_log_storage_health',{'errors':errors,'heartbeat':heartbeat,'error_since':error_since})
    smb=archive.config(store)['enabled'];backlog=transfer.get('pending',0)+transfer.get('waiting_local',0)
    upload_origin=transfer.get('error_since') or transfer.get('heartbeat') or cfg['configured_at']
    smb_failed=smb and (not transfer.get('available') and now-upload_origin>=cfg['delay'] or bool(backlog and transfer.get('error') and now-upload_origin>=cfg['delay']))
    issues=[('collector',collector_failed if enabled_sources else None,'Log receiver contact is stale. Check docker compose ps/logs log-receiver, port 5514 binding and writable local storage.',{'heartbeat':heartbeat}),
            ('storage',storage_failed if heartbeat and now-heartbeat<=30 else None,'The collector repeatedly failed to store events. Check local disk capacity and log volume permissions.',{'storage_errors':errors}),
            ('archive',smb_failed if smb else None,'Persistent SMB archiving failure. Local collection continues. Check log-archiver, SMB connectivity/space/permissions, then use Save and test connection.',{'pending':transfer.get('pending',0),'waiting_local':transfer.get('waiting_local',0),'error':transfer.get('error'),'error_since':transfer.get('error_since')})]
    for kind,failed,reason,evidence in issues:
        identifier='log-health-'+machine+'-'+kind
        if (kind=='archive' and not smb) or (kind=='collector' and not enabled_sources):
            with store.connect() as c:c.execute('UPDATE checks SET enabled=0 WHERE id=?',(identifier,))
            continue
        with store.connect() as c:
            c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,'log_health','{}',30,1,2,'high') ON CONFLICT(id) DO UPDATE SET enabled=1",(identifier,machine,'Log collection · '+kind))
        healthy=None if failed is None else not failed
        if kind=='archive' and healthy and transfer.get('error'):healthy=None # A failed upload is never reported recovered merely because the backlog shrank.
        observe(store,identifier,healthy,{'reason':reason if failed else 'Fresh collection-service evidence; a quiet source is not unhealthy.',**evidence},now)
