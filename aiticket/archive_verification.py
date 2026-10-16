"""Bounded SMB read-back through the human search and AI evidence adapters.

No model call, host operation or AI authorization is created by verification.
"""
import time
from datetime import datetime,timezone
from . import log_archive as archive
from .archive_health import target,LABELS


def schedule(store,vault,manual=False,now=None):
    now=time.time() if now is None else now
    cfg=archive.config(store)
    if not cfg['enabled']:raise ValueError('Enable SMB archiving before verifying retained evidence.')
    identity=target(cfg);state=store.setting('archive_verification',{})
    if state.get('target')!=identity:state={'target':identity}
    streams=archive.archive_status(store).get('streams',{})
    for dataset in LABELS:
        prior=state.get(dataset,{})
        task=archive.job(store,prior['job']) if prior.get('job') else None
        if task and task['state'] in ('pending','running'):continue
        if not manual and now-prior.get('checked_at',0)<86400:continue
        stream=streams.get(dataset,{})
        caught_up=stream.get('pending')==0 or (0<(stream.get('pending') or 0)<1000 and stream.get('oldest_pending') is not None and 0<=now-stream['oldest_pending']<300)
        if not manual and (stream.get('target')!=identity or not caught_up):continue
        receipt=store.setting('archive_receipt_'+dataset,{})
        probe=receipt.get('probe') or receipt
        sample=probe.get('sample') or {}
        if receipt.get('target')!=identity or not sample:
            state[dataset]={'state':'waiting','note':'Waiting for a verified upload sample.'};continue
        # Retention can legitimately remove an early catch-up sample. Prefer a
        # newer retained receipt instead of opening a false read-back incident.
        cutoff=now-cfg['days']*86400 if cfg['days'] else 0
        if sample.get('received',sample['at'])<cutoff:
            probe=receipt;sample=receipt['sample']
            if sample.get('received',sample['at'])<cutoff:
                state[dataset]={'state':'waiting','note':'Waiting for a sample inside the configured SMB retention period.'}
                continue
        at=sample['at'];machine=sample.get('machine_id')
        params={'dataset':dataset,'start':max(0,at-1),'end':at+1,'machine':machine or '',
                'record_key':sample.get('record_key') or sample.get('event_key'),'max_files':1,'scan_limit':10000,'result_limit':2,
                'verification':{'target':identity,'file':probe['file'],'sample':sample},
                'display':{'start':datetime.fromtimestamp(max(0,at-1),timezone.utc).strftime('%Y-%m-%dT%H:%M'),
                           'end':datetime.fromtimestamp(at+60,timezone.utc).strftime('%Y-%m-%dT%H:%M'),'machine':machine or '',
                           'kind':'','q':'','source':'','severity':'','tier':'smb'}}
        try:identifier=archive.submit(store,vault,'search',archive.connection(store,vault),params)
        except ValueError:
            # Uploading and existing user/AI searches take priority; retry later.
            if manual:raise
            continue
        state[dataset]={'state':'queued','job':identifier,'requested_at':now,'note':'Reading one known uploaded batch; no local fallback.'}
        store.save('archive_verification',state)
    store.save('archive_verification',state)
    return state


def completed(store,identifier):
    task=archive.job(store,identifier)
    if not task or not task['params'].get('verification'):return
    params=task['params'];verification=params['verification'];dataset=params['dataset']
    state=store.setting('archive_verification',{})
    if state.get('target')!=verification['target'] or state.get(dataset,{}).get('job')!=identifier:return
    item={'job':identifier,'checked_at':time.time(),'state':'failed','ui_verified':False,'ai_verified':False,
          'note':task.get('error') or 'Uploaded sample was not returned by the SMB search.'}
    if task['state']=='complete':
        try:
            records=archive.search_results(store,identifier,strict=True)
            key='record_key' if dataset=='telemetry' else 'event_key'
            match=next((r for r in records if r.get(key)==params['record_key']),None)
            if match:
                item.update(ui_verified=True,state='partial',note='SMB sample readable; waiting for a current host association to verify AI access.')
                item['search_url']=('/telemetry-history' if dataset=='telemetry' else '/network-events/archive')+'?job='+identifier
                machine=verification['sample'].get('machine_id')
                if machine and store.rows('SELECT 1 FROM machines WHERE id=?',(machine,)):
                    from .log_archive_ai import append_facts
                    response={'archive_type':dataset,'observed_facts':[],'suspected_causes':[]}
                    append_facts(response,[match],machine,identifier,limit=1)
                    facts=response['observed_facts']
                    if facts and facts[0].get('reference'):
                        item.update(ai_verified=True,state='passed',note='SMB search, record reference and bounded host-scoped AI evidence adapter verified.')
                    else:item.update(state='failed',note='SMB sample is readable but the host-scoped AI adapter did not return it.')
            elif task['result'].get('truncated'):
                item.update(state='inconclusive',note='Verification reached a search limit; no recovery claim is made.')
        except ValueError:
            item['note']='The SMB search cache could not be validated.'
    state[dataset]=item;store.save('archive_verification',state)
