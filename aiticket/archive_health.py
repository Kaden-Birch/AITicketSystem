"""Independent evidence-stream progress. Silence without queued work is not failure."""
import time
from . import log_archive as archive

LABELS={'network':'SIEM logs','telemetry':'Telemetry'}


def target(cfg):
    from .archive_storage import identity
    return identity(cfg)


def receipt(store,dataset,cfg,records,name,sample):
    """Called only after verified upload AND durable local acknowledgment."""
    key='archive_receipt_'+dataset;prior=store.setting(key,{})
    identity=target(cfg)
    total=prior.get('completed',0) if prior.get('target')==identity else 0
    probe=prior.get('probe') if prior.get('target')==identity else None
    verified=store.setting('archive_verification',{}).get(dataset,{})
    if not probe or verified.get('state')=='passed' and verified.get('checked_at',0)>=probe['created'] or not probe['sample'].get('machine_id') and sample.get('machine_id'):
        probe={'file':name,'sample':sample,'created':time.time()}
    store.save(key,{'probe':probe,'target':identity,'at':time.time(),'completed':total+records,'records':records,'file':name,'sample':sample})


def snapshot(store,cfg,network,telemetry,previous=None,now=None):
    now=time.time() if now is None else now
    previous=previous or {};identity=target(cfg);streams={}
    for dataset,raw in (('network',network),('telemetry',telemetry)):
        prior=previous.get(dataset,{})
        if prior.get('target')!=identity:prior={}
        confirmation=store.setting('archive_receipt_'+dataset,{})
        if confirmation.get('target')!=identity:confirmation={}
        queued=int(raw.get('queued',raw.get('pending',0)) or 0)
        waiting=int(raw.get('waiting_local',0) or 0)
        count=queued+waiting
        completed=confirmation.get('completed',0)
        baseline=prior.get('baseline') or {'at':now,'pending':count,'completed':completed}
        elapsed=now-baseline['at'];rate=prior.get('net_per_minute');moving=prior.get('uploading',False)
        if elapsed>=30:
            rate=round((baseline['pending']-count)*60/elapsed,1)
            moving=completed>baseline['completed']
            baseline={'at':now,'pending':count,'completed':completed}
        age_from=confirmation.get('at') or prior.get('pending_since') or now
        pending_since=(prior.get('pending_since') or now) if count else None
        streams[dataset]={'target':identity,'label':LABELS[dataset],'pending':count,'queued':queued,'waiting_local':waiting,
            'pending_bytes':raw.get('pending_bytes',0),'oldest_pending':raw.get('oldest_pending',raw.get('oldest')),
            'last_success':confirmation.get('at'),'completed':completed,'last_progress':age_from,'pending_since':pending_since,
            'buffer_bytes':cfg['buffer_mb']*1048576,'buffer_percent':round(raw.get('pending_bytes',0)/(cfg['buffer_mb']*1048576)*100,1),
            'net_per_minute':rate,'uploading':moving,'baseline':baseline,'sampled_at':now,'gaps':raw.get('gaps',raw.get('dropped',0))}
    return streams


def view(store,now=None,transfer=None):
    now=time.time() if now is None else now
    cfg=archive.config(store);state=archive.archive_status(store) if transfer is None else transfer
    identity=target(cfg);delay=store.setting('network_log_health',{}).get('delay',900)
    available=bool(state.get('heartbeat') and 0<=now-state['heartbeat']<120)
    corrupt=state.get('halted') or (state.get('sqlite_errorcode') is not None and state['sqlite_errorcode']&255 in (11,26))
    streams=[]
    for dataset,label in LABELS.items():
        s=dict(state.get('streams',{}).get(dataset,{}))
        if s.get('target')!=identity:s={}
        s.update(dataset=dataset,label=label)
        s.setdefault('pending',None);s.setdefault('pending_bytes',0);s.setdefault('buffer_percent',0)
        s.setdefault('oldest_pending',None);s.setdefault('last_success',None);s.setdefault('net_per_minute',None)
        status='Awaiting service';tone='unknown'
        # Small batches normally wait up to five minutes before upload.
        stall_after=max(delay,360) if (s['pending'] or 0)<1000 and not s.get('waiting_local') else delay
        stage=state.get('error_stage')
        own_error=state.get('error') and (stage not in ('SIEM upload','telemetry upload') or stage==('SIEM upload' if dataset=='network' else 'telemetry upload'))
        if not cfg['enabled']:status='Paused'
        elif corrupt:status='Database error';tone='down'
        elif not available:status='Service unavailable';tone='down'
        elif s['pending'] is None:status='Awaiting stream snapshot'
        elif s['pending'] and now-max(s.get('last_progress',now),s.get('pending_since') or 0)>=stall_after:status='Stalled';tone='down'
        elif own_error:status='Retrying';tone='warning'
        elif not s['pending']:status='Up to date' if s['last_success'] else 'Awaiting data';tone='healthy' if s['last_success'] else 'unknown'
        elif s.get('uploading') and (s['net_per_minute'] or 0)>0:status='Catching up';tone='healthy'
        elif s.get('uploading'):status='Uploading';tone='healthy'
        else:status='Queued';tone='unknown'
        s.update(status=status,tone=tone,stalled=status=='Stalled',fresh=available)
        streams.append(s)
    checks=store.setting('archive_verification',{})
    if checks.get('target')!=identity:checks={}
    return {'streams':streams,'enabled':cfg['enabled'],'available':available,'corrupt':bool(corrupt),'error':state.get('error'),
            'heartbeat':state.get('heartbeat'),'verification':checks,'alerts':store.setting('network_log_health',{})}
