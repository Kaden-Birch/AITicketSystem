import json
import time
import pytest
from aiticket import archive_health as health, archive_verification as verify
from aiticket import log_archive as archive,telemetry_archive as telemetry,log_coverage as coverage
from test_log_archive import configure,smb
from test_troubleshooting import host,feed,cef,MAC
from test_evidence_groups_maintenance import window,operational


def fresh(store,cfg,now,network=None,readings=None,previous=None):
    streams=health.snapshot(store,cfg,network or {'pending':0},readings or {'pending':0},previous,now)
    state={'heartbeat':now,'available':True,'streams':streams,'error':None}
    store.save('network_log_archive_status',state)
    return state


def test_independent_stall_and_catching_up_not_masked_by_siem(environment):
    _,store,vault=environment;cfg=configure(store,vault);now=time.time()
    health.receipt(store,'network',cfg,1000,'unused',{})
    state=fresh(store,cfg,now,readings={'pending':10000,'pending_bytes':1e6,'oldest':now-5000})
    state['heartbeat']=now+1000
    result=health.view(store,now+1000,state)
    assert result['streams'][0]['status']=='Up to date'
    assert result['streams'][1]['status']=='Stalled'
    health.receipt(store,'telemetry',cfg,1000,'unused',{})
    receipt=store.setting('archive_receipt_telemetry');receipt['at']=now+1001;store.save('archive_receipt_telemetry',receipt)
    next_state=fresh(store,cfg,now+1001,readings={'pending':9000,'pending_bytes':9e5},previous=state['streams'])
    result=health.view(store,now+1001,next_state)
    assert result['streams'][1]['status']=='Catching up'
    assert result['streams'][1]['net_per_minute']>0
    # Quiet sources never acquire a synthetic stale-upload failure.
    quiet=fresh(store,cfg,now+2000)
    assert not any(s['stalled'] for s in health.view(store,now+2000,quiet)['streams'])
    assert health.view(store,now+2200,quiet)['streams'][0]['status']=='Service unavailable'


def test_single_incident_updates_and_recovers_using_host_policies(environment,monkeypatch):
    _,store,vault=environment;cfg=configure(store,vault);host(store);now=time.time()
    coverage.save(store,{'health_machine':'m','health_enabled':'yes','failure_minutes':'2'})
    monkeypatch.setattr(coverage.logs,'status',lambda _:{'heartbeat':time.time(),'storage_errors':0})
    monkeypatch.setattr(archive,'archive_status',lambda _:store.setting('network_log_archive_status',{})|{'available':True})
    state=fresh(store,cfg,now,readings={'pending':10000,'oldest':now-1000})
    state['heartbeat']=now+180;store.save('network_log_archive_status',state)
    coverage.tick(store,now+180,force=True)
    rows=store.rows("SELECT * FROM incidents WHERE check_id LIKE '%archive'")
    assert len(rows)==1 and 'Telemetry uploads are stalled' in rows[0]['report']
    state.update(error='SMB unavailable',error_since=now-200,heartbeat=now+210)
    store.save('network_log_archive_status',state);coverage.tick(store,now+210,force=True)
    assert len(store.rows("SELECT * FROM incidents WHERE check_id LIKE '%archive'"))==1
    assert 'Persistent archive error' in store.rows('SELECT report FROM incidents WHERE id=?',(rows[0]['id'],))[0]['report']
    fresh(store,cfg,now+240);coverage.tick(store,now+240,force=True)
    fresh(store,cfg,now+270);coverage.tick(store,now+270,force=True)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(rows[0]['id'],))[0]['status']=='Resolved'


def test_buffer_pressure_sustains_corruption_immediate_and_maintenance_suppresses(environment,monkeypatch):
    _,store,vault=environment;cfg=configure(store,vault);host(store);now=time.time()
    coverage.save(store,{'health_machine':'m','health_enabled':'yes','failure_minutes':'2','buffer_percent':'90'})
    monkeypatch.setattr(coverage.logs,'status',lambda _:{'heartbeat':now,'storage_errors':0})
    state=fresh(store,cfg,now,readings={'pending':10,'pending_bytes':cfg['buffer_mb']*1048576*.95})
    coverage.tick(store,now,force=True);assert not store.rows('SELECT 1 FROM incidents')
    state['heartbeat']=now+121;store.save('network_log_archive_status',state)
    coverage.tick(store,now+121,force=True)
    assert 'nearly full' in store.rows('SELECT report FROM incidents')[0]['report']
    # Same consolidated incident gains immediate corruption evidence, without a new ticket.
    state.update(sqlite_errorcode=11,halted=True);store.save('network_log_archive_status',state)
    coverage.tick(store,now+122,force=True)
    assert len(store.rows('SELECT 1 FROM incidents'))==1
    assert 'Database corruption' in store.rows('SELECT report FROM incidents')[0]['report']
    with store.connect() as c:c.execute("UPDATE incidents SET status='Resolved',closed=?",(now+123,))
    window(store,'m',now,now+1000);coverage.tick(store,now+150,force=True)
    assert not store.rows('SELECT 1 FROM incidents WHERE closed IS NULL')


def uploaded(store,vault,io):
    cfg=configure(store,vault);host(store);now=time.time()
    with store.connect() as c:c.execute('INSERT OR REPLACE INTO network_inventory VALUES(?,?,?)',('m',now,json.dumps({'interfaces':[{'mac':MAC}]})))
    feed(store,events=[(cef(),now-20)])
    worker=archive.Archiver(store,vault,io);worker.upload(cfg)
    telemetry.record(store,'metrics','m','m',{'cpu_percent':85,'password':'must-not-leak'},now-10)
    worker.telemetry.step(cfg);worker.publish()
    return cfg,worker


def test_real_smb_verification_human_links_and_ai_adapter_without_local_fallback(signed_in,smb):
    client,store,vault,csrf=signed_in;cfg,worker=uploaded(store,vault,smb[1])
    assert client.post('/network-events/archive/verify').status_code==403
    response=client.post('/network-events/archive/verify',data={'csrf':csrf,'return_to':'https://evil.invalid'})
    assert response.status_code==302 and response.location=='/settings/network-logs'
    state=store.setting('archive_verification');assert len([s for s in state.values() if isinstance(s,dict) and s.get('job')])==2
    # Prove read-back actually comes from remote bytes, with no retained telemetry fallback.
    with store.connect() as c:c.execute('DELETE FROM telemetry_records')
    for _ in range(2):assert worker.process_job()
    result=store.setting('archive_verification')
    for dataset in health.LABELS:
        item=result[dataset]
        assert item['state']=='passed' and item['ui_verified'] and item['ai_verified'],item
        page=client.get(item['search_url']);assert page.status_code==200
        assert b'must-not-leak' not in page.data
    assert not store.rows('SELECT 1 FROM ai_jobs') and not store.rows('SELECT 1 FROM command_jobs')
    for path in ('/settings/network-logs','/telemetry-history','/network-events/coverage'):
        response=client.get(path);assert response.status_code==200
        assert b'Archive transfer health' in response.data and b'Verify SMB read-back now' in response.data


def test_automatic_verification_waits_for_backlog_and_runs_daily(environment,smb):
    _,store,vault=environment;cfg,worker=uploaded(store,vault,smb[1]);now=time.time()
    state=archive.archive_status(store);state['streams']['telemetry']['pending']=1;store.save('network_log_archive_status',state)
    result=verify.schedule(store,vault,now=now)
    assert 'network' in result and 'telemetry' not in result
    assert worker.process_job()
    state['streams']['telemetry']['pending']=0;store.save('network_log_archive_status',state)
    verify.schedule(store,vault,now=now+60);assert worker.process_job()
    count=len(store.rows('SELECT 1 FROM log_archive_jobs'))
    verify.schedule(store,vault,now=now+120)
    assert len(store.rows('SELECT 1 FROM log_archive_jobs'))==count
    verify.schedule(store,vault,now=now+86500)
    assert len(store.rows('SELECT 1 FROM log_archive_jobs'))==count+2


def test_corrupted_remote_batch_fails_verification_even_with_local_records(environment,smb):
    _,store,vault=environment;cfg,worker=uploaded(store,vault,smb[1])
    verify.schedule(store,vault,manual=True)
    for p in smb[0].root.rglob('telemetry-*.gz'):p.write_bytes(b'broken')
    worker.process_job();worker.process_job()
    result=store.setting('archive_verification')
    assert result['network']['state']=='passed'
    assert result['telemetry']['state']=='failed' and not result['telemetry']['ui_verified']
    assert 'must-not-leak' not in json.dumps(result)


def test_destination_change_does_not_reuse_progress_or_verification(environment,smb):
    _,store,vault=environment;cfg,worker=uploaded(store,vault,smb[1]);verify.schedule(store,vault,manual=True)
    worker.process_job();worker.process_job()
    cfg['folder']='different';store.save('network_log_smb',cfg | {'password':None})
    view=health.view(store)
    assert not view['verification'] and all(s['last_success'] is None for s in view['streams'])


def test_unassigned_sample_is_partial_not_false_ai_success(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault)
    telemetry.record(store,'dashboard','workspace',None,{'hosts':[]})
    worker=archive.Archiver(store,vault,smb[1]);worker.telemetry.step(cfg);worker.publish()
    verify.schedule(store,vault,manual=True);assert worker.process_job()
    result=store.setting('archive_verification')['telemetry']
    assert result['state']=='partial' and result['ui_verified'] and not result['ai_verified']
    from aiticket.log_archive_ai import result as ai_result
    with pytest.raises(ValueError,match='different run'):ai_result(store,'not-authorized','m',result['job'])


def test_verification_retains_old_uploaded_probe_while_backlog_drains(environment):
    _,store,vault=environment;cfg=configure(store,vault)
    health.receipt(store,'telemetry',cfg,1000,'old-batch',{'record_key':'old','machine_id':'m','at':10})
    health.receipt(store,'telemetry',cfg,1000,'new-batch',{'record_key':'new','machine_id':'m','at':20})
    receipt=store.setting('archive_receipt_telemetry')
    assert receipt['sample']['record_key']=='new' and receipt['probe']['sample']['record_key']=='old'
    assert receipt['completed']==2000


def test_verification_failure_opens_one_incident_and_fresh_pass_resolves(environment,monkeypatch):
    _,store,vault=environment;cfg=configure(store,vault);host(store);now=time.time()
    coverage.save(store,{'health_machine':'m','health_enabled':'yes','failure_minutes':'2'})
    monkeypatch.setattr(archive,'archive_status',lambda _:store.setting('network_log_archive_status',{})|{'available':True})
    state={'target':health.target(cfg),'telemetry':{'state':'failed','checked_at':now-180,'note':'Cannot read sample'}}
    store.save('archive_verification',state);fresh(store,cfg,now)
    coverage.tick(store,now,force=True)
    rows=store.rows("SELECT * FROM incidents WHERE check_id LIKE '%archive'")
    assert len(rows)==1 and 'read-back verification failed' in rows[0]['report']
    state['telemetry']['state']='passed';store.save('archive_verification',state)
    fresh(store,cfg,now+30);coverage.tick(store,now+30,force=True)
    fresh(store,cfg,now+60);coverage.tick(store,now+60,force=True)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(rows[0]['id'],))[0]['status']=='Resolved'


def test_old_event_in_recent_upload_verifies_using_receipt_partition(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);host(store)
    telemetry.record(store,'metrics','m','m',{'cpu_percent':70},time.time()-60*86400)
    worker=archive.Archiver(store,vault,smb[1]);worker.telemetry.step(cfg);worker.publish()
    verify.schedule(store,vault,manual=True);assert worker.process_job()
    assert store.setting('archive_verification')['telemetry']['state']=='passed'


def test_expired_verification_sample_is_not_a_false_smb_failure(environment,smb):
    _,store,vault=environment;cfg,worker=uploaded(store,vault,smb[1]);now=time.time()
    receipt=store.setting('archive_receipt_telemetry')
    receipt['sample']['received']=now-400*86400
    receipt['probe']['sample']['received']=now-400*86400
    store.save('archive_receipt_telemetry',receipt)
    state=verify.schedule(store,vault,manual=True,now=now)
    assert state['telemetry']['state']=='waiting' and 'retention' in state['telemetry']['note']
    assert not any(json.loads(r['params']).get('dataset')=='telemetry' for r in store.rows('SELECT params FROM log_archive_jobs'))


def test_normal_batch_delay_is_not_a_stall_and_errors_are_stream_scoped(environment):
    _,store,vault=environment;cfg=configure(store,vault);now=time.time()
    store.save('network_log_health',{'delay':120})
    health.receipt(store,'network',cfg,1000,'batch',{})
    state=fresh(store,cfg,now,readings={'pending':10,'oldest':now})
    state['heartbeat']=now+180
    assert health.view(store,now+180,state)['streams'][1]['status']=='Queued'
    state.update(error='Upload failed',error_stage='telemetry upload')
    streams=health.view(store,now+180,state)['streams']
    assert streams[0]['status']=='Up to date' and streams[1]['status']=='Retrying'
    state.update(error=None,heartbeat=now+400)
    assert health.view(store,now+400,state)['streams'][1]['status']=='Stalled'


def test_database_corruption_in_search_is_not_swallowed_as_an_smb_error(environment,smb):
    import sqlite3
    _,store,vault=environment;cfg,worker=uploaded(store,vault,smb[1])
    verify.schedule(store,vault,manual=True)
    error=sqlite3.DatabaseError('private internals');error.sqlite_errorcode=sqlite3.SQLITE_CORRUPT
    def broken(*args,**kwargs):raise error
    worker.io=broken
    with pytest.raises(sqlite3.DatabaseError):worker.process_job()
    worker.stage='archive request';worker.failure(error)
    assert worker.halted and worker.state['halted'] and worker.state['next_retry'] is None
    assert 'private internals' not in worker.state['error']
