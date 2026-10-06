import json,time,gzip
from unittest.mock import Mock
from pathlib import Path
import pytest
from aiticket import telemetry_archive as telemetry,log_archive as archive,log_archive_ai as history
from aiticket.db import Store
from test_log_archive import configure,smb
from test_log_intelligence import dates
from test_evidence_groups_maintenance import operational


def agent(store):
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('m','Server',?)",(time.time(),))
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('a','m','fixture')")


def reading(store,n):
    now=time.time()
    with store.connect() as c:c.execute('UPDATE agents SET telemetry=?,last_seen=?,sampled_at=? WHERE id=?',(json.dumps({'cpu_percent':n,'password':'private-value','nested':{'api_key':'private-key'},'url':'https://host/?X-Plex-Token=private-token','processes':[{'name':'database','memory_bytes':123}]}),now,now,'a'))


def exporter(store,io):
    directory=Path(store.path).parent/'transfer';directory.mkdir(exist_ok=True)
    return telemetry.Exporter(store,io,directory)


def test_atomic_history_redaction_capture_gate_and_pause(environment):
    _,store,vault=environment;agent(store);reading(store,1)
    assert telemetry.status(store)['records']==0
    configure(store,vault);reading(store,2);reading(store,3)
    with pytest.raises(RuntimeError):
        with store.connect() as c:
            c.execute("UPDATE agents SET telemetry='{}',last_seen=?",(time.time(),));raise RuntimeError()
    rows=store.rows('SELECT * FROM telemetry_records WHERE kind="agent"')
    assert len(rows)==2 and [json.loads(r['payload'])['telemetry']['cpu_percent'] for r in rows]==[2,3]
    assert 'private-value' not in str(rows) and 'private-key' not in str(rows) and 'private-token' not in str(rows)
    assert json.loads(rows[0]['payload'])['telemetry']['processes'][0]['memory_bytes']==123
    cfg=store.setting('network_log_smb');cfg['enabled']=False;store.save('network_log_smb',cfg);reading(store,4)
    assert len(store.rows('SELECT * FROM telemetry_records WHERE kind="agent"'))==3


def test_buffer_full_does_not_break_heartbeat_or_replace_monitoring(environment):
    _,store,vault=environment;agent(store);configure(store,vault)
    with store.connect() as c:c.execute('UPDATE telemetry_archive_meta SET pending_bytes=16*1048576')
    reading(store,20)
    assert json.loads(store.rows('SELECT telemetry FROM agents')[0]['telemetry'])['cpu_percent']==20
    assert telemetry.status(store)['dropped']>=1
    assert not store.rows('SELECT * FROM telemetry_records WHERE kind="agent"')


def test_nested_secret_and_oversize_are_explicit():
    result=telemetry.encode(json.dumps({'environment':{'DB_PASSWORD':'secret'},'nested':json.dumps({'access_token':'secret'}),'text':'Bearer abc.xyz password=secret','key':'-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----','nan':float('nan')}))
    assert 'secret' not in result and 'abc.xyz' not in result and json.loads(result)['nan'] is None
    assert json.loads(telemetry.encode(json.dumps({'long':'x'*(telemetry.MAX_RECORD+1)})))['truncated']


def test_outage_restart_retry_exact_batch_and_search_independent_namespace(environment,smb):
    _,store,vault=environment;agent(store);cfg=configure(store,vault);reading(store,21)
    fake,io=smb;names=[]
    def uploaded_but_interrupted(cfg,action,**kw):
        if action=='upload':
            names.append(kw['name']);io(cfg,action,**kw);raise OSError('lost acknowledgement')
        return io(cfg,action,**kw)
    worker=exporter(store,uploaded_but_interrupted)
    with pytest.raises(OSError):worker.step(cfg)
    assert store.setting('telemetry_archive_batch')['ids']
    reading(store,22)
    worker=exporter(Store(store.path),io);worker.step(cfg)
    assert len(list(fake.root.rglob(names[0])))==1
    worker.step(cfg)
    assert not store.setting('telemetry_archive_batch')
    catalog=io(cfg,'catalog',dataset='telemetry')['files'];assert catalog
    assert not io(cfg,'catalog')['files']
    path=Path(store.path).parent/'found.json';now=time.time()
    io(cfg,'search',dataset='telemetry',names=[f['name'] for f in catalog],params={'start':now-100,'end':now+100,'machine':'m','kind':'agent'},file=str(path))
    results=json.loads(path.read_text());keys=[r['record_key'] for r in results]
    assert len(keys)==len(set(keys)) and {r['data']['telemetry']['cpu_percent'] for r in results}=={21,22}
    assert 'private-value' not in path.read_text()
    assert telemetry.status(store)['pending_bytes']==sum(r['size'] for r in store.rows('SELECT size FROM telemetry_records WHERE uploaded=0'))


def test_existing_readings_backfill_and_retention_preserve_pending(environment,smb):
    _,store,vault=environment;agent(store);reading(store,32);cfg=configure(store,vault);fake,io=smb
    worker=exporter(store,io);worker.step(cfg);worker.step(cfg)
    rows=store.rows('SELECT * FROM telemetry_records WHERE kind="agent"');assert rows and rows[0]['id'].startswith('backfill-')
    assert any(b'32' in gzip.decompress(p.read_bytes()) for p in fake.root.rglob('telemetry-*.gz'))
    telemetry.record(store,'metrics','m','m',{'cpu_percent':30},time.time()-86400*30)
    with store.connect() as c:c.execute('UPDATE telemetry_records SET received=?',(time.time()-86400*30,))
    broken=exporter(store,Mock(side_effect=OSError('offline')))
    with pytest.raises(OSError):broken.step(cfg)
    assert store.rows('SELECT * FROM telemetry_records WHERE uploaded=0')
    worker.step(cfg)
    assert not store.rows('SELECT * FROM telemetry_records WHERE uploaded=1 AND received<?',(time.time()-7*86400,))


def test_ai_telemetry_history_scope_references_and_redaction(environment,smb):
    app,store,vault=environment;incident,job=operational(store,vault);cfg=configure(store,vault);now=time.time()
    telemetry.record(store,'metrics','m','m',{'cpu_percent':85,'password':'private-value'},now)
    telemetry.record(store,'metrics','other','other',{'cpu_percent':99},now)
    exporter(store,smb[1]).step(cfg)
    identifier=history.search(store,vault,job,'m',dates(now,archive_type='telemetry',record_type='metrics'))['id']
    assert archive.Archiver(store,vault,smb[1]).process_job()
    answer=history.result(store,job,'m',identifier)
    assert answer['state']=='complete' and len(answer['observed_facts'])==1,answer
    assert answer['observed_facts'][0]['data']['cpu_percent']==85
    assert answer['observed_facts'][0]['reference'].startswith('/telemetry-history/records/')
    assert not answer['suspected_causes'] and 'private-value' not in str(answer)
    with pytest.raises(ValueError):history.result(store,job,'other',identifier)


def test_authenticated_ui_limits_csrf_details_and_dashboard_link(signed_in):
    client,store,vault,csrf=signed_in;cfg=configure(store,vault)
    telemetry.record(store,'dashboard','workspace',None,{'hosts':[{'name':'<script>unsafe</script>','cpu_percent':2}]})
    response=client.get('/telemetry-history');assert response.status_code==200
    assert b'Telemetry history' in response.data and b'<script>unsafe</script>' not in response.data
    key=store.rows('SELECT id FROM telemetry_records WHERE kind="dashboard"')[0]['id']
    assert client.get('/telemetry-history/records/'+key).status_code==200
    assert b'Dashboard history' in client.get('/').data
    assert client.post('/telemetry-history',data={'tier':'smb'}).status_code==403
    assert client.get('/telemetry-history?start=2020-01-01&end=2021-01-01').status_code==200
    with client.session_transaction() as s:s.clear()
    assert client.get('/telemetry-history').status_code==302


def test_migration_from43_preserves_existing_data(environment):
    _,store,vault=environment;agent(store);reading(store,42)
    from conftest import remove_schema44
    with store.connect() as c:
        remove_schema44(c);c.execute('UPDATE schema_version SET version=43')
    upgraded=Store(store.path)
    assert json.loads(upgraded.rows('SELECT telemetry FROM agents')[0]['telemetry'])['cpu_percent']==42
    assert telemetry.status(upgraded)['records']==0


def test_destination_change_bounded_requeue_and_namespace_isolation(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault);worker=exporter(store,smb[1])
    telemetry.record(store,'metrics','m','m',{'cpu_percent':43})
    worker.step(cfg)
    cfg2={**cfg,'folder':'different/archive'};worker.step(cfg2)
    assert smb[1](cfg2,'catalog',dataset='telemetry')['files']
    assert smb[1](cfg,'catalog',dataset='telemetry')['files']
    assert telemetry.status(store)['pending_bytes']==sum(r['size'] for r in store.rows('SELECT size FROM telemetry_records WHERE uploaded=0'))
    assert not store.rows('SELECT id FROM telemetry_records WHERE uploaded=-1')


def test_smb_retention_and_indefinite_are_independent_of_local(environment,smb):
    _,store,vault=environment;cfg=configure(store,vault,smb_days='0');worker=exporter(store,smb[1])
    worker.capture_dashboard()
    telemetry.record(store,'metrics','m','m',{'cpu_percent':44},time.time()-60*86400)
    with store.connect() as c:c.execute('UPDATE telemetry_records SET received=?',(time.time()-60*86400,))
    worker.step(cfg)
    assert not store.rows('SELECT * FROM telemetry_records WHERE kind="metrics"')
    catalog=smb[1](cfg,'catalog',dataset='telemetry')['files'];assert len(catalog)>=1
    store.save('telemetry_archive_retention',0);worker.step({**cfg,'days':7})
    after=smb[1](cfg,'catalog',dataset='telemetry')['files']
    assert len(after)<len(catalog) and all(r['received']>=time.time()-7*86400 for r in after)


def test_snapshot_capture_filters_scheduler_writes_and_network_host_mapping(environment):
    _,store,vault=environment;agent(store);configure(store,vault);now=time.time()
    with store.connect() as c:
        c.execute("INSERT INTO integrations(id,machine_id,kind,name,config,secret,snapshot,at) VALUES('p','m','plex','Plex','{}','encrypted-secret',?,?)",(json.dumps({'responsive':True,'libraries':[{'id':1,'name':'Movies'}]}),now))
        c.execute("UPDATE integrations SET next_run=?,lease_until=? WHERE id='p'",(now+60,now+30))
        c.execute("UPDATE integrations SET snapshot=?,at=? WHERE id='p'",('{"responsive":false}',now+1))
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('m','agent',now,'{"cpu_percent":5}'))
        c.execute('INSERT INTO network_samples VALUES(?,?,?)',('interface:m:eth0',now,'{"link_speed":1000}'))
    rows=store.rows('SELECT * FROM telemetry_records WHERE kind="integration"')
    assert len(rows)==2 and 'encrypted-secret' not in str(rows)
    assert store.rows('SELECT machine_id FROM telemetry_records WHERE kind="network"')[0]['machine_id']=='m'
    assert store.rows('SELECT machine_id FROM telemetry_records WHERE kind="metrics"')[0]['machine_id']=='m'


def test_dashboard_capture_continues_when_network_upload_fails(environment):
    _,store,vault=environment;configure(store,vault)
    worker=archive.Archiver(store,vault,Mock(side_effect=OSError('offline')))
    worker.upload=Mock(side_effect=OSError('offline'))
    worker.step()
    assert store.rows('SELECT id FROM telemetry_records WHERE kind="dashboard"')
    assert store.setting('network_log_archive_status')['error']=='offline'
