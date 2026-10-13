import json,time
from datetime import datetime,timezone
from unittest.mock import patch
from aiticket import backup_health as b
from test_log_archive import smb


def job(now,key='task:1'):
    return {'key':key,'name':'Data replication','kind':'Replication','machine_id':'nas','enabled':True,'schedule':{'hour':'2','minute':'0'},'next_due':now+60,'status':'FINISHED','last_run':now-60,'last_success':now-60,'duration':None,'reference':'replication:1','note':'Completion only','target':'backup/data'}


def seed(store):
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('nas','NAS',?)",(time.time(),))


def test_deadline_persistence_recovery_and_scoped_archive(environment):
    _,store,_=environment;seed(store);now=time.time();store.save('telemetry_capture_enabled',True)
    first=job(now);b.save_inventory(store,'truenas','connection',[first],[],now)
    assert b.probe(store,{'inventory':'truenas:connection','key':first['key']})[0] is True
    later=now+4000;second=job(later);second['last_run']=now-60;second['last_success']=now-60
    b.save_inventory(store,'truenas','connection',[second],[],later)
    saved=json.loads(store.rows('SELECT data FROM backup_inventory')[0]['data'])[0]
    assert saved['pending_due']==now+60
    assert b.evaluate(saved,later)[0] is False
    second['last_success']=later;second['last_run']=later
    b.save_inventory(store,'truenas','connection',[second],[],later)
    saved=json.loads(store.rows('SELECT data FROM backup_inventory')[0]['data'])[0]
    assert b.evaluate(saved,later)[0] is True
    assert store.rows("SELECT count(*) n FROM checks WHERE kind='backup_health'")[0]['n']==1
    assert store.rows("SELECT * FROM telemetry_records WHERE kind='backup' AND machine_id='nas'")
    from aiticket.evidence import page
    with store.connect() as c:
        evidence=page(c,'nas','backups')
    assert evidence['items'][0]['restore_verified'] is False
    assert 'backup/data' in json.dumps(evidence)


def test_unknown_stale_disabled_and_schedule_changes(environment):
    _,store,_=environment;seed(store);now=time.time();value=job(now)
    b.save_inventory(store,'truenas','c',[value],[],now)
    value['schedule']={'hour':'4','minute':'0'};value['next_due']=now+8000
    b.save_inventory(store,'truenas','c',[value],[],now+4000)
    saved=json.loads(store.rows('SELECT data FROM backup_inventory')[0]['data'])[0]
    assert saved['pending_due']==now+8000
    assert b.evaluate(saved,now+5000)[0] is None # stale, not a backup failure
    saved['observed_at']=now;saved['status']='FAILED';saved['visibility_error']=True
    assert b.evaluate(saved,now)[0] is None
    saved['visibility_error']=False
    assert b.evaluate(saved,now)[0] is False
    saved['enabled']=False;b.save_inventory(store,'truenas','c',[saved],[],now+4100)
    assert store.rows("SELECT enabled FROM checks WHERE kind='backup_health'")[0]['enabled']==0


def test_cron_timezone_dst_and_ambiguous_fields():
    now=datetime(2026,10,13,6,tzinfo=timezone.utc).timestamp()
    result=b.cron_next({'minute':'0','hour':'2'},'America/Edmonton',now)
    assert datetime.fromtimestamp(result,timezone.utc).hour==8
    assert b.cron_next({'minute':'0','hour':'2'},None,now) is None
    assert b.cron_next({'dom':'1','dow':'1'},'UTC',now) is None
    assert b.cron_next({'minute':'*/0'},'UTC',now) is None
    assert b.stamp({'$date':now*1000})==now
    assert b.stamp('2026-10-13T12:00:00') is None


def test_proxmox_guest_mapping_uses_vm_id_not_names(environment):
    from test_proxmox import setup,inventory
    from aiticket.proxmox import Client,discover,link
    _,store,vault=environment;setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):discover(store,vault,'p1')
    guest=store.rows("SELECT * FROM proxmox_objects WHERE object_key='qemu/209'")[0]
    link(store,guest['id'],None,'stopped','Guest');now=time.time()
    def get(self,path):
        if path=='/cluster/backup':return [{'id':'backup','vmid':'209','schedule':'02:00','next-run':now+100,'storage':'pbs'}]
        if '/nodes/a/tasks?' in path:return [{'id':'209','type':'vzdump','status':'OK','starttime':now-200,'endtime':now-100,'upid':'run:209'}]
        return []
    with patch.object(Client,'get',get):jobs,errors=b.pve_collect(store,vault,store.rows('SELECT * FROM proxmox_connections')[0],now)
    value=next(j for j in jobs if j['key']=='guest:'+guest['id'])
    assert value['status']=='SUCCESS' and value['duration']==100
    assert value['next_due']==now+100 and value['reference']=='run:209'
    assert value['machine_id']==store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(guest['id'],))[0]['machine_id']


def test_nas_projection_and_page_no_credentials(signed_in):
    client,store,vault,_=signed_in;seed(store);now=time.time()
    from aiticket.integrations import save
    identifier=save(store,vault,'nas','truenas','NAS',{'interval':60,'url':'https://nas.test','username':'monitor','ca':True},'fixture-secret')
    snapshot={'backup_timezone':'UTC','replication_tasks':[{'id':1,'name':'Replication','enabled':True,'schedule':{'hour':'2','minute':'0'},'state':{'state':'FINISHED','datetime':'2026-10-13T02:00:00+00:00'},'ssh_credentials':{'password':'must-not-leak'}}]}
    jobs=b.nas_jobs(snapshot,'nas');b.save_inventory(store,'truenas',identifier,jobs,[],now)
    assert 'must-not-leak' not in json.dumps(jobs)
    response=client.get('/backups');assert response.status_code==200 and b'Replication' in response.data and b'Not verified' in response.data
    assert b'fixture-secret' not in response.data
    assert client.get('/hosts/nas').status_code==200


def test_collector_failure_fallback_and_deleted_source(environment):
    from test_proxmox import setup
    _,store,vault=environment;setup(store,vault)
    now=time.time();seed(store)
    with patch('aiticket.backup_health.pve_collect',side_effect=[OSError('offline'),([job(now)],[])]):
        assert b.tick(store,vault)
    assert not store.rows('SELECT error FROM backup_inventory')[0]['error']
    with store.connect() as c:c.execute('UPDATE backup_inventory SET next_run=0')
    with patch('aiticket.backup_health.pve_collect',side_effect=OSError('offline')):assert b.tick(store,vault)
    assert b.probe(store,{'inventory':'proxmox:cluster','key':'task:1'})[0] is None
    with store.connect() as c:
        c.execute('DELETE FROM proxmox_connections')
    b.tick(store,vault)
    assert store.rows("SELECT enabled FROM checks WHERE kind='backup_health'")[0]['enabled']==0


def test_backup_evidence_ticket_boundary(environment):
    from test_evidence_groups_maintenance import operational
    from aiticket import ai
    app,store,vault=environment;_,run=operational(store,vault)
    now=time.time();value=job(now);value['machine_id']='m'
    b.save_inventory(store,'truenas','source',[value],[],now)
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('other','Other',?)",(now,))
    unrelated=job(now);unrelated['machine_id']='other';unrelated['name']='private-other-job'
    b.save_inventory(store,'truenas','other',[unrelated],[],now)
    credential=vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(run,))[0]['credential']);headers={'Authorization':'Bearer '+credential};client=app.test_client();path='/api/hermes/'+run+'/command'
    response=client.post(path,json={'action':'evidence','source':'backups'},headers=headers)
    assert response.status_code==200 and 'private-other-job' not in response.get_data(as_text=True)
    assert client.post(path,json={'action':'evidence','source':'backups','machine_id':'other'},headers=headers).status_code==403


def test_backup_telemetry_roundtrips_to_smb(environment,smb,tmp_path):
    from aiticket import telemetry_archive as telemetry
    from test_log_archive import configure
    _,store,vault=environment;seed(store);now=time.time();cfg=configure(store,vault)
    b.save_inventory(store,'truenas','c',[job(now)],[],now)
    record=telemetry.local_search(store,{'machine':'nas','kind':'backup','start':now-1,'end':now+1})[0]
    assert telemetry.validate_document(record)
    worker=telemetry.Exporter(store,smb[1],tmp_path);worker.step(cfg)
    files=smb[1](cfg,'catalog',dataset='telemetry')['files']
    result_file=tmp_path/'backup-search.json'
    smb[1](cfg,'search',dataset='telemetry',file=str(result_file),names=[f['name'] for f in files],params={'machine':'nas','kind':'backup','start':now-1,'end':now+1,'q':'','limit':10})
    assert any(r['kind']=='backup' and r['machine_id']=='nas' for r in json.loads(result_file.read_text()))


def test_backup_check_policy_can_be_edited_without_changing_source(signed_in):
    client,store,_,csrf=signed_in;seed(store);now=time.time()
    b.save_inventory(store,'truenas','c',[job(now)],[],now)
    check=store.rows("SELECT * FROM checks WHERE kind='backup_health'")[0]
    response=client.post('/checks/'+check['id']+'/edit',data={'csrf':csrf,'name':'Backup health','interval':'300','fail_after':'3','recover_after':'2','severity':'high'})
    assert response.status_code==302
    saved=store.rows('SELECT * FROM checks WHERE id=?',(check['id'],))[0]
    assert saved['severity']=='high' and json.loads(saved['config'])['inventory']=='truenas:c'
