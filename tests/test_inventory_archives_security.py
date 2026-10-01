import copy
import json
import pytest
from unittest.mock import patch
from aiticket.db import Store
from aiticket.inventory import export_inventory,import_inventory
from aiticket.proxmox import discover,link,Client,schedule
from aiticket.policies import group_create,group_assign,override
from aiticket.administration import archive_incident
from aiticket.engine import observe
from test_proxmox import setup,inventory
from test_core import seed
from test_notification_overrides import values


def populated(store,vault):
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    guest=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu'")[0]
    link(store,guest['id'],None,'running','Guest')
    mid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(guest['id'],))[0]['machine_id']
    group=group_create(store,'Applications')
    group_assign(store,mid,group)
    override(store,'group',group,values())
    schedule(store,'p1',300)
    with store.connect() as c:
        c.execute("INSERT INTO agents(id,machine_id,credential_digest,action_credential_digest) VALUES('agent',?,'monitor-secret','action-secret')",(mid,))
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('heartbeat',?,'Heartbeat','agent',?,60)",(mid,json.dumps({'agent_id':'agent','max_age':180})))
    return mid


def test_full_roundtrip_without_credentials_or_authority(environment,tmp_path):
    _,store,vault=environment
    populated(store,vault)
    document=export_inventory(store)
    serialized=json.dumps(document)
    assert not any(value in serialized for value in ('fixture-secret','monitor-secret','action-secret','credential_digest','token_secret','recovery_role'))
    target=Store(tmp_path/'destination.db')
    import_inventory(target,vault,document)
    assert len(target.rows('SELECT * FROM machines'))==1
    assert len(target.rows('SELECT * FROM checks'))==2
    assert all(r['enabled']==0 for r in target.rows('SELECT * FROM checks'))
    assert all(r['recovery_role']=='protected' for r in target.rows('SELECT * FROM machines'))
    assert target.rows('SELECT interval FROM discovery_schedules')[0]['interval']==0
    assert target.rows('SELECT revoked FROM agents')[0]['revoked']==1
    assert vault.decrypt(target.rows('SELECT token_secret FROM proxmox_connections')[0]['token_secret'])==''
    assert target.rows('SELECT * FROM notification_overrides')
    # Re-import is additive/idempotent; local credentials are retained.
    before=store.rows('SELECT credential_digest FROM agents')
    import_inventory(store,vault,document)
    assert store.rows('SELECT credential_digest FROM agents')==before
    assert vault.decrypt(store.rows('SELECT token_secret FROM proxmox_connections')[0]['token_secret'])=='fixture-secret'


def test_invalid_graph_and_bindings_roll_back(environment):
    _,store,vault=environment
    mid=populated(store,vault)
    original=export_inventory(store)
    for mutate in ('cycle','secret','binding','unknown'):
        doc=copy.deepcopy(original)
        if mutate=='cycle': doc['tables']['machines'][0]['parent_id']=mid
        if mutate=='secret': doc['tables']['checks'][0]['config']['token_secret']='hidden'
        if mutate=='binding': doc['tables']['proxmox_objects'][0]['object_key']='different'
        if mutate=='unknown': doc['tables']['checks'][0]['machine_id']='missing'
        with pytest.raises(ValueError): import_inventory(store,vault,doc)
        assert export_inventory(store)==original
        assert all(r['enabled']==1 for r in store.rows('SELECT * FROM checks'))


def test_archive_preserves_evidence_and_snapshot_immutability(environment):
    _,store,_=environment
    seed(store)
    for n in range(3): observe(store,'c',False,{},now=100+n)
    iid=store.rows('SELECT id FROM incidents')[0]['id']
    with pytest.raises(ValueError): archive_incident(store,iid)
    observe(store,'c',True,{},now=103)
    observe(store,'c',True,{},now=104)
    before=store.rows('SELECT * FROM observations')
    archive_incident(store,iid)
    archive_incident(store,iid)
    assert store.rows('SELECT * FROM observations')==before
    snapshot=store.rows('SELECT * FROM incident_archives')[0]
    document=json.loads(snapshot['document'])
    assert len(document['observations'])==5 and document['incident']['closed']==104
    assert len(store.rows('SELECT * FROM incident_archives'))==1
    archive_incident(store,iid,restore=True)
    assert store.rows('SELECT archived_at FROM incidents')[0]['archived_at'] is None
    assert store.rows('SELECT * FROM incident_archives')[0]==snapshot
    with pytest.raises(Exception,match='immutable'):
        with store.connect() as c: c.execute("UPDATE incident_archives SET document='{}'")


def test_security_events_no_credentials(environment):
    app,store,_=environment
    client=app.test_client()
    client.get('/login')
    with client.session_transaction() as s: csrf=s['csrf']
    for n in range(5):
        assert client.post('/login',data={'csrf':csrf,'password':'secret-wrong-password'}).status_code==200
    assert client.post('/login',data={'csrf':csrf,'password':'secret-wrong-password'}).status_code==429
    assert client.post('/settings',data={'webhook':'secret-webhook'}).status_code==403
    records=store.rows('SELECT * FROM audit')
    assert sum(r['action']=='security.login_failed' for r in records)==5
    assert any(r['action']=='security.request_denied' and json.loads(r['details'])['status']==429 for r in records)
    assert 'secret-wrong-password' not in json.dumps(records) and 'secret-webhook' not in json.dumps(records)


def test_admin_transfer_review_and_archive_ui(signed_in):
    client,store,vault,csrf=signed_in
    populated(store,vault)
    document=client.get('/administration/inventory-export').json
    data={'csrf':csrf,'operation':'inventory_import','document':json.dumps(document)}
    assert client.post('/administration',data=data).status_code==400
    data['confirm']='yes'
    assert client.post('/administration',data=data).status_code==302
    check=store.rows("SELECT id FROM checks WHERE kind='proxmox_linked'")[0]['id']
    assert client.post('/checks/'+check+'/enabled',data={'csrf':csrf,'enabled':'yes'}).status_code==302
    assert b'Monitoring checks' in client.get('/hosts').data
    # Closed incident archive filters and downloadable immutable snapshot.
    seed(store)
    for n in range(3): observe(store,'c',False,{},now=100+n)
    observe(store,'c',True,{},now=103)
    observe(store,'c',True,{},now=104)
    iid=store.rows("SELECT id FROM incidents WHERE check_id='c'")[0]['id']
    assert client.post('/incidents/'+iid+'/archive',data={'csrf':csrf,'operation':'archive'}).status_code==302
    assert b'0 matching incidents' in client.get('/history').data
    assert b'1 matching incidents' in client.get('/history?archived=only').data
    assert client.get('/incidents/'+iid+'/archive-export').json['format']=='aiticket-incident-archive'
    assert client.post('/logout',data={'csrf':csrf}).status_code==302
    assert store.rows("SELECT * FROM audit WHERE action='security.logout'")
