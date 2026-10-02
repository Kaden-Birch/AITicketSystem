import json
from unittest.mock import patch
import pytest
from aiticket.host_admin import edit,open_ticket
from aiticket.hostview import overview,object_detail
from aiticket.proxmox import Client,discover
from aiticket.inventory import export_inventory
from test_proxmox import setup,inventory


def test_edit_preserves_identity_and_rejects_cycles(signed_in):
    client,store,_,csrf=signed_in
    client.post('/hosts',data={'csrf':csrf,'name':'Agent first'})
    mid=store.rows('SELECT id FROM machines')[0]['id']
    client.post('/hosts',data={'csrf':csrf,'name':'Parent','parent':mid})
    parent=store.rows("SELECT id FROM machines WHERE name='Parent'")[0]['id']
    response=client.post('/hosts/'+mid+'/edit',data={'csrf':csrf,'name':'Renamed host'})
    assert response.status_code==302
    assert store.rows('SELECT name FROM machines WHERE id=?',(mid,))[0]['name']=='Renamed host'
    assert client.post('/hosts/'+mid+'/edit',data={'csrf':csrf,'name':'Bad','parent':parent}).status_code==400
    assert b'Renamed host' in client.get('/hosts/'+mid).data
    assert client.post('/hosts/'+mid+'/edit',data={'name':'No CSRF'}).status_code==403


def test_unassigned_node_dashboard_guests_and_late_agent_link(signed_in):
    client,store,vault,csrf=signed_in
    setup(store,vault)
    resources=inventory()
    for r in resources:
        r.update(cpu=.2,maxcpu=8,mem=1024,maxmem=2048,uptime=500)
    with patch.object(Client,'get',return_value=resources): discover(store,vault,'p1')
    node=store.rows("SELECT * FROM proxmox_objects WHERE kind='node'")[0]
    guest=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu' AND template=0")[0]
    assert len(object_detail(store,node['id'])['guests'])==2
    dashboard=client.get('/').data
    assert ('/proxmox/resources/'+node['id']).encode() in dashboard
    assert b'20.0%' in dashboard and b'not assigned' in dashboard
    client.post('/hosts',data={'csrf':csrf,'name':'Previously enrolled VM'})
    mid=store.rows("SELECT id FROM machines WHERE name='Previously enrolled VM'")[0]['id']
    with store.connect() as c:
        c.execute('INSERT INTO agents(id,machine_id,credential_digest) VALUES(?,?,?)',('previous-agent',mid,'unchanged-credential-digest'))
    iid=open_ticket(store,mid,'Original ticket','Retain this history','low')
    response=client.post('/hosts/'+mid+'/proxmox-link',data={'csrf':csrf,'object_id':guest['id'],'expected':'running','confirm':'yes'})
    assert response.status_code==302
    assert store.rows('SELECT machine_id,credential_digest FROM agents WHERE id=?',('previous-agent',))[0]=={'machine_id':mid,'credential_digest':'unchanged-credential-digest'}
    assert b'Proxmox snapshot' in client.get('/hosts/'+mid).data
    assert store.rows('SELECT machine_id FROM incidents WHERE id=?',(iid,))[0]['machine_id']==mid
    assert store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(guest['id'],))[0]['machine_id']==mid
    assert client.post('/hosts/'+mid+'/proxmox-link',data={'csrf':csrf,'object_id':node['id'],'expected':'online','confirm':'yes'}).status_code==400
    assert client.post('/proxmox/resources/'+node['id']+'/link',data={'csrf':csrf,'create_name':'Proxmox node','expected':'online','confirm':'yes'}).status_code==302
    assert store.rows('SELECT parent_id FROM machines WHERE id=?',(mid,))[0]['parent_id']==store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(node['id'],))[0]['machine_id']


def test_manual_ticket_is_not_a_probe_and_closes_independently(signed_in):
    client,store,_,csrf=signed_in
    client.post('/hosts',data={'csrf':csrf,'name':'Tagged host'})
    mid=store.rows('SELECT id FROM machines')[0]['id']
    response=client.post('/tickets/new',data={'csrf':csrf,'machine_id':mid,'title':'User observed issue','description':'Application intermittently slow','severity':'medium'})
    assert response.status_code==302
    iid=response.location.rsplit('/',1)[-1]
    row=store.rows('SELECT * FROM incidents WHERE id=?',(iid,))[0]
    assert json.loads(row['report'])['manual_ticket']
    assert not store.rows('SELECT * FROM deliveries') and not store.rows('SELECT * FROM ai_jobs')
    assert not store.rows('SELECT * FROM checks WHERE enabled=1')
    assert export_inventory(store)['tables']['checks']==[]
    assert b'USER-REPORTED' in client.get(response.location).data
    assert b'Application intermittently slow' in client.get(response.location).data
    assert client.post('/checks/'+row['check_id']+'/enabled',data={'csrf':csrf,'enabled':'yes'}).status_code==400
    client.post('/incidents/'+iid+'/note',data={'csrf':csrf,'operation':'resolve','note':'Finished testing'})
    closed=store.rows('SELECT * FROM incidents WHERE id=?',(iid,))[0]
    assert closed['closed'] and closed['status']=='Resolved'
    assert client.post('/tickets/new',data={'csrf':csrf,'machine_id':'missing','title':'Invalid','description':'Bad','severity':'low'}).status_code==400
    assert client.post('/tickets/new',data={'machine_id':mid,'title':'Invalid','description':'Bad'}).status_code==403


def test_manual_ticket_explicit_ai_preserves_report_and_never_auto_queues(environment):
    from test_codex_mode import configure
    from aiticket import ai
    _,store,vault=environment
    existing=configure(store,vault)
    mid=store.rows('SELECT machine_id FROM incidents WHERE id=?',(existing,))[0]['machine_id']
    identifier=open_ticket(store,mid,'Manual AI trial','Synthetic user report for a read-only test','low')
    assert ai.request_job(store,vault,identifier,automatic=True) is None
    job=ai.request_job(store,vault,identifier)
    saved=store.rows('SELECT evidence FROM ai_jobs WHERE id=?',(job,))[0]
    assert 'Synthetic user report' in saved['evidence']
    assert 'user reported' in saved['evidence']
