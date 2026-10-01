import json
from unittest.mock import patch
import pytest
from aiticket.db import uid
from aiticket.proxmox import discover,link,unlink,Client
from aiticket.engine import claim,observe


def setup(store,vault):
    with store.connect() as c:
        c.execute("INSERT INTO proxmox_clusters VALUES('cluster','Lab')")
        for n in (1,2):
            c.execute('INSERT INTO proxmox_connections VALUES(?,?,?,?,?,?,?,NULL,NULL)',(f'p{n}','cluster',f'Endpoint {n}',f'https://192.0.2.{n}:8006','monitor@pve!readonly',vault.encrypt('fixture-secret'),None))


def inventory(node='a'):
    return [{'type':'node','id':'node/a','node':'a','status':'online'},
            {'type':'node','id':'node/b','node':'b','status':'online'},
            {'type':'qemu','id':'qemu/209','name':'Guest','node':node,'status':'stopped'},
            {'type':'lxc','id':'lxc/210','name':'Template','node':'a','status':'stopped','template':1},
            {'type':'storage','id':'storage/a/local','storage':'local','node':'a','status':'available'}]


def test_duplicate_endpoints_migration_and_unlink_history(environment):
    _,store,vault=environment
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        assert discover(store,vault,'p1')==5
        discover(store,vault,'p2')
    assert len(store.rows('SELECT * FROM proxmox_objects'))==5
    objects={r['object_key']:r for r in store.rows('SELECT * FROM proxmox_objects')}
    link(store,objects['node/a']['id'],None,'online','Node A')
    link(store,objects['node/b']['id'],None,'online','Node B')
    link(store,objects['qemu/209']['id'],None,'stopped','Guest')
    guest=store.rows("SELECT * FROM proxmox_objects WHERE object_key='qemu/209'")[0]
    machine=store.rows('SELECT * FROM machines WHERE id=?',(guest['machine_id'],))[0]
    parent_before=machine['parent_id']
    with patch.object(Client,'get',return_value=inventory('b')):
        discover(store,vault,'p2')
    assert store.rows('SELECT * FROM machines WHERE id=?',(guest['machine_id'],))[0]['parent_id']!=parent_before
    assert store.rows("SELECT * FROM proxmox_objects WHERE object_key='qemu/209'")[0]['id']==guest['id']
    for i in range(3):
        observe(store,guest['check_id'],False,{},now=i+1)
    unlink(store,guest['id'])
    assert len(store.rows('SELECT * FROM incidents'))==1
    assert len(store.rows('SELECT * FROM observations'))==3
    assert store.rows('SELECT enabled FROM checks WHERE id=?',(guest['check_id'],))[0]['enabled']==0
    assert store.rows('SELECT * FROM audit WHERE action=?',('proxmox.unlinked',))


def test_retirement_prevents_reused_id_inheriting_machine(environment):
    _,store,vault=environment
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    old=store.rows("SELECT * FROM proxmox_objects WHERE object_key='qemu/209'")[0]
    link(store,old['id'],None,'stopped','Old guest')
    unlink(store,old['id'],retire=True)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    new=store.rows("SELECT * FROM proxmox_objects WHERE object_key='qemu/209' AND present=1")[0]
    assert new['id']!=old['id'] and new['generation']==2 and new['machine_id'] is None


def test_template_exclusion_missing_visibility_and_explicit_link(environment):
    _,store,vault=environment
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    template=store.rows("SELECT * FROM proxmox_objects WHERE template=1")[0]
    with pytest.raises(ValueError,match='Templates'):
        link(store,template['id'],None,'stopped','Template')
    with patch.object(Client,'get',return_value=[]):
        discover(store,vault,'p2')
    assert len(store.rows('SELECT * FROM proxmox_objects WHERE present=1'))==5
    assert not store.rows('SELECT * FROM machines')


def test_connection_creation_and_secret_hiding(signed_in):
    client,store,_,csrf=signed_in
    assert client.get('/proxmox').status_code==200
    data={'csrf':csrf,'operation':'connection','name':'Endpoint','url':'https://192.0.2.10:8006','cluster_name':'Lab','token_id':'monitor@pve!readonly','token_secret':'fixture-secret'}
    assert client.post('/proxmox',data=data).status_code==302
    assert b'fixture-secret' not in client.get('/proxmox').data
    assert 'fixture-secret' not in json.dumps(store.rows('SELECT * FROM audit'))
    assert client.post('/proxmox',data=data).status_code==400
    connection=store.rows('SELECT * FROM proxmox_connections')[0]
    with patch.object(Client,'get',return_value=inventory()):
        assert client.post('/proxmox',data={'csrf':csrf,'operation':'discover','connection_id':connection['id']}).status_code==302
    obj=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu'")[0]
    data={'csrf':csrf,'operation':'link','object_id':obj['id'],'create_name':'Guest','expected':'stopped'}
    assert client.post('/proxmox',data=data).status_code==400
    data['confirm']='yes'
    assert client.post('/proxmox',data=data).status_code==302
    assert len(store.rows('SELECT * FROM machines'))==1


def test_endpoint_fallback_and_stopped_expected_state(environment):
    from aiticket.adapters import probe
    _,store,vault=environment
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    obj=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu'")[0]
    link(store,obj['id'],None,'stopped','Guest')
    check=store.rows("SELECT * FROM checks WHERE kind='proxmox_linked'")[0]
    with patch.object(Client,'get',side_effect=[OSError('unreachable'),inventory()]):
        healthy,evidence=probe(check['kind'],json.loads(check['config']),vault,store)
    assert healthy and evidence['expected']=='stopped'


def test_migration_to_unlinked_node_clears_old_parent(environment):
    _,store,vault=environment
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    node=store.rows("SELECT * FROM proxmox_objects WHERE object_key='node/a'")[0]
    guest=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu'")[0]
    link(store,node['id'],None,'online','Node A')
    link(store,guest['id'],None,'stopped','Guest')
    mid=store.rows('SELECT machine_id FROM proxmox_objects WHERE id=?',(guest['id'],))[0]['machine_id']
    assert store.rows('SELECT parent_id FROM machines WHERE id=?',(mid,))[0]['parent_id']
    with patch.object(Client,'get',return_value=inventory('b')):
        discover(store,vault,'p2')
    assert store.rows('SELECT parent_id FROM machines WHERE id=?',(mid,))[0]['parent_id'] is None
