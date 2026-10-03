import json,time
import pytest
from aiticket import fleet_groups
from aiticket.db import uid
from aiticket.proxmox import Client,discover,link
from test_proxmox import setup,inventory
from unittest.mock import patch


def machine(store,name,os_name=None,revoked=False):
    mid=uid()
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(mid,name,time.time()))
        if os_name is not None:
            c.execute('INSERT INTO agents(id,machine_id,credential_digest,host_info,revoked,last_seen) VALUES(?,?,?,?,?,?)',(uid(),mid,uid(),json.dumps({'os':os_name}),int(revoked),1))
    return mid


def test_dynamic_groups_classify_os_nodes_and_revocation(environment):
    _,store,vault=environment
    linux=machine(store,'Linux','Ubuntu 24.04.4 LTS');windows=machine(store,'Windows','Microsoft Windows Server 2025')
    unknown=machine(store,'Unknown','');revoked=machine(store,'Revoked','Debian GNU/Linux',True);bare=machine(store,'Bare')
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):discover(store,vault,'p1')
    node=store.rows("SELECT id FROM proxmox_objects WHERE kind='node'")[0]['id']
    link(store,node,linux,'online')
    groups={g['id']:g['members'] for g in fleet_groups.catalog(store)['categories'][0]['groups']}
    assert groups['builtin:linux']==[linux]
    assert groups['builtin:windows']==[windows]
    assert set(groups['builtin:agents'])=={linux,windows,unknown}
    assert groups['builtin:proxmox']==[linux]
    assert set(groups['builtin:no-agent'])=={bare,revoked}
    with store.connect() as c:c.execute('UPDATE agents SET revoked=1 WHERE machine_id=?',(linux,))
    groups={g['id']:g['members'] for g in fleet_groups.catalog(store)['categories'][0]['groups']}
    assert groups['builtin:linux']==[] and groups['builtin:proxmox']==[linux]


def test_custom_group_crud_overlapping_members_and_isolated_notifications(signed_in):
    client,store,_,csrf=signed_in;one=machine(store,'One');two=machine(store,'Two')
    with store.connect() as c:
        c.execute("INSERT INTO notification_groups VALUES('legacy','Existing notifications')")
        c.execute('INSERT INTO machine_groups VALUES(?,?)',(one,'legacy'))
    created=client.post('/fleet/groups',data={'csrf':csrf,'name':'Media servers','members':[one,two]})
    assert created.status_code==302
    identifier=created.location.rsplit('/',1)[-1]
    other=fleet_groups.save(store,'Another group',[one])
    assert client.get(created.location).status_code==200
    assert len(store.rows('SELECT * FROM fleet_group_members WHERE machine_id=?',(one,)))==2
    assert client.post(created.location,data={'csrf':csrf,'name':'Media renamed','members':[two]}).status_code==302
    assert store.rows('SELECT machine_id FROM fleet_group_members WHERE group_id=?',(identifier,))==[{'machine_id':two}]
    assert client.post('/fleet/groups',data={'csrf':csrf,'name':'media RENAMED'}).status_code==400
    assert client.post(created.location,data={'csrf':csrf,'name':'Bad','members':'missing'}).status_code==400
    assert store.rows('SELECT name FROM fleet_groups WHERE id=?',(identifier,))[0]['name']=='Media renamed'
    page=client.get('/fleet')
    assert page.status_code==200 and b'Built-in groups' in page.data and b'Media renamed' in page.data
    catalog=fleet_groups.catalog(store)
    assert catalog['categories'][-1]['groups'][0]['members']==[one]
    assert client.post(created.location,data={'csrf':csrf,'operation':'delete'}).status_code==400
    assert client.post(created.location,data={'csrf':csrf,'operation':'delete','confirm':'yes'}).status_code==302
    assert not store.rows('SELECT * FROM fleet_group_members WHERE group_id=?',(identifier,))
    assert store.rows('SELECT * FROM fleet_groups WHERE id=?',(other,))
    assert len(store.rows('SELECT * FROM machines'))==2
    assert store.rows('SELECT * FROM machine_groups')==[{'machine_id':one,'group_id':'legacy'}]
    assert client.get(created.location).status_code==404


def test_groups_require_auth_csrf_and_reject_network_devices(environment,signed_in):
    app,_,_=environment;client,store,_,csrf=signed_in
    assert app.test_client().get('/fleet/groups').status_code==302
    assert client.post('/fleet/groups',data={'name':'No csrf'}).status_code==403
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('unifi:test','Appliance',1)")
    assert client.post('/fleet/groups',data={'csrf':csrf,'name':'Wrong inventory','members':'unifi:test'}).status_code==400
    assert not store.rows('SELECT * FROM fleet_groups')
    identifier=fleet_groups.save(store,'Empty group',[])
    assert next(g for g in fleet_groups.catalog(store)['custom_groups'] if g['id']==identifier)['members']==[]
