import json
import time
from unittest.mock import patch
from aiticket.proxmox import Client, discover
from aiticket.proxmox_view import build, guest_history
from test_proxmox import setup


def seed(store, vault, ha=None):
    setup(store,vault)
    resources=[{'type':'node','id':'node/a','node':'a','status':'online','cpu':.3,'maxcpu':16,'mem':8*1024**3,'maxmem':32*1024**3},
               {'type':'node','id':'node/b','node':'b','status':'online'},
               {'type':'qemu','id':'qemu/209','name':'Web VM','node':'a','status':'running','cpu':.5,'maxcpu':4,'mem':2*1024**3,'maxmem':4*1024**3,'disk':1024**3,'maxdisk':16*1024**3},
               {'type':'lxc','id':'lxc/210','name':'Container','node':'b','status':'running','disk':1024**3,'maxdisk':4*1024**3}]
    def get(self,path):
        if path=='/cluster/resources':return resources
        if ha is None:raise PermissionError('HA not readable')
        return ha
    with patch.object(Client,'get',get):discover(store,vault,'p1')
    return {r['object_key']:r for r in store.rows('SELECT * FROM proxmox_objects')}


def test_workspace_placement_ha_and_filesystem_scope(environment):
    _,store,vault=environment
    objects=seed(store,vault,[{'sid':'vm:209'}])
    data=build(store,{'object':objects['node/a']})
    nodes={n['id']:n for n in data['nodes']}
    vm=nodes['a']['guests'][0];ct=nodes['b']['guests'][0]
    assert vm['ha'] is True and ct['ha'] is False
    assert vm['diskUsed'] is None and vm['allocatedDisk']==16
    assert ct['diskUsed']==1 and ct['disk']==4
    assert vm['href']=='/proxmox/resources/'+vm['object_id']
    assert not vm['linked'] and vm['cpu']==50
    assert data['selected']=='a'


def test_denied_ha_and_stale_inventory_do_not_imply_unmanaged(environment):
    _,store,vault=environment
    objects=seed(store,vault)
    assert build(store,{'object':objects['node/a']})['nodes'][0]['guests'][0]['ha'] is None
    with store.connect() as c:c.execute('UPDATE proxmox_objects SET last_seen=?',(time.time()-3600,))
    objects={r['object_key']:r for r in store.rows('SELECT * FROM proxmox_objects')}
    data=build(store,{'object':objects['node/a']})
    assert data['nodes'][0]['fresh'] is False
    assert data['nodes'][0]['guests'][0]['cpu'] is None


def test_history_exact_samples_window_entity_and_qemu_disk(environment):
    _,store,vault=environment
    objects=seed(store,vault)
    obj=objects['qemu/209'];now=time.time()
    with store.connect() as c:
        c.execute('DELETE FROM metric_samples')
        for entity,at,value in [(obj['id'],now-30,42.125),(obj['id'],now-4000,90),(obj['id'],now+300,95),(objects['lxc/210']['id'],now-20,99)]:
            c.execute('INSERT INTO metric_samples(entity_id,source,at,metrics) VALUES(?,?,?,?)',(entity,'proxmox',at,json.dumps({'cpu_percent':value,'disk_percent':50})))
    data=guest_history(store,obj)
    assert data['charts'][0]['samples']==[{'time':(now-30)*1000,'value':42.125}]
    assert all(c['label']!='Storage usage' for c in data['charts'])


def test_workspace_route_and_unassigned_node_render(signed_in):
    client,store,vault,_=signed_in
    objects=seed(store,vault)
    response=client.get('/proxmox/resources/'+objects['node/a']['id'])
    assert response.status_code==200 and b'px-payload' in response.data and b'Web VM' in response.data
    response=client.get('/proxmox/resources/'+objects['qemu/209']['id']+'/workspace-data?power_only=1')
    assert response.status_code==200 and 'history' not in response.json
    assert response.json['power']['start'] is False
    assert client.get('/proxmox/resources/'+objects['node/a']['id']+'/workspace-data').status_code==404
    with client.session_transaction() as session:session.clear()
    assert client.get('/proxmox/resources/'+objects['qemu/209']['id']+'/workspace-data').status_code==302


def test_agent_filesystem_and_addresses_with_stale_fallback(environment):
    from aiticket.proxmox import link
    _,store,vault=environment
    objects=seed(store,vault)
    obj=objects['qemu/209'];link(store,obj['id'],None,'running','Web VM')
    obj=store.rows('SELECT * FROM proxmox_objects WHERE id=?',(obj['id'],))[0]
    now=time.time();mid=obj['machine_id']
    telemetry={'cpu_percent':20,'memory_total_bytes':4*1024**3,'memory_available_bytes':3*1024**3,'disk_total_bytes':8*1024**3,'disk_free_bytes':6*1024**3}
    with store.connect() as c:
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,sampled_at,telemetry) VALUES(?,?,?,?,?,?)',('agent',mid,'fixture',now,now,json.dumps(telemetry)))
        c.execute('INSERT INTO network_inventory VALUES(?,?,?)',(mid,now,json.dumps({'interfaces':[{'addresses':['127.0.0.1','192.0.2.20','fe80::1','invalid']}]})))
    vm=build(store,{'object':objects['node/a']})['nodes'][0]['guests'][0]
    assert vm['cpu']==20 and vm['diskUsed']==2 and vm['disk']==8 and vm['allocatedDisk']==16
    assert vm['ips']==['192.0.2.20']
    with store.connect() as c:
        c.execute('UPDATE agents SET last_seen=?,sampled_at=?',(now-400,now-400))
        c.execute('UPDATE network_inventory SET at=?',(now-400,))
    vm=build(store,{'object':objects['node/a']})['nodes'][0]['guests'][0]
    assert vm['cpu']==50 and vm['diskUsed'] is None and vm['ips']==[]
    assert guest_history(store,obj)['source']=='proxmox'
