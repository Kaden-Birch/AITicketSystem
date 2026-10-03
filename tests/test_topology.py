import copy
import json
import time
from unittest.mock import patch
import pytest
from aiticket import topology,unifi,ai
from aiticket.db import uid
from test_commands import setup
from test_codex_mode import configure
from test_unifi import configured


def network():
    return {'machine_type':'physical','neighbors':[],'interfaces':[{'name':'eno1','kind':'physical','mac':'aa:bb:cc:dd:ee:ff','carrier':True,'state':'up','master':'','addresses':['10.0.0.2'],'members':[]}]}


def seed(store,vault,machine='shell-host'):
    row=configured(store,vault,'network');now=time.time()
    snapshot={'sampled_at':now,'readings':{'devices':{'items':[{'id':'sw1','name':'Switch','macAddress':'11:22:33:44:55:66','state':'ONLINE'}]},'device:sw1':{'interfaces':{'ports':[{'idx':8,'id':'Ethernet8','state':'UP','nativeNetworkId':'net10','taggedNetworkIds':['net20']},{'idx':9,'id':'Ethernet9','state':'UP'}]}},'clients':{'items':[{'macAddress':'aa:bb:cc:dd:ee:ff','uplinkDeviceId':'sw1','uplinkPortIndex':8}]}},'errors':{}}
    with store.connect() as c:
        c.execute('UPDATE unifi_connections SET snapshot=? WHERE id=?',(json.dumps(snapshot),row['id']))
        unifi.retain(c,row,snapshot)
        c.execute('INSERT INTO network_inventory VALUES(?,?,?)',(machine,now,json.dumps(network())))
    return row,snapshot


def facts(store,machine='shell-host',now=None):
    with store.connect() as c:return topology.context(c,machine,now)


def test_exact_candidates_confirmed_multi_uplinks_and_mac_change(environment):
    _,store,vault=environment;setup(store);row,snapshot=seed(store,vault)
    result=facts(store)
    assert result['machine_type']=='physical' and result['fresh']
    assert len(result['links'])==1 and result['links'][0]['confidence']=='candidate'
    assert result['links'][0]['port']==8 and result['links'][0]['networks']['native']=='net10'
    with store.connect() as c:assert len(topology.choices(c))==2
    choice=json.dumps([row['id'],'sw1',8]);topology.save(store,'shell-host','eno1',choice)
    topology.save(store,'shell-host','eno1',choice) # idempotent identical association
    topology.save(store,'shell-host','eno2',json.dumps([row['id'],'sw1',9]))
    result=facts(store)
    assert len(result['links'])==2 and all(x['confidence']=='confirmed' for x in result['links'])
    modified=network();modified['interfaces'][0]['mac']='00:00:00:00:00:01'
    with store.connect() as c:c.execute('UPDATE network_inventory SET data=? WHERE machine_id=?',(json.dumps(modified),'shell-host'))
    assert facts(store)['links'][0]['confidence']=='needs_verification'
    with pytest.raises(ValueError):topology.save(store,'shell-host','eno1',json.dumps([row['id'],'sw1',999]))
    assert len(store.rows('SELECT * FROM network_links'))==2


def test_lldp_exact_identifier_only_and_shared_bond_mac_is_ambiguous(environment):
    _,store,vault=environment;setup(store);row,snapshot=seed(store,vault)
    data=network();data['neighbors']=[{'interface':'eno1','chassis_mac':'11:22:33:44:55:66','port_id':'Ethernet8','port_id_type':'ifname'}]
    with store.connect() as c:c.execute('UPDATE network_inventory SET data=?',(json.dumps(data),))
    assert facts(store)['links'][0]['confidence']=='corroborated'
    data['neighbors'][0]['port_id']='8' # Do not parse arbitrary numeric LLDP labels as port indexes.
    with store.connect() as c:c.execute('UPDATE network_inventory SET data=?',(json.dumps(data),))
    assert facts(store)['links'][0]['confidence']=='candidate'
    data['interfaces'].append({**data['interfaces'][0],'name':'bond0','kind':'bond','members':['eno1'],'bond_mode':'802.3ad'})
    with store.connect() as c:c.execute('UPDATE network_inventory SET data=?',(json.dumps(data),))
    assert facts(store)['links']==[]
    data['neighbors'][0]['port_id']='Ethernet8'
    with store.connect() as c:c.execute('UPDATE network_inventory SET data=?',(json.dumps(data),))
    assert facts(store,now=time.time()+1000)['links'][0]['confidence']=='last_known'


def test_multiple_switches_history_missing_ports_and_deleted_device(environment):
    _,store,vault=environment;setup(store);row,snapshot=seed(store,vault)
    # Add a second connection/switch, retaining independent credential boundaries.
    second=unifi.save(store,vault,{'name':'Other console','url':'https://10.0.0.3','secret':'other-secret','kind':'network'})
    other=store.rows('SELECT * FROM unifi_connections WHERE id=?',(second,))[0]
    other_snapshot=copy.deepcopy(snapshot);other_snapshot['readings']['devices']['items'][0]['id']='sw2'
    other_snapshot['readings']['devices']['items'][0]['name']='Other switch'
    other_snapshot['readings']['device:sw2']=other_snapshot['readings'].pop('device:sw1')
    other_snapshot['readings']['clients']={'items':[]}
    with store.connect() as c:
        c.execute('UPDATE unifi_connections SET snapshot=? WHERE id=?',(json.dumps(other_snapshot),second));unifi.retain(c,other,other_snapshot)
    topology.save(store,'shell-host','eno1',json.dumps([row['id'],'sw1',8]))
    topology.save(store,'shell-host','eno2',json.dumps([second,'sw2',8]))
    now=time.time()
    with store.connect() as c:
        entity=topology.port_entity(row['id'],'sw1',8)
        c.execute('DELETE FROM network_samples WHERE entity=?',(entity,))
        topology.retain(c,entity,now-20,{'state':'UP'});topology.retain(c,entity,now-10,{'state':'DOWN'});topology.retain(c,entity,now,{'state':'DOWN'})
        states=topology.history(c,entity)
        assert states[0]['state']=='DOWN' and states[0]['observed_at']==now-10 and states[0]['last_observed_at']==now
        c.execute('UPDATE unifi_devices SET deleted=? WHERE connection_id=?',(now,row['id']))
    result=facts(store)
    assert len(result['links'])==2 and result['links'][0]['state']=='UNKNOWN' and not result['links'][0]['fresh']
    assert result['links'][1]['switch']=='Other switch'
    assert 'secret' not in json.dumps(result)


def test_vm_inherits_physical_host_without_asserting_network_is_healthy(environment):
    _,store,vault=environment;setup(store);row,snapshot=seed(store,vault)
    from test_proxmox import setup as proxmox_setup,inventory
    from aiticket.proxmox import Client,discover,link
    proxmox_setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):discover(store,vault,'p1')
    node=store.rows("SELECT id FROM proxmox_objects WHERE kind='node'")[0]['id'];guest=store.rows("SELECT id FROM proxmox_objects WHERE kind='qemu'")[0]['id']
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('guest','Guest',?)",(time.time(),))
    link(store,node,'shell-host','online');link(store,guest,'guest','running')
    topology.save(store,'shell-host','eno1',json.dumps([row['id'],'sw1',8]))
    result=facts(store,'guest')
    assert result['machine_type']=='vm' and result['hosted_on']['machine_id']=='shell-host'
    assert result['physical_host']['links'][0]['port']==8
    assert 'may still' in result['note'] and result['related_guests']==[]
    with store.connect() as c:c.execute('UPDATE agents SET revoked=1')
    assert not facts(store,'guest')['physical_host']['fresh']


def test_heartbeat_validation_retention_and_backward_compatibility(environment):
    app,store,_=environment;setup(store);client=app.test_client();auth={'Authorization':'Bearer fixture-agent-credential'}
    payload={'event_id':uid(),'network':network(),'sampled_at':time.time()}
    assert client.post('/api/agent/heartbeat',json=payload,headers=auth).status_code==200
    assert facts(store)['interfaces'][0]['addresses']==['10.0.0.2']
    assert client.post('/api/agent/heartbeat',json=payload,headers=auth).json['status']=='duplicate'
    assert len(store.rows('SELECT * FROM network_samples'))==1
    for bad in ({'interfaces':'oops'}, {'neighbors':[{}]}, {'interfaces':[dict(network()['interfaces'][0],addresses=['not-an-IP'])]}, {'interfaces':[dict(network()['interfaces'][0],command='reboot')]}):
        assert client.post('/api/agent/heartbeat',json={'event_id':uid(),'network':bad},headers=auth).status_code==400
    # Legacy agents still report successfully, without falsely fresh old interface data.
    assert client.post('/api/agent/heartbeat',json={'event_id':uid()},headers=auth).status_code==200
    assert facts(store)['interfaces']==[]


def test_settings_routes_and_tags_preserve_scope(signed_in):
    client,store,vault,csrf=signed_in;setup(store);row,_=seed(store,vault)
    route='/hosts/shell-host/network-links';payload={'interface':'eno1','port':json.dumps([row['id'],'sw1',8])}
    assert client.post(route,data=payload).status_code==403
    assert client.post(route,data={**payload,'csrf':csrf}).status_code==302
    assert b'Switch \xc2\xb7 Port 8' in client.get('/hosts/shell-host').data
    assert b'Physical machine' in client.get('/hosts/shell-host').data
    assert b'Confirm connection' in client.get('/hosts/shell-host/settings').data
    identifier=store.rows('SELECT id FROM network_links')[0]['id']
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('another','Another',?)",(time.time(),))
    assert client.post('/hosts/another/network-links',data={'csrf':csrf,'operation':'remove','id':identifier}).status_code==302
    assert store.rows('SELECT * FROM network_links')
    assert client.post(route,data={'csrf':csrf,'operation':'remove','id':identifier}).status_code==302
    assert not store.rows('SELECT * FROM network_links')


def test_ai_context_and_read_only_refresh_are_ticket_bound(environment):
    app,store,vault=environment;incident=configure(store,vault,command_tools=True)
    # configure creates machine m without agent. A target network relationship remains usable offline.
    row,_=seed(store,vault,'m');topology.save(store,'m','eno1',json.dumps([row['id'],'sw1',8]))
    job=ai.request_job(store,vault,incident)
    rowjob=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    assert json.loads(rowjob['evidence'])['network_topology']['links'][0]['confidence']=='confirmed'
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    auth={'Authorization':'Bearer '+vault.decrypt(rowjob['credential'])}
    with patch('aiticket.unifi.refresh',return_value={}) as refresh:
        response=app.test_client().post('/api/hermes/'+job+'/command',json={'action':'network','machine_id':'not-the-ticket'},headers=auth)
        assert response.status_code==200 and response.json['network_topology']['links'][0]['port']==8
        assert refresh.call_args.args[2]==row['id']
    assert not store.rows('SELECT * FROM command_jobs') and not store.rows('SELECT * FROM proxmox_api_jobs')
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='cancelled' WHERE id=?",(job,))
    assert app.test_client().post('/api/hermes/'+job+'/command',json={'action':'network'},headers=auth).status_code==403
    assert len(json.dumps(topology.bounded(facts(store,'m'),500)))<1200


def test_agent_inventory_partial_collection_and_lldp(tmp_path):
    from agent import network as collector
    root=tmp_path/'net';root.mkdir();iface=root/'eno1';iface.mkdir()
    (iface/'device').mkdir();(iface/'address').write_text('aa:bb:cc:dd:ee:ff');(iface/'carrier').write_text('1');(iface/'operstate').write_text('up')
    lldp={'lldp':{'interface':{'eno1':{'chassis':{'Switch':{'id':{'type':'mac','value':'11:22:33:44:55:66'}}},'port':{'id':{'type':'ifname','value':'Ethernet8'}}}}}}
    def command(args):
        if args[0]=='ip':return json.dumps([{'ifname':'eno1','addr_info':[{'local':'10.0.0.2'}]}])
        if args[0]=='lldpcli':return json.dumps(lldp)
        return None
    with patch.object(collector,'command',side_effect=command):result=collector.inventory(root)
    assert topology.validate(result)==result and result['interfaces'][0]['addresses']==['10.0.0.2']
    assert result['neighbors'][0]['port_id']=='Ethernet8'
    with patch.object(collector,'command',return_value=None):assert collector.inventory(root)['interfaces']
    assert unifi.clean({'uplinkDeviceId':'switch','uplinkPortIndex':8,'password':'no'})=={'uplinkDeviceId':'switch','uplinkPortIndex':8}


def test_proxmox_interface_fallback_does_not_claim_physical_link_state(environment):
    _,store,vault=environment;setup(store)
    from test_proxmox import setup as proxmox_setup,inventory
    from aiticket.proxmox import Client,discover,link
    proxmox_setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):discover(store,vault,'p1')
    node=store.rows("SELECT id FROM proxmox_objects WHERE kind='node'")[0]['id'];link(store,node,'shell-host','online')
    rows=[{'iface':'eno1','type':'eth','active':1,'password':'secret'},{'iface':'vmbr0','type':'bridge','bridge_ports':'eno1','cidr':'10.0.0.1/24','active':1}]
    with patch.object(Client,'get',return_value=rows) as read:
        assert topology.refresh_proxmox(store,vault,'shell-host')=={}
        assert read.call_args.args[0].endswith('/network')
    result=facts(store)
    assert result['interfaces'][0]['master']=='vmbr0'
    assert result['interfaces'][0]['carrier'] is None and 'configuration' in result['interface_source']
    assert result['interfaces'][1]['addresses']==['10.0.0.1'] and 'secret' not in json.dumps(result)
    with patch.object(Client,'get',side_effect=TimeoutError('secret')):
        assert topology.refresh_proxmox(store,vault,'shell-host')
    assert facts(store)['interfaces'] # Failure retains last known data, without a fresh timestamp.


def test_optional_client_detail_enrichment_does_not_create_false_outage(environment):
    _,store,vault=environment;row=configured(store,vault,'network')
    with store.connect() as c:c.execute("UPDATE unifi_connections SET site='site1'")
    def read(self,path,params=None):
        if path.endswith('/sites'):return {'data':[{'id':'site1'}]}
        if path.endswith('/devices'):return {'data':[]}
        if path.endswith('/networks'):return {'data':[]}
        if path.endswith('/clients'):return {'data':[{'id':'client1','macAddress':'aa:bb:cc:dd:ee:ff'}]}
        return {'uplinkDeviceId':'switch1','uplinkPortIndex':8}
    with patch.object(unifi.Client,'get',read):
        snapshot=unifi.refresh(store,vault,row['id'])
        assert snapshot['readings']['clients']['items'][0]['uplinkPortIndex']==8
    def missing(self,path,params=None):
        if path.endswith('/clients/client1'):raise ValueError('HTTP 404')
        return read(self,path,params)
    with patch.object(unifi.Client,'get',missing):
        healthy,evidence=unifi.probe(store,vault,{'connection_id':row['id']})
        assert healthy and evidence['optional_telemetry_errors']['client:client1']=='HTTP 404'
