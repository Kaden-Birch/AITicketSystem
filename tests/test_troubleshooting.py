import json
import time
from datetime import datetime, timezone
import pytest
from aiticket import network_logs as logs, troubleshooting, network_observations as views, unifi
from aiticket.log_receiver import Collector

MAC='aa:bb:cc:dd:ee:01'
AP='aa:bb:cc:dd:ee:02'
OLD='aa:bb:cc:dd:ee:03'


@pytest.fixture(autouse=True)
def local_logs(monkeypatch): monkeypatch.delenv('AITICKET_LOG_DATA',raising=False)


def host(store,identifier='m'):
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(identifier,identifier,time.time()))
        c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES(?,?,?,?,?,?)',('check-'+identifier,identifier,'Reachability','tcp','{}',60))
        c.execute('INSERT INTO network_inventory VALUES(?,?,?)',(identifier,time.time(),json.dumps({'interfaces':[{'name':'eth0','mac':MAC if identifier=='m' else OLD}]})))


def feed(store,connection=None, events=None):
    source=logs.save_source(store,{'name':'Console','sender_ip':'192.0.2.1','connection_id':connection,'enabled':'yes'})
    collector=Collector(store)
    for text,at in events or []:
        stamp=datetime.fromtimestamp(at,timezone.utc).isoformat()
        collector.receive(('<134>1 '+stamp+' console - - - '+text).encode(),'192.0.2.1',at)
    collector.flush()
    return source,collector


def cef(name='WiFi Client Disconnected',device=AP,client=MAC,extra=''):
    return f'CEF:0|Ubiquiti|UniFi|10|401|{name}|5|UNIFIclientMac={client} UNIFIclientIp=192.0.2.20 UNIFIconnectedToDeviceMac={device} UNIFIconnectedToDevicePort=3 msg=Network event {extra}'


def connection(store,vault):
    return unifi.save(store,vault,{'name':'Home','kind':'network','url':'https://192.0.2.1','secret':'fixture'})


def test_timeline_merges_sources_transitions_resource_deltas_and_redacts(environment):
    _,store,_=environment;host(store);host(store,'unrelated');now=time.time()
    _,collector=feed(store,events=[(cef(extra='UNIFIwifiAirtimeUtilization=14'),now-90)])
    with store.connect() as c:
        for identifier,at,health in [('baseline',now-400,'healthy'),('bad1',now-100,'down'),('bad2',now-95,'down'),('good',now-50,'healthy')]:
            c.execute('INSERT INTO observations VALUES(?,?,?,?,?)',(identifier,'check-m',at,health,json.dumps({'reason':'Sample result','password':'never-show'})))
        for at,cpu in [(now-150,10),(now-120,14),(now-80,35),(now-40,39)]:
            c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('m','agent',at,json.dumps({'cpu_percent':cpu,'ram_percent':40})))
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('unrelated','agent',now-30,json.dumps({'cpu_percent':99})))
        c.execute('INSERT INTO change_events VALUES(?,?,?,?,?,?,?)',('change','m','Container','image','Image changed',json.dumps({'before':'old','after':'new','token':'secret'}),now-70))
        c.execute('INSERT INTO incidents(id,machine_id,check_id,severity,status,first_seen,last_seen,report,closed) VALUES(?,?,?,?,?,?,?,?,?)',('ticket','m','check-m','medium','Resolved',now-105,now-50,json.dumps({'check':'Example','observed':'healthy'}),now-45))
        result=troubleshooting.build(c,['m'],now-300,now)
        assert [x['at'] for x in result['items']]==sorted([x['at'] for x in result['items']],reverse=True)
        assert set(result['counts'])=={'checks','network','resources','changes','tickets','actions'}
        assert result['counts']['actions']==0
        checks=[x for x in result['items'] if x['kind']=='checks']
        assert len(checks)==2 and checks[0]['title'].endswith('Monitoring recovered')
        cpu=[x for x in result['items'] if x['kind']=='resources' and x['details']['metric']=='cpu_percent']
        assert len(cpu)==2 and cpu[0]['summary']=='10% → 35%'
        assert 'never-show' not in json.dumps(result) and 'secret' not in json.dumps(result)
        assert all(item['machine_id']=='m' for item in result['items'])
        assert troubleshooting.build(c,['m'],now-300,now,'network')['counts']['checks']==0
    assert collector.archive.backlog()['pending']==0
    assert not store.rows('SELECT 1 FROM ai_jobs')


def test_missing_network_history_keeps_other_evidence_and_resource_gaps(environment):
    _,store,_=environment;host(store);now=time.time()
    with store.connect() as c:
        for at,cpu in [(now-600,10),(now-10,85)]:c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('m','agent',at,json.dumps({'cpu_percent':cpu})))
        result=troubleshooting.build(c,['m'],now-900,now)
        assert not result['network_available'] and len(result['items'])==2
        assert result['items'][0]['details']['gap_before'] and result['items'][0]['summary']=='85%'
        assert result['items'][0]['details']['previous_displayed_value'] is None


def test_timeline_ui_filters_escape_dates_auth_and_readonly_ai(signed_in):
    client,store,_,_=signed_in;host(store);now=time.time()
    _,collector=feed(store,events=[(cef(name='<script>bad()</script>'),now-5)])
    response=client.get('/hosts/m/troubleshooting')
    assert response.status_code==200 and b'&lt;script&gt;bad()&lt;/script&gt;' in response.data
    assert b'<script>bad()</script>' not in response.data
    assert b'Observed sequence' in response.data
    assert client.get('/hosts/m/troubleshooting?kind=invalid').status_code==200
    assert b'supported evidence type' in client.get('/hosts/m/troubleshooting?kind=invalid').data
    assert b'Choose valid dates' in client.get('/hosts/m/troubleshooting?start=bad').data or b'Invalid isoformat' in client.get('/hosts/m/troubleshooting?start=bad').data
    assert client.get('/hosts/missing/troubleshooting').status_code==404
    with store.connect() as c:
        from aiticket.evidence import page
        output=page(c,'m','troubleshooting',limit=5)
        assert output['items'] and 'untrusted' in output['note']
    assert not store.rows('SELECT 1 FROM command_jobs') and not store.rows('SELECT 1 FROM ai_jobs')
    with client.session_transaction() as session:session.clear()
    assert client.get('/hosts/m/troubleshooting').status_code==302


def test_timeline_scope_uses_explicit_parent_and_confirmed_links_only(environment,monkeypatch):
    _,store,vault=environment;host(store);host(store,'parent');host(store,'switch');host(store,'candidate')
    identifier=connection(store,vault)
    with store.connect() as c:
        c.execute("UPDATE machines SET parent_id='parent' WHERE id='m'")
        for device,machine in [('sw','switch'),('maybe','candidate')]:
            c.execute('INSERT INTO unifi_devices(connection_id,device_id,machine_id,check_id,data,last_seen) VALUES(?,?,?,?,?,?)',(identifier,device,machine,'fixture','{}',time.time()))
    def context(c,machine):
        return {'links':[{'connection_id':identifier,'device_id':'sw','confidence':'confirmed'},{'connection_id':identifier,'device_id':'maybe','confidence':'candidate'}]} if machine=='m' else {}
    monkeypatch.setattr('aiticket.topology.context',context)
    with store.connect() as c:
        assert set(troubleshooting.scope(c,'m'))=={'m','parent','switch'}


def test_port_observations_scope_current_vs_history_and_stale_api(environment):
    _,store,vault=environment;host(store);now=time.time();identifier=connection(store,vault)
    source,collector=feed(store,identifier,[(cef(extra='UNIFIwifiAirtimeUtilization=14 UNIFIwifiInterference=9 UNIFIWiFiRssi=-77'),now-100)])
    second=connection(store,vault)
    other=logs.save_source(store,{'name':'Other console','sender_ip':'192.0.2.2','connection_id':second,'enabled':'yes'})
    event=logs.parse(cef(),now-20);event.update(source_id=other,associations=[]);collector.archive.append([event])
    ports=[{'number':3}]
    snapshot={'sampled_at':now-5,'readings':{'clients':{'items':[{'id':'client','macAddress':MAC,'ipAddress':'192.0.2.20','uplink':{'deviceId':'switch','portIndex':3},'type':'WIRED'}]}}}
    result=views.build(store,identifier,'switch',{'macAddress':AP},snapshot,ports,now=now)
    assert result['counts']['disconnect']==1 and len(result['samples'])==1
    assert result['current_clients'][0]['host_url']=='/hosts/m' and result['api_fresh']
    assert ports[0]['observations']['disconnects']==1 and len(ports[0]['observations']['clients'])==1
    assert result['samples'][0]['airtime']==14 and result['samples'][0]['rssi']==-77
    snapshot['sampled_at']=now-1000
    stale=views.build(store,identifier,'switch',{'macAddress':AP},snapshot,ports,now=now)
    assert not stale['api_fresh'] and not stale['current_clients'][0]['fresh']
    assert not store.rows('SELECT 1 FROM incidents')


def test_roam_measurements_belong_to_correct_ap_and_invalid_values_are_absent(environment):
    _,store,vault=environment;host(store);now=time.time();identifier=connection(store,vault)
    text=cef('WiFi Client Roamed',extra=f'UNIFIlastConnectedToDeviceMac={OLD} UNIFIlastConnectedToDevicePort=5 UNIFIWiFiRssi=-45 UNIFIlastConnectedToWiFiRssi=-82 UNIFIwifiAirtimeUtilization=22 UNIFIwifiInterference=NaN')
    feed(store,identifier,[(text,now-60)])
    current=views.build(store,identifier,'ap-new',{'macAddress':AP},{},[{'number':3}],now=now)
    previous=views.build(store,identifier,'ap-old',{'macAddress':OLD},{},[{'number':5}],now=now)
    assert current['counts']['roam']==previous['counts']['roam']==1
    assert current['samples'][0]['rssi']==-45 and current['samples'][0]['airtime']==22
    assert previous['samples'][0]['rssi']==-82 and previous['samples'][0]['airtime'] is None
    assert current['samples'][0]['interference'] is None
    assert current['events'][0]['ports']==[3] and previous['events'][0]['ports']==[5]


def test_network_device_route_renders_port_details_and_event_graphs(signed_in):
    client,store,vault,_=signed_in;host(store);now=time.time();identifier=connection(store,vault)
    feed(store,identifier,[(cef(extra='UNIFIWiFiRssi=-55 UNIFIwifiAirtimeUtilization=0'),now-10)])
    device={'name':'Lobby AP','macAddress':AP,'state':'ONLINE','interfaces':{'ports':[{'idx':3,'state':'UP','speedMbps':1000}],'radios':[{'frequencyGHz':5,'channel':36}]}}
    snapshot={'sampled_at':now,'readings':{'clients':{'items':[]}},'errors':{}}
    with store.connect() as c:
        c.execute('UPDATE unifi_connections SET snapshot=? WHERE id=?',(json.dumps(snapshot),identifier))
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',('ap','Lobby AP',now))
        c.execute('INSERT INTO unifi_devices(connection_id,device_id,machine_id,check_id,data,last_seen) VALUES(?,?,?,?,?,?)',(identifier,'ap','ap','fixture',json.dumps({'device':device}),now))
    response=client.get('/network-devices/'+identifier+'/devices/ap')
    assert response.status_code==200 and b'Wi-Fi observations' in response.data
    assert b'data-wireless-chart="airtime"' in response.data and b'"airtime": 0.0' in response.data
    assert b'id="unet-insights"' in response.data and b'Troubleshooting timeline' in response.data
    assert b'"disconnects": 1' in response.data


def test_ticket_scope_and_tool_payload_stay_bounded(signed_in,monkeypatch):
    client,store,_,_=signed_in;host(store);host(store,'related');now=time.time()
    with store.connect() as c:
        for ticket,machine in [('primary','m'),('member','related')]:
            c.execute('INSERT INTO incidents(id,machine_id,check_id,severity,status,first_seen,last_seen,report) VALUES(?,?,?,?,?,?,?,?)',(ticket,machine,'check-'+machine,'medium','Open',now-60,now-5,json.dumps({'check':'Preview','observed':'down','evidence':{}})))
        c.execute('INSERT INTO ticket_groups VALUES(?,?,?,?,?)',('primary','member','Shared investigation',0,now))
        assert set(troubleshooting.scope(c,incident='primary'))=={'m','related'}
    response=client.get('/incidents/primary/troubleshooting')
    assert response.status_code==200 and b'/hosts/related' in response.data
    assert b'Troubleshooting timeline' in client.get('/incidents/primary').data
    assert client.get('/incidents/missing/troubleshooting').status_code==404
    def oversized(*args,**kwargs):
        return {'items':[{'id':str(i),'details':{str(k):'x'*1000 for k in range(30)}} for i in range(10)],'partial':[],'truncated':False,'network_available':True}
    monkeypatch.setattr(troubleshooting,'build',oversized)
    with store.connect() as c:
        from aiticket.evidence import page
        output=page(c,'m','troubleshooting',limit=50)
        assert len(json.dumps(output['items']))<=50000 and all(item['truncated'] for item in output['items'])
    assert not store.rows('SELECT 1 FROM command_jobs')


def test_quiet_api_manual_binding_is_scoped_and_malformed_clients_are_unavailable(environment):
    _,store,vault=environment;host(store);host(store,'manual');now=time.time();identifier=connection(store,vault);second=connection(store,vault)
    source=logs.save_source(store,{'name':'Home','sender_ip':'192.0.2.1','connection_id':identifier,'enabled':'yes'})
    other=logs.save_source(store,{'name':'Other','sender_ip':'192.0.2.2','connection_id':second,'enabled':'yes'})
    with store.connect() as c:
        c.execute('INSERT INTO log_host_bindings VALUES(?,?,?,?)',(source,MAC,'manual',now))
        c.execute('INSERT INTO log_host_bindings VALUES(?,?,?,?)',(other,MAC,'m',now))
    snapshot={'sampled_at':now,'readings':{'clients':{'items':[{'id':'client','macAddress':MAC,'uplinkDeviceId':'ap'}]}}}
    result=views.build(store,identifier,'ap',{'macAddress':AP},snapshot,[],now=now)
    assert result['current_clients'][0]['host_url']=='/hosts/manual' and not result['events']
    snapshot['readings']['clients']='unavailable'
    assert not views.build(store,identifier,'ap',{'macAddress':AP},snapshot,[],now=now)['api_available']
