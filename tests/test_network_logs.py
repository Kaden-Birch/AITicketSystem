import json
import time
import pytest
from aiticket import network_logs as logs
from aiticket.log_receiver import Collector, Framer

NOW = time.time()
CLIENT = 'aa:bb:cc:dd:ee:01'
DEVICE = 'aa:bb:cc:dd:ee:02'
CEF = ('<134>1 '+__import__('datetime').datetime.fromtimestamp(NOW,__import__('datetime').timezone.utc).isoformat()+' console - - - CEF:0|Ubiquiti|UniFi Network|9.3|401|WiFi Client Disconnected|5|'
       'UNIFIcategory=Monitoring UNIFIclientMac='+CLIENT+' UNIFIclientIp=10.0.0.2 UNIFIlastConnectedToDeviceName=Lobby AP UNIFIlastConnectedToDeviceMac='+DEVICE+' UNIFIlastConnectedToDevicePort=3 UNIFIwifiAirtimeUtilization=14 UNIFIlastConnectedToWiFiRssi=-77 msg=Lost connection')


@pytest.fixture(autouse=True)
def fresh_sample(monkeypatch):
    global NOW, CEF
    monkeypatch.delenv('AITICKET_LOG_DATA',raising=False)
    NOW=time.time()
    CEF=__import__('re').sub(r'<134>1 \S+', '<134>1 '+__import__('datetime').datetime.fromtimestamp(NOW,__import__('datetime').timezone.utc).isoformat(), CEF, count=1)


def source(store):
    return logs.save_source(store, {'name':'Home console','sender_ip':'10.0.0.1','enabled':'yes'})


def hosts(store):
    with store.connect() as c:
        for identifier in ('client','other','console','ap'):
            c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(identifier,identifier,NOW))
        c.execute('INSERT INTO network_inventory VALUES(?,?,?)',('client',NOW,json.dumps({'interfaces':[{'name':'eth0','mac':CLIENT,'addresses':['10.0.0.2']}]})))


def collect(store, count=1):
    identifier=source(store)
    collector=Collector(store)
    for i in range(count): collector.receive(CEF.encode(), '10.0.0.1', NOW+i/100)
    collector.flush(NOW+1)
    return identifier,collector


def test_cef_escaping_timestamp_redaction_and_generic_fallback():
    event=logs.parse(CEF,NOW)
    assert event['device_name']=='Lobby AP' and event['port']=='3'
    assert event['fields']['UNIFIwifiAirtimeUtilization']=='14'
    assert event['client_mac']==CLIENT and event['severity']==5 and event['timestamp_kind']=='reported'
    text=r'CEF:0|Ubiquiti|UniFi|9|id|Name \| escaped|8|msg=values a\=b\nnext token=two words password=super secret src=10.0.0.2'
    event=logs.parse(text,NOW)
    assert event['name']=='Name | escaped'
    assert event['message']=='values a=b\nnext'
    assert event['fields']['token']=='[REDACTED]'
    assert 'two words' not in event['raw'] and 'super secret' not in event['raw']
    assert logs.parse('<131>old syslog text',NOW)['severity']==7
    assert logs.parse('CEF:broken',NOW)['format']=='unparsed CEF'
    assert logs.parse('<134>Oct 5 02:01:02 console msg',NOW)['at']==NOW
    iso=__import__('datetime').datetime.fromtimestamp(NOW-600,__import__('datetime').timezone.utc).isoformat()
    delayed=logs.parse('CEF:0|Ubiquiti|UniFi|9|1|Delayed|2|UNIFIutcTime='+iso+' msg=Test',NOW)
    assert delayed['at']==pytest.approx(NOW-600) and delayed['timestamp_kind']=='reported'
    with pytest.raises(ValueError):logs.parse(b'x'*16385,NOW)


def test_tcp_framing_split_combined_and_limits():
    frame=Framer()
    message=CEF.encode()
    octets=str(len(message)).encode()+b' '+message
    assert frame.feed(octets[:8])==[]
    assert frame.feed(octets[8:]+b'second\nthird\r\n')==[message,b'second',b'third']
    assert frame.feed(b'part')==[] and frame.feed(b'ial\n')==[b'partial']
    with pytest.raises(ValueError):Framer().feed(b'999999 '+message)
    with pytest.raises(ValueError):Framer().feed(b'x'*16385+b'\n')


def test_allowlist_rate_size_readonly_archive_and_no_actions(environment):
    _,store,_=environment
    hosts(store)
    identifier=source(store);collector=Collector(store)
    collector.receive(CEF.encode(),'10.0.0.99',NOW)
    collector.receive(b'x'*16385,'10.0.0.1',NOW)
    for _ in range(205):collector.receive(CEF.encode(),'10.0.0.1',NOW)
    collector.flush(NOW)
    assert collector.stats['dropped']>=6 and collector.stats['oversize']==1
    with store.connect() as c:
        result=logs.query(c,machine='client',start=NOW-1,end=NOW+1,limit=1)
        assert result['available'] and result['next_offset']==1 and result['items'][0]['client_ip']=='10.0.0.2'
        assert not c.execute('SELECT 1 FROM incidents').fetchone()
        assert not c.execute('SELECT 1 FROM ai_jobs').fetchone()
    with logs.reader(store) as c:
        with pytest.raises(__import__('sqlite3').OperationalError):c.execute('DELETE FROM events')
    assert logs.status(store)['available']
    with store.connect() as c:c.execute('UPDATE log_sources SET enabled=0 WHERE id=?',(identifier,))
    collector.refresh();before=len(collector.pending);collector.receive(CEF.encode(),'10.0.0.1')
    assert len(collector.pending)==before


def test_mac_ambiguity_ip_time_and_manual_override_history(environment):
    _,store,_=environment;hosts(store)
    identifier,collector=collect(store)
    with store.connect() as c:
        assert logs.query(c,machine='client',start=NOW-10)['items']
    logs.bind(store,identifier,CLIENT,'other')
    with store.connect() as c:
        assert not logs.query(c,machine='client',start=NOW-10)['items']
        assert logs.query(c,machine='other',start=NOW-10)['items'][0]['associations'][0]['method']=='Administrator MAC association'
    logs.bind(store,identifier,CLIENT,None)
    with store.connect() as c:
        assert logs.query(c,machine='client',start=NOW-10)['items']
        c.execute('INSERT INTO network_inventory VALUES(?,?,?)',('other',NOW,json.dumps({'interfaces':[{'mac':CLIENT,'addresses':['10.0.0.2']}]})))
    collector.refresh();event=logs.parse(CEF,NOW);assert not collector.match(event,collector.sources['10.0.0.1'])
    event['client_mac']=None;assert not collector.match(event,collector.sources['10.0.0.1'])
    with store.connect() as c:c.execute("DELETE FROM network_inventory WHERE machine_id='other'")
    collector.refresh();assert collector.match(event,collector.sources['10.0.0.1'])[0]['machine_id']=='client'
    event['timestamp_kind']='received';assert not collector.match(event,collector.sources['10.0.0.1'])
    event['timestamp_kind']='reported';event['at']-=600;assert not collector.match(event,collector.sources['10.0.0.1'])
    event['at']=NOW;collector.interfaces=[('client',NOW-1000,{'addresses':['10.0.0.2']})]
    assert not collector.match(event,collector.sources['10.0.0.1'])


def test_archive_retention_pagination_and_unavailable(environment):
    _,store,_=environment;hosts(store)
    with store.connect() as c:assert logs.query(c,machine='client')['available'] is False
    identifier,collector=collect(store,5)
    with store.connect() as c:
        assert len(logs.query(c,start=NOW-10,limit=2)['items'])==2
        assert logs.query(c,start=NOW-10,offset=2,limit=2)['next_offset']==4
        assert not logs.query(c,start=NOW-10,severity=7)['items']
        assert logs.query(c,start=NOW-10,text='Lost')['items']
    delayed=logs.parse(CEF.replace('Lost connection','Delayed evidence'),NOW+2)
    delayed.update(at=NOW-3600,source_id=identifier,associations=[])
    collector.archive.append([delayed])
    with store.connect() as c:
        old=logs.query(c,start=NOW-3700,end=NOW-3500)['items']
        assert len(old)==1 and logs.event(c,old[0]['id'])['message']=='Delayed evidence'
    collector.archive.retain({'days':7,'megabytes':10,'rows':2},NOW+1)
    assert logs.status(store)['events']==2
    collector.archive.retain({'days':1,'megabytes':10,'rows':2},NOW+2*86400)
    assert logs.status(store)['events']==0


def test_authenticated_ui_errors_preserve_values_and_event_escape(signed_in):
    client,store,_,csrf=signed_in;hosts(store)
    assert client.get('/settings/network-logs').status_code==200
    response=client.post('/settings/network-logs',data={'csrf':csrf,'name':'Preserve me','sender_ip':'invalid'})
    assert response.status_code==200 and b'Preserve me' in response.data and b'exact IP' in response.data and b'id="network-log-editor" data-live-preserve' in response.data
    assert client.post('/settings/network-logs',data={'name':'Bad'}).status_code==403
    identifier,collector=collect(store,28)
    collector.receive(CEF.replace('Lost connection','<script>alert(1)</script>').encode(),'10.0.0.1',NOW+2)
    collector.flush(NOW+3)
    response=client.get('/network-events')
    assert response.status_code==200 and b'Older events' in response.data
    assert b'&lt;script&gt;' in response.data and b'<script>alert(1)</script>' not in response.data
    assert client.get('/network-events?offset=25').status_code==200
    with store.connect() as c:event=logs.query(c,limit=1)['items'][0]
    assert client.get('/network-events/'+str(event['id'])).status_code==200
    assert client.post('/network-events/'+str(event['id']),data={'csrf':csrf,'machine_id':'other'}).status_code==302
    assert b'WiFi Client Disconnected' in client.get('/network-events?machine=other').data
    client.get('/logout')
    with client.session_transaction() as s:s.clear()
    assert client.get('/network-events').status_code==302


def test_evidence_bounded_and_maintenance_is_context_only(environment):
    _,store,_=environment;hosts(store);identifier,collector=collect(store,20)
    from aiticket.policies import add_window
    from aiticket.evidence import page
    add_window(store,'Work','client','once','UTC',{'start':__import__('datetime').datetime.fromtimestamp(NOW-60,__import__('datetime').timezone.utc).replace(tzinfo=None).isoformat(),'end':__import__('datetime').datetime.fromtimestamp(NOW+60,__import__('datetime').timezone.utc).replace(tzinfo=None).isoformat()})
    with store.connect() as c:
        result=page(c,'client','network_logs',limit=3,now=NOW+1)
        assert len(result['items'])==3 and result['next_offset']==3
        assert result['items'][0]['maintenance'] is True and 'raw' not in result['items'][0]
        assert len(json.dumps(result))<50000
        assert 'Untrusted' in logs.evidence(c,['client'],NOW)['note']
        assert not c.execute('SELECT 1 FROM ai_jobs').fetchone()


def test_source_validation_disabled_and_unique(environment):
    _,store,_=environment
    identifier=source(store)
    with pytest.raises(ValueError):source(store)
    with pytest.raises(ValueError):logs.save_source(store,{'name':'bad','sender_ip':'localhost'})
    with pytest.raises(ValueError):logs.save_source(store,{'name':'bad','sender_ip':'10.0.0.3','connection_id':'missing'})
    logs.save_source(store,{'id':identifier,'name':'disabled','sender_ip':'10.0.0.1'})
    assert not Collector(store).sources


def test_infrastructure_matches_stay_within_source_connection(environment):
    _,store,vault=environment;hosts(store)
    from aiticket import unifi
    first=unifi.save(store,vault,{'name':'Home','url':'https://10.0.0.1','kind':'network','secret':'fixture'})
    second=unifi.save(store,vault,{'name':'Other site','url':'https://10.0.1.1','kind':'network','secret':'fixture'})
    with store.connect() as c:
        for connection,machine in ((first,'ap'),(second,'other')):
            c.execute('INSERT INTO unifi_devices(connection_id,device_id,machine_id,check_id,data,last_seen) VALUES(?,?,?,?,?,?)',(connection,'same-mac',machine,'fixture',json.dumps({'device':{'macAddress':DEVICE}}),NOW))
    identifier=logs.save_source(store,{'name':'Home console','sender_ip':'10.0.0.1','connection_id':first,'enabled':'yes'})
    collector=Collector(store);collector.receive(CEF.encode(),'10.0.0.1',NOW);collector.flush(NOW)
    with store.connect() as c:
        assert logs.query(c,machine='ap',start=NOW-1)['items']
        assert not logs.query(c,machine='other',start=NOW-1)['items']
    logs.bind(store,identifier,CLIENT,'ap')
    with store.connect() as c:
        assert not logs.query(c,machine='client',start=NOW-1)['items']
        associations=logs.query(c,machine='ap',start=NOW-1)['items'][0]['associations']
        assert {'client','infrastructure','console'}=={a['role'] for a in associations}


def test_ai_logs_are_scoped_untrusted_and_manual_readable_in_maintenance(environment):
    app,store,vault=environment;hosts(store)
    from test_codex_mode import configure
    from test_evidence_groups_maintenance import window
    from aiticket import ai,commands
    incident=configure(store,vault,command_tools=True)
    commands.configure(store,'m',{'enabled':'yes','hermes':'yes','approval':'immediate'})
    identifier,collector=collect(store)
    logs.bind(store,identifier,CLIENT,'m')
    window(store,'m')
    assert ai.request_job(store,vault,incident,automatic=True) is None
    job=ai.request_job(store,vault,incident,read_only=True)
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    snapshot=json.loads(row['evidence'])
    assert snapshot['network_events']['on_demand'] and 'events' not in snapshot['network_events']
    assert 'tier local first' in snapshot['historical_archive']['note']
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    headers={'Authorization':'Bearer '+vault.decrypt(row['credential'])};client=app.test_client();path='/api/hermes/'+job+'/command'
    response=client.post(path,json={'action':'evidence','source':'network_logs'},headers=headers)
    assert response.status_code==200 and response.json['items']
    assert client.post(path,json={'action':'evidence','machine_id':'other','source':'network_logs'},headers=headers).status_code==403
    assert not store.rows('SELECT 1 FROM command_jobs')
    assert client.get('/hosts/m').status_code==302


def test_listener_bind_failure_does_not_publish_healthy_heartbeat(monkeypatch):
    from unittest.mock import Mock
    from aiticket import log_receiver
    collector=Mock();collector.flush.side_effect=AssertionError('A failed listener cannot publish a heartbeat')
    udp=Mock();udp.bind.side_effect=OSError('Address already in use');tcp=Mock()
    monkeypatch.setattr(log_receiver,'Collector',lambda _:collector)
    monkeypatch.setattr(log_receiver.socket,'socket',Mock(side_effect=[udp,tcp]))
    monkeypatch.setattr(log_receiver.selectors,'DefaultSelector',Mock(return_value=Mock()))
    monkeypatch.setattr(log_receiver.signal,'signal',Mock())
    with pytest.raises(OSError,match='Address already in use'):log_receiver.run(None)
    collector.flush.assert_not_called()
