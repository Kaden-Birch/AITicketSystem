"""Counter/reset semantics and retained evidence for the host's I/O graphs."""
import importlib.util
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
import pytest
from aiticket.db import uid
from aiticket.security import digest
from aiticket.metric_history import charts,record
from aiticket.host_overview import prepare
from aiticket.performance_events import build
from aiticket.changes import reboot,event

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def network():
    spec=importlib.util.spec_from_file_location('performance_network_fixture',ROOT/'agent/network.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def test_rates_leave_gaps_for_first_sample_counter_reset_device_change_and_restart(network):
    state={};net={'eth0':dict(rx_bytes=100,tx_bytes=200,rx_errors=2,tx_errors=0,rx_dropped=1,tx_dropped=0)}
    disk={'sda':dict(read_bytes=1000,write_bytes=2000,io_ops=10,io_ms=30,busy_ms=500)}
    assert 'disk_read_bytes_per_second' not in network.performance_rates(state,net,disk,10)
    net2={'eth0':{key:value+20 for key,value in net['eth0'].items()}}
    disk2={'sda':{key:value+100 for key,value in disk['sda'].items()}}
    rates=network.performance_rates(state,net2,disk2,20)
    assert rates['network_rx_bytes_per_second']==2 and rates['disk_read_bytes_per_second']==10
    assert rates['disk_latency_ms']==1 and rates['disk_busy_percent']==1
    assert rates['network_rx_errors_per_second']==2
    assert 'network_rx_bytes_per_second' not in network.performance_rates(state,net,disk2,30)
    assert 'network_rx_bytes_per_second' not in network.performance_rates(state,{**net,'eth1':net['eth0']},disk2,40)
    assert 'disk_read_bytes_per_second' not in network.performance_rates(state,net,disk2,2000)
    state['io_counters']['session']='old-process'
    assert 'disk_read_bytes_per_second' not in network.performance_rates(state,net,disk2,2010)


def test_linux_excludes_duplicate_interfaces_partitions_and_stacked_disks(network,tmp_path):
    net=tmp_path/'net';disks=tmp_path/'block';net.mkdir();disks.mkdir()
    for name in ('eth0','veth123','docker0','lo','slave0'):
        path=net/name;(path/'statistics').mkdir(parents=True)
        for key in network.COUNTERS:(path/'statistics'/key).write_text('1000')
    (net/'slave0'/'master').symlink_to(net/'eth0')
    for name in ('sda','dm-0','loop0'):
        path=disks/name;(path/'slaves').mkdir(parents=True)
        (path/'stat').write_text('10 0 100 40 20 0 200 60 0 500 500')
    (disks/'dm-0'/'slaves'/'sda').touch()
    state={};network.performance(state,net,disks,10)
    (net/'eth0'/'statistics'/'rx_bytes').write_text('2000')
    (disks/'sda'/'stat').write_text('20 0 200 80 30 0 300 120 0 1000 1000')
    result=network.performance(state,net,disks,20)
    assert result['network_interfaces_sampled']==1 and result['disk_devices_sampled']==1
    assert result['network_rx_bytes_per_second']==100
    assert result['disk_read_bytes_per_second']==5120
    assert result['disk_latency_ms']==5 and result['disk_busy_percent']==5
    assert network.performance({},tmp_path/'missing',tmp_path/'missing',30)=={}


def test_windows_raw_counter_mapping_is_bounded_and_preserves_latency(network,monkeypatch):
    fake=SimpleNamespace(**{name:lambda *args,**kwargs:None for name in ('literal','ps','ps_argv','query','run','policy','system_directory')})
    monkeypatch.setitem(sys.modules,'platform_support',fake);monkeypatch.setitem(sys.modules,'network',network)
    spec=importlib.util.spec_from_file_location('performance_windows_fixture',ROOT/'agent/windows/backend.py')
    backend=importlib.util.module_from_spec(spec);spec.loader.exec_module(backend)
    counters={'network':[{'id':'adapter','rx_bytes':1000,'tx_bytes':2000}], 'disks':[{'Name':'0 C:','DiskReadBytesPersec':3000,'DiskWriteBytesPersec':4000,'AvgDisksecPerTransfer':100,'AvgDisksecPerTransfer_Base':10,'Frequency_PerfTime':1000,'PercentIdleTime':500000,'Timestamp_Sys100NS':1000000}]}
    calls=[]
    monkeypatch.setattr(backend,'query',lambda script,**kwargs:calls.append(kwargs) or counters)
    real=network.performance_rates;now=iter((10,20))
    monkeypatch.setattr(network,'performance_rates',lambda state,net,disk:real(state,net,disk,next(now)))
    state={};backend.performance(state)
    row=counters['disks'][0];row.update(DiskReadBytesPersec=13000,AvgDisksecPerTransfer=150,AvgDisksecPerTransfer_Base=20,PercentIdleTime=90500000,Timestamp_Sys100NS=101000000)
    counters['network'][0]['rx_bytes']=11000
    rates=backend.performance(state)
    assert rates['network_rx_bytes_per_second']==1000 and rates['disk_read_bytes_per_second']==1000
    assert rates['disk_latency_ms']==5 and rates['disk_busy_percent']==10
    assert all(call=={'timeout':4,'limit':60000} for call in calls)


def enroll(store,machine,now):
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'I/O host',now))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,sampled_at) VALUES(?,?,?,?,?)',(uid(),machine,digest('performance-fixture'),now,now))


def test_heartbeat_retains_io_in_history_archive_and_ai_context(environment):
    app,store,_=environment;now=time.time();machine=uid();enroll(store,machine,now)
    store.save('telemetry_capture_enabled',True)
    payload={'event_id':uid(),'sampled_at':now,'telemetry':{'network_rx_bytes_per_second':2000000,'network_tx_bytes_per_second':1000000,'disk_read_bytes_per_second':3000000,'disk_write_bytes_per_second':4000000,'disk_latency_ms':2.5,'disk_busy_percent':20,'network_rx_errors':4},'network':{'interfaces':[{'name':'eth0','kind':'physical','state':'up','carrier':True,'speed_mbps':1000,'rx_errors':4,'tx_errors':0,'rx_dropped':0,'tx_dropped':0}],'neighbors':[]}}
    client=app.test_client();headers={'Authorization':'Bearer performance-fixture'}
    assert client.post('/api/agent/heartbeat',json=payload,headers=headers).status_code==200
    history=charts(store,{'id':machine,'agent':{'id':'a'}},'1h',now+1)
    data={'checks':[],'history':history};prepare(data)
    assert [trace['latest'] for trace in data['overview_charts'][2]['traces']]==[2,1]
    assert [trace['latest'] for trace in data['overview_charts'][3]['traces']]==[3,4]
    assert any(chart['key']=='disk_latency_ms' for chart in history['charts'])
    assert 'network_rx_bytes_per_second' in store.rows("SELECT payload FROM telemetry_records WHERE kind='agent'")[0]['payload']
    from aiticket.machine_context import context
    with store.connect() as c:assert context(c,machine)['telemetry']['metrics']['disk_latency_ms']==2.5
    bad={**payload,'event_id':uid(),'telemetry':{'disk_busy_percent':101}}
    assert client.post('/api/agent/heartbeat',json=bad,headers=headers).status_code==400
    bad={**payload,'event_id':uid(),'network':{'interfaces':[{**payload['network']['interfaces'][0],'rx_errors':-1}]}}
    assert client.post('/api/agent/heartbeat',json=bad,headers=headers).status_code==400


def test_missing_direction_is_a_gap_not_zero(environment):
    _,store,_=environment;now=time.time()
    with store.connect() as c:record(c,'m','agent',now-10,{'network_tx_bytes_per_second':1000000})
    data={'checks':[],'history':charts(store,{'id':'m','agent':{'id':'a'}},'1h',now)};prepare(data)
    chart=data['overview_charts'][2]
    assert [trace['label'] for trace in chart['traces']]==['Received','Sent']
    assert chart['traces'][0]['latest'] is None and all(s['value'] is None for s in chart['traces'][0]['samples'])
    assert chart['traces'][1]['latest']==1


def test_event_window_host_scope_boot_and_redacted_evidence(environment):
    _,store,_=environment;now=time.time();machine=uid();enroll(store,machine,now)
    other=uid()
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(other,'Other',now))
        event(c,machine,'Container','image','old','new',now-100)
        event(c,machine,'Container','restart_count',1,2,now-100)
        event(c,other,'Container','image','secret-other-host','new',now-100)
        event(c,machine,'Container','image','older','old',now-4000)
        reboot(c,machine,{'uptime_seconds':600},now-200,{'uptime_seconds':10},now-100,now-100)
        reboot(c,machine,{'uptime_seconds':10},now-100,{'uptime_seconds':20},now-90,now-90)
    markers=build(store,machine,{'start':now-3600,'end':now})
    assert len(markers['items'])==3 and len(markers['groups'])==1
    assert any('reboot' in item['title'] for item in markers['items'])
    assert 'secret-other-host' not in json.dumps(markers)
    assert all(item['at']==pytest.approx(now-100) for item in markers['items'])


def test_interface_changes_and_command_markers_use_observed_not_queued_time(environment):
    _,store,_=environment;now=time.time();machine=uid();enroll(store,machine,now)
    from aiticket.changes import network as network_changes
    initial={'interfaces':[{'name':'eth0','state':'up','carrier':True,'speed_mbps':1000}]}
    current={'interfaces':[{'name':'eth0','state':'down','carrier':False,'speed_mbps':1000}]}
    with store.connect() as c:
        c.execute('INSERT INTO network_inventory VALUES(?,?,?)',(machine,now-200,json.dumps(initial)))
        network_changes(c,machine,current,now-100)
        agent=c.execute('SELECT id FROM agents WHERE machine_id=?',(machine,)).fetchone()[0]
        c.execute('INSERT INTO command_jobs(id,machine_id,agent_id,command,fingerprint,policy_version,timeout,output_limit,state,created,expires,dispatched,completed) VALUES(?,?,?,?,?,1,10,1024,?,?,?,?,?)',('cmd',machine,agent,'password=must-not-appear','hash','completed',now-500,now+100,now-200,now-100))
    result=build(store,machine,{'start':now-3600,'end':now})
    assert len(result['items'])==4
    assert 'must-not-appear' not in json.dumps(result)
    actions=[row for row in result['items'] if row['kind']=='actions']
    assert sorted(row['at'] for row in actions)==[now-200,now-100]
    assert all('proof' in row['details']['note'] for row in actions)


def test_event_markers_are_bounded_and_render_evidence_safely(signed_in):
    client,store,_,_=signed_in;now=time.time();machine=uid();enroll(store,machine,now)
    with store.connect() as c:
        for i in range(205):event(c,machine,'<script>not-executable</script>','image',i,i+1,now-100-i)
        record(c,machine,'agent',now-10,{'network_rx_bytes_per_second':1000000,'network_tx_bytes_per_second':2000000,'disk_read_bytes_per_second':3000000,'disk_write_bytes_per_second':4000000})
    page=client.get('/hosts/'+machine+'?window=1h')
    assert page.status_code==200
    assert 'data-host-event=' in page.text and 'View events' in page.text
    assert '<script>not-executable</script>' not in page.text
    result=build(store,machine,{'start':now-3600,'end':now})
    assert len(result['items'])==100 and result['truncated']
    assert len(result['groups'])<=120
