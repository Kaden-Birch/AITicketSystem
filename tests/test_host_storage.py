import io
import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from aiticket import host_storage as storage,capacity_forecasts as capacity,telemetry_archive
from test_windows_support import enrolled
from test_log_archive import configure


def volume(identity='root',mount='/',total=100_000_000_000,free=20_000_000_000):
    return {'id':identity,'mount':mount,'filesystem':'ext4','total_bytes':total,'free_bytes':free}


def send(client,headers,volumes=None,at=None,event=None,telemetry=None):
    payload={'event_id':event or str(uuid.uuid4()),'sampled_at':at if at is not None else time.time(),'host_info':{'os':'Linux'},'telemetry':telemetry or {}}
    if volumes is not None:payload['filesystems']=volumes
    return client.post('/api/agent/heartbeat',headers=headers,json=payload)


def test_heartbeat_retains_and_archives_each_volume_atomically(environment):
    app,store,vault=environment;machine,agent,headers=enrolled(store);configure(store,vault)
    client=app.test_client();rows=[volume(),volume('data','/var/lib/docker',200_000_000_000,60_000_000_000)]
    event=str(uuid.uuid4())
    assert send(client,headers,rows,event=event).status_code==200
    samples=store.rows("SELECT * FROM capacity_samples WHERE machine_id=?",(machine,))
    assert len(samples)==2 and {r['label'] for r in samples}=={'/','/var/lib/docker'}
    assert all(r['kind']=='host_filesystem' for r in samples)
    raw=json.loads(store.rows('SELECT telemetry FROM agents WHERE id=?',(agent,))[0]['telemetry'])
    assert raw['filesystems']==rows
    archived=store.rows("SELECT payload FROM telemetry_records WHERE kind='agent' AND machine_id=?",(machine,))
    assert any(json.loads(r['payload'])['telemetry']['filesystems']==rows for r in archived)
    before=store.rows('SELECT * FROM capacity_samples')
    assert send(client,headers,rows,event=event).json['status']=='duplicate'
    assert store.rows('SELECT * FROM capacity_samples')==before


@pytest.mark.parametrize('values',[[volume(free=200_000_000_000)],[volume(total=0)],[volume(total=True)],[{**volume(),'extra':'no'}],[volume(),volume()],['no'],[volume(mount='bad\nname')],None])
def test_invalid_filesystems_cannot_create_history(environment,values):
    app,store,_=environment;_,_,headers=enrolled(store)
    payload={'event_id':str(uuid.uuid4()),'filesystems':values}
    response=app.test_client().post('/api/agent/heartbeat',headers=headers,json=payload)
    assert response.status_code==400
    assert not store.rows('SELECT * FROM capacity_samples')
    assert not store.rows('SELECT * FROM agent_events')


def test_backfill_reuses_only_same_agent_actual_system_disk_history(environment):
    app,store,vault=environment;machine,agent,headers=enrolled(store);configure(store,vault);now=time.time()
    for i in range(10):
        telemetry_archive.record(store,'agent',machine,machine,{'agent_id':agent,'host_info':{'os':'Linux'},'telemetry':{'disk_total_bytes':100e9,'disk_free_bytes':40e9-i*1e9}},at=now-(9-i)*86400)
    # Wrong enrollment and percentages alone must not seed a filesystem prediction.
    telemetry_archive.record(store,'agent',machine,machine,{'agent_id':'replaced','telemetry':{'disk_total_bytes':100e9,'disk_free_bytes':1e9}},at=now)
    telemetry_archive.record(store,'agent',machine,machine,{'agent_id':agent,'telemetry':{'disk_percent':75}},at=now-12*86400)
    storage.backfill(store)
    entity=storage.entity(machine,agent,{'id':'legacy-system'})
    result=capacity.forecast(store,entity,now+1)
    assert result['state']=='growing' and result['days']==10 and result['eta_days']==31
    assert len(store.rows('SELECT * FROM capacity_samples WHERE entity=?',(entity,)))==10
    assert send(app.test_client(),headers,telemetry={'disk_total_bytes':100e9,'disk_free_bytes':31e9}).status_code==200
    from aiticket.hostview import detail
    view=storage.build(store,detail(store,machine)['host'])
    assert view['legacy'] and view['volumes'][0]['forecast']['state']=='growing'


def test_host_page_multiple_mounts_stale_and_replacement(signed_in):
    client,store,vault,_=signed_in;machine,agent,headers=enrolled(store);now=time.time()
    rows=[volume(),volume('data','/srv/media <b>')]
    with store.connect() as c:
        for i in range(10):
            for row in rows:storage.retain(c,machine,agent,{'filesystems':[{**row,'free_bytes':29e9-i*1e9}]},{},now-(9-i)*86400)
    assert send(client,headers,rows,at=now).status_code==200
    page=client.get('/hosts/'+machine)
    assert page.status_code==200 and b'Filesystem capacity forecasts' in page.data
    assert b'/srv/media &lt;b&gt;' in page.data and b'/srv/media <b>' not in page.data
    assert page.data.count(b'Estimated limit in')==2
    assert send(client,headers,[volume('replacement')]).status_code==200
    page=client.get('/hosts/'+machine)
    assert b'Learning the capacity trend' in page.data and b'Estimated limit in' not in page.data
    assert b'/srv/media' not in page.data
    with store.connect() as c:c.execute('UPDATE agents SET last_seen=? WHERE id=?',(now-300,agent))
    page=client.get('/hosts/'+machine)
    assert b'Current capacity reading is stale' in page.data


def test_proxmox_allocation_does_not_become_guest_filesystem_forecast(signed_in):
    from test_hosts_power import guest
    client,store,vault,_=signed_in;machine,_=guest(store,vault)
    page=client.get('/hosts/'+machine)
    assert page.status_code==200 and b'Proxmox disk allocation is not guest free space' in page.data
    assert not store.rows("SELECT * FROM capacity_samples WHERE kind='host_filesystem'")


def test_linux_collection_deduplicates_bind_mounts_and_skips_remote_storage():
    from agent import agent as runtime
    content='''1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:1 / /bind rw - ext4 /dev/sda1 rw
3 1 8:2 / /srv/data\\040set rw - xfs /dev/sdb1 rw
4 1 0:1 / /smb rw - cifs //nas/share rw
5 1 0:2 / /tmp rw - tmpfs tmpfs rw
'''
    def stat(path):
        assert path not in ('/smb','/tmp')
        return SimpleNamespace(f_blocks=100,f_frsize=4096,f_bavail=50,f_fsid=1 if path in ('/','/bind') else 2)
    with patch.object(runtime.Path,'open',return_value=io.StringIO(content)),patch.object(runtime.os,'statvfs',side_effect=stat):values=runtime.filesystems()
    assert [r['mount'] for r in values]==['/','/srv/data set']
    assert storage.validate(values)==values


def test_windows_legacy_forecast_labels_system_drive():
    rows=storage.volumes({'disk_total_bytes':100,'disk_free_bytes':50},{'os':'Windows Server 2025'})
    assert rows[0]['mount']=='System drive'


def test_stalled_disk_probe_is_bounded_and_old_readings_stay_stale(environment):
    from agent import agent as runtime
    worker=SimpleNamespace(is_alive=lambda:True,start=lambda:None)
    with patch.object(runtime,'_filesystem_worker',None),patch.object(runtime,'_filesystem_latest',None),patch.object(runtime,'_filesystem_started',float('-inf')),patch('threading.Thread',return_value=worker) as thread:
        assert runtime.filesystem_inventory() is None
        assert runtime.filesystem_inventory() is None
        assert thread.call_count==1 and thread.call_args.kwargs['daemon']
    app,store,_=environment;machine,agent,headers=enrolled(store);now=time.time()
    payload={'event_id':str(uuid.uuid4()),'sampled_at':now,'filesystems':[volume()],'filesystems_at':now-300}
    assert app.test_client().post('/api/agent/heartbeat',headers=headers,json=payload).status_code==200
    from aiticket.hostview import detail
    view=storage.build(store,detail(store,machine)['host'])
    assert not view['volumes'][0]['fresh']
    assert view['volumes'][0]['forecast']['state']=='stale'
    assert store.rows('SELECT at FROM capacity_samples')[0]['at']==now-300
