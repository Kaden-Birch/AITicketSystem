"""Real inventory, optional API coverage and presentation honesty."""
import json,time
from unittest.mock import Mock,patch
from aiticket import truenas,integrations,truenas_view


def inventory():
    return {'system':{'hostname':'Voyager','version':'TrueNAS-25.04.2.6','cores':8,'physmem':32*1024**3},'pools':[{'id':1,'name':'Archive','status':'ONLINE','healthy':True,'topology':{'data':[{'type':'RAIDZ','parity':2,'children':[{'type':'DISK','disk':'sda','status':'ONLINE','stats':{'read_errors':0}},{'type':'DISK','disk':'sdb','status':'ONLINE','stats':{'checksum_errors':3}}]}]}},{'id':2,'name':'Apps','status':'ONLINE','healthy':True,'topology':{'data':[{'type':'MIRROR','children':[{'type':'DISK','disk':'nvme0n1','status':'ONLINE'},{'type':'DISK','path':'/dev/sdz1','status':'OFFLINE'}]}]}}], 'disks':{'sda':{'type':'HDD','size':12e12,'model':'Archive disk','serial':'one','secret':'discard'},'sdb':{'type':'HDD','size':12e12},'nvme0n1':{'type':'SSD','size':2e12},'sdz':{'type':'SSD','size':2e12}},'datasets':[{'id':'Archive','used':{'parsed':1e12},'available':{'parsed':11e12}},{'id':'Apps','used':{'parsed':1e11},'available':{'parsed':1.9e12}}], 'apps':[{'name':'Plex','state':'RUNNING','human_version':'1.40','active_workloads':{'container_details':[{'id':'c1','service_name':'plex','image':'plex/image','state':'running','environment':{'secret':'discard'}}],'volumes':[{'source':'/mnt/media','destination':'/media'}]}}],'vms':[{'id':8,'name':'Ubuntu','vcpus':2,'cores':2,'threads':1,'memory':4096,'autostart':True,'status':{'state':'RUNNING'},'devices':[{'attributes':{'dtype':'DISPLAY','password':'discard'}},{'attributes':{'dtype':'DISK','path':'/mnt/Apps/ubuntu.img'}}],'cloud_init':'discard'}],'alerts':[],'services':[{'service':'cifs','state':'RUNNING'}]}


def snapshot():
    return truenas.normalize(inventory(),{'reporting.realtime':{'cpu':{'cpu':{'usage':18,'temp':51}},'memory':{'physical_memory_total':32*1024**3,'physical_memory_available':16*1024**3,'arc_size':8*1024**3},'interfaces':{'eno1':{'link_state':'LINK_STATE_UP','speed':10000,'received_bytes_rate':1024,'sent_bytes_rate':2048}},'disks':{'read_bytes':3e6,'write_bytes':2e6}}})


def setup(store,vault):
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('nas','Voyager',1)")
    identifier=integrations.save(store,vault,'nas','truenas','Voyager',{'url':'https://nas.invalid','username':'monitor','interval':60},'fixture-secret',snapshot=snapshot())
    return identifier


def test_inventory_secret_filter_and_exact_pool_members(environment):
    _,store,vault=environment;setup(store,vault);connection=integrations.views(store,'nas')[0]
    view=truenas_view.build(store,{'id':'nas'},connection)
    assert 'discard' not in json.dumps(connection['data'])
    assert len(view['disks'])==5 # A partition cannot be guessed to be its physical disk.
    sda=next(x for x in view['disks'] if x['title']=='sda');sdb=next(x for x in view['disks'] if x['title']=='sdb')
    assert sda['media']=='HDD' and sda['state']=='healthy' and sdb['state']=='warning'
    assert next(x for x in view['disks'] if x['title']=='sdz1')['media']=='?'
    assert next(x for x in view['disks'] if x['title']=='sdz')['pool_name']=='Unmapped'
    assert view['vms'][0]['reading']=='4 vCPUs · 4.0 GiB'
    assert view['apps'][0]['children'][0]['key']==view['containers'][0]['key']
    assert sdb['indicator']=='I/O errors'
    assert view['metrics'][1]['fill']==38.75 and view['metrics'][2]['value']==50
    # Drawer selection remains the same when another pool is inserted or removed.
    connection['data']['pools'].reverse()
    after=truenas_view.build(store,{'id':'nas'},connection)
    assert next(x for x in after['disks'] if x['title']=='sda')['key']==sda['key']
    assert integrations.probe(store,'truenas',{'connection_id':connection['id'],'scope':'host'})[0] is True


def test_missing_stale_and_bounded_history(environment):
    _,store,vault=environment;setup(store,vault);connection=integrations.views(store,'nas')[0];now=time.time()
    with store.connect() as c:
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('nas','truenas',now-20,json.dumps({'disk_read_bytes':3e6,'transmit_kib_s':1024})))
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('nas','agent',now-10,json.dumps({'disk_read_bytes':9e6})))
    view=truenas_view.build(store,{'id':'nas'},connection,'10m',now)
    assert view['samples']==[{'at':(now-20)*1000,'read':3,'write':None,'receive':None,'send':1.048576}]
    connection['fresh']=False
    view=truenas_view.build(store,{'id':'nas'},connection)
    assert view['health']=='unknown' and all(m['value'] is None for m in view['metrics']) and all(x['state']=='unknown' for x in view['disks'])
    connection['data']={'error':'Offline'};connection['fresh']=True
    view=truenas_view.build(store,{'id':'nas'},connection,'invalid')
    assert not view['fresh'] and not view['vm_available'] and view['window']=='1h' and view['disks']==[]


def test_optional_disk_vm_permissions_preserve_pool_checks():
    fake=Mock()
    def call(method,*args):
        if method=='auth.login_ex':return {'response_type':'SUCCESS'}
        if method=='system.info':return inventory()['system']
        if method in ('device.get_info','vm.query'):raise truenas.RPCError(method)
        return {'pool.query':inventory()['pools'],'pool.dataset.query':inventory()['datasets'],'app.query':[], 'alert.list':[], 'service.query':[]}[method]
    fake.call.side_effect=call;fake.statistics.return_value={}
    with patch('aiticket.truenas.Client',return_value=fake):d=truenas.collect({'username':'monitor'},'fixture')
    assert d['pools'][0]['healthy'] and 'vms' not in d and 'disks' not in d
    assert any('vms' in w for w in d['warnings']);fake.close.assert_called_once()
    fake.call.assert_any_call('device.get_info',{'type':'DISK','get_partitions':False,'serials_only':False})
    fake.call.assert_any_call('vm.query',[],{'limit':100})


def test_workspace_render_and_existing_monitor_actions(signed_in):
    client,store,vault,csrf=signed_in;identifier=setup(store,vault)
    page=client.get('/hosts/nas?window=30d')
    assert page.status_code==200
    for label in (b'Server &amp; storage',b'NAS applications &amp; workloads',b'Virtual machines',b'Additional performance history',b'Open tickets',b'Ticket history',b'Host settings',b'Add application',b'Monitor pool',b'Monitor application'):assert label in page.data
    assert b'fixture-secret' not in page.data and b'discard' not in page.data
    assert b'/services/new?host=nas' in page.data
    assert b'value="nas" selected' in client.get('/services/new?host=nas').data
    response=client.post('/integrations/'+identifier+'/checks',data={'csrf':csrf,'scope':'pool','target':'1'})
    assert response.status_code==302
    response=client.post('/integrations/'+identifier+'/checks',data={'csrf':csrf,'scope':'app','target':'Plex'})
    assert response.status_code==302
    assert len(store.rows('SELECT id FROM checks'))==3
    with store.connect() as c:c.execute('UPDATE integrations SET snapshot=?',(json.dumps({'error':'Connection unavailable'}),))
    page=client.get('/hosts/nas');assert page.status_code==200 and b'Visibility is incomplete' in page.data


def test_many_drives_and_escaped_strings(signed_in):
    client,store,vault,csrf=signed_in;setup(store,vault);raw=inventory();raw['pools'][0]['name']='Archive <script>alert(1)</script>'
    raw['pools'][0]['topology']['data'][0]['children']=[{'type':'DISK','disk':f'sd{i}','status':'ONLINE'} for i in range(36)]
    raw['disks']={f'sd{i}':{'type':'HDD','size':12e12} for i in range(36)}
    with store.connect() as c:c.execute('UPDATE integrations SET snapshot=?',(json.dumps(truenas.normalize(raw,{})),))
    page=client.get('/hosts/nas');assert page.status_code==200
    assert b'<script>alert(1)</script>' not in page.data
    assert b'Archive &lt;script&gt;alert(1)&lt;/script&gt;' in page.data
    assert page.data.count(b'data-drive-pool=')>=36
