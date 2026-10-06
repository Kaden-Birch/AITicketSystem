import json
import re
import time
from aiticket.dashboard_view import build
from aiticket.overview_ui import dashboard_data
from aiticket.engine import observe
from test_overview_ui import monitored


def payload(client):
    response=client.get('/')
    assert response.status_code==200
    return json.loads(re.search(rb'<script id="dashboard-payload" type="application/json">(.*?)</script>',response.data,re.S).group(1))


def test_dashboard_empty_and_real_tickets_are_bounded_and_prioritized(signed_in):
    client,store,_,_=signed_in
    assert payload(client)['tickets']==[]
    priorities=['low','medium','high','critical','medium','high','low','critical']
    for i,severity in enumerate(priorities):
        _,check=monitored(store,'http',severity)
        observe(store,check,False,{'reason':'failure'},now=time.time()-100+i)
    data=payload(client)
    assert data['summary']['open']==8 and len(data['tickets'])==5
    assert [t['severity'] for t in data['tickets']]==['critical','critical','high','high','medium']
    assert data['tickets'][0]['updated']>=data['tickets'][1]['updated']
    assert not data['nodes'] and not data['nas'] and not data['network']
    assert len(data['summary']['daily'])==30


def test_dashboard_inventory_scope_stale_data_and_credentials(signed_in):
    from test_proxmox_workspace import seed
    from test_truenas_workspace import setup
    client,store,vault,_=signed_in
    seed(store,vault);setup(store,vault)
    data=payload(client)
    assert len(data['nodes'])==2
    assert data['nodes'][0]['guests'][0]['name']=='Web VM'
    assert len(data['nas'])==1 and len(data['nas'][0]['drives'])==5
    assert next(d for d in data['nas'][0]['drives'] if d['title']=='nvme0n1')['media']=='SSD'
    assert len(data['nas'][0]['containers'])==1 and len(data['nas'][0]['vms'])==1
    encoded=json.dumps(data)
    assert 'fixture-secret' not in encoded and 'https://nas.invalid' not in encoded
    with store.connect() as c:
        c.execute('UPDATE integrations SET at=?',(time.time()-10000,))
        c.execute('UPDATE proxmox_objects SET last_seen=?',(time.time()-10000,))
    data=payload(client)
    assert not data['nas'][0]['fresh'] and all(d['state']=='unknown' for d in data['nas'][0]['drives'])
    assert all(not n['fresh'] for n in data['nodes'])


def test_updated_ticket_order_uses_latest_timeline(environment):
    _,store,_=environment
    for _ in range(2):
        _,check=monitored(store,'http','high');observe(store,check,False,{},now=time.time()-60)
    rows=store.rows('SELECT id FROM incidents ORDER BY id');chosen=rows[-1]['id']
    with store.connect() as c:store.timeline(c,chosen,'note','Recent update',now=time.time())
    assert build(store,dashboard_data(store))['tickets'][0]['id']==chosen


def test_unifi_link_speeds_drive_media_and_stale_readings(signed_in):
    from unittest.mock import patch
    from aiticket import unifi
    client,store,vault,_=signed_in
    identifier=unifi.save(store,vault,{'name':'LAN','url':'https://unifi.invalid','secret':'fixture-secret','kind':'network','site':'site1'})
    device={'id':'d1','name':'Switch','state':'ONLINE','type':'gateway','interfaces':{'ports':[{'idx':i,'state':'UP' if speed else 'DOWN','speedMbps':speed} for i,speed in enumerate([100,1000,2500,10000,25000,0],1)]},'storage':{'disks':[{'slotId':1,'state':'optimal','type':'HDD'},{'slotId':2,'state':'failed','type':'SSD'}]}}
    def get(self,path,params=None):
        if path.endswith('/devices'):return {'data':[device]}
        if path.endswith('/devices/d1'):return device
        if path.endswith('/statistics/latest'):return {'cpuUtilizationPct':10}
        return {'data':[]}
    with patch.object(unifi.Client,'get',get):unifi.refresh(store,vault,identifier)
    data=payload(client);d=data['network'][0]
    assert [p['speed'] for p in d['ports']]==[100,1000,2500,10000,25000,0]
    assert [d['media'] for d in d['drives']]==['HDD','SSD']
    assert 'fixture-secret' not in json.dumps(data)
    with store.connect() as c:c.execute('UPDATE unifi_devices SET last_seen=?',(time.time()-3600,))
    d=payload(client)['network'][0]
    assert not d['fresh'] and all(p['speed'] is None for p in d['ports'])
    assert all(d['state']=='unknown' for d in d['drives'])
