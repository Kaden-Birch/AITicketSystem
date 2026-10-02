import time,json
from aiticket.metric_history import record,charts
from aiticket.administration import prune
from aiticket.db import uid


def test_source_separation_gaps_and_retention(environment):
    _,store,_=environment;now=time.time()
    with store.connect() as c:
        record(c,'machine','agent',now-60,{'cpu_percent':80,'memory_total_bytes':100,'memory_available_bytes':25})
        record(c,'machine','agent',now-1800,{'cpu_percent':20})
        record(c,'object','proxmox',now-10,{'cpu':.4,'maxmem':100,'mem':50})
        record(c,'machine','agent',now-700000,{'cpu_percent':10})
    host={'id':'machine','agent':{},'object':{'id':'object'}}
    host['agent']={'id':'agent'}
    history=charts(store,host,'1h',now)
    cpu=next(x for x in history['charts'] if x['key']=='cpu_percent')
    assert cpu['latest']==80 and len(cpu['segments'])==2 and history['count']==2
    host['agent']=None
    assert charts(store,host,'1h',now)['charts'][0]['latest']==40
    prune(store,now)
    assert not store.rows('SELECT * FROM metric_samples WHERE at<?',(now-604800,))


def test_host_specific_add_check_and_history_page(signed_in):
    client,store,_,_=signed_in;machine=uid()
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Chart host',time.time()))
    assert client.get('/hosts/'+machine+'/checks/new').status_code==200
    page=client.get('/hosts/'+machine)
    assert page.status_code==200 and b'Performance history' in page.data and b'Host settings' in page.data
    assert b'No metric history yet' in page.data
    assert client.get('/hosts/missing/checks/new').status_code==404
