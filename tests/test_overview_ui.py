import json,time
from aiticket import overview_ui,host_presence
from aiticket.engine import observe
from aiticket.db import uid


def monitored(store,kind='agent',severity='medium',machine=None):
    machine=machine or uid();check=uid()
    with store.connect() as c:
        c.execute('INSERT OR IGNORE INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Example host',time.time()))
        c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,?,?,60,1,1,?)',(check,machine,'Heartbeat' if kind=='agent' else 'Application',kind,'{}',severity))
    return machine,check


def test_compact_pages_search_and_auth(signed_in):
    client,store,vault,csrf=signed_in;machine,check=monitored(store)
    observe(store,check,False,{'reason':'lost heartbeat'})
    assert b'Example host' in client.get('/').data  # Featured open ticket now includes its host.
    hosts=client.get('/hosts').data
    assert b'Example host' in hosts and b'Monitoring checks' not in hosts and b'Add machine' not in hosts
    assert b'Heartbeat' in client.get('/tickets').data
    search=client.get('/search?q=Example').json
    assert any(r['url']=='/hosts/'+machine for r in search['results'])
    assert any(r['kind']=='Check' for r in client.get('/search?q=Heartbeat').json['results'])
    assert client.get('/search?q=%').status_code==200
    assert client.get('/tickets?view=unknown').status_code==400
    assert client.get('/hosts/new').status_code==200
    assert b'site-menu' in hosts and b'command-palette' in hosts
    client.post('/logout',data={'csrf':csrf})
    assert client.get('/search?q=Example').status_code==302


def test_manual_offline_closes_only_reachability_and_resumes(environment):
    _,store,vault=environment;machine,check=monitored(store);_,appcheck=monitored(store,'http',machine=machine)
    now=time.time()
    observe(store,check,False,{'reason':'heartbeat lost'},now=now)
    observe(store,appcheck,False,{'reason':'HTTP error'},now=now)
    assert len(store.rows('SELECT * FROM incidents WHERE closed IS NULL'))==2
    assert host_presence.set_offline(store,machine,True)==1
    assert len(store.rows('SELECT * FROM incidents WHERE closed IS NULL'))==1
    closed=store.rows('SELECT * FROM incidents WHERE closed IS NOT NULL')[0]
    report=json.loads(closed['report']);assert report['manual_resolution'] and report.get('observed')!='healthy'
    observe(store,check,False,{'reason':'heartbeat lost'},now=now+30)
    assert len(store.rows('SELECT * FROM incidents'))==2
    assert overview_ui.host_list(store,now+30)[0]['state']=='offline'
    host_presence.set_offline(store,machine,False)
    observe(store,check,False,{'reason':'heartbeat lost'},now=now+60)
    assert len(store.rows('SELECT * FROM incidents'))==3


def test_ticket_filters_intervention_and_history_metrics(signed_in):
    client,store,vault,csrf=signed_in;machine,check=monitored(store,'http')
    now=time.time();observe(store,check,False,{},now=now-7200)
    incident=store.rows('SELECT * FROM incidents')[0]
    with store.connect() as c:
        c.execute('INSERT INTO ticket_blockers VALUES(?,?,?,?,?,NULL)',(uid(),incident['id'],None,'Need clarification',now-3600))
    assert b'Needs attention' in client.get('/tickets?view=manual').data
    data=overview_ui.dashboard_data(store,now)
    assert data['manual_percent']==100 and data['average_hours'] is None
    observe(store,check,True,{},now=now)
    data=overview_ui.dashboard_data(store,now)
    assert data['average_hours']==2 and data['open']==0
    assert b'Heartbeat' not in client.get('/tickets?view=open').data
    assert b'Application' in client.get('/tickets?view=resolved').data


def test_dashboard_uses_health_not_resource_averages(environment):
    _,store,vault=environment;machine,_=monitored(store);now=time.time()
    with store.connect() as c:
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,capabilities) VALUES(?,?,?,?)',(uid(),machine,'fixture','{}'))
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',(machine,'agent',now-1,json.dumps({'cpu_percent':40,'ram_percent':20,'disk_percent':10})))
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('unassigned-unifi','unifi',now-1,json.dumps({'cpu_percent':99})))
    data=overview_ui.dashboard_data(store,now)
    assert data['charts']==[]
    assert data['host_health']['unreachable']==1
    assert data['check_health']['unknown']==1
    assert len(data['ticket_charts'][0]['series'])==2

def test_stopped_proxmox_explains_missing_heartbeat_without_hiding_other_checks(environment):
    from test_hosts_power import guest
    _,store,vault=environment;machine,_=guest(store,vault,status='stopped');_,heartbeat=monitored(store,machine=machine)
    _,application=monitored(store,'http',machine=machine);now=time.time()
    observe(store,heartbeat,False,{'heartbeat_age_seconds':300},now=now)
    assert not store.rows('SELECT * FROM incidents')
    assert next(h for h in overview_ui.host_list(store,now) if h['id']==machine)['state']=='offline'
    observe(store,application,False,{'reason':'bad service'},now=now)
    assert len(store.rows('SELECT * FROM incidents WHERE closed IS NULL'))==1


def test_offline_api_requires_auth_and_preserves_mixed_incident(signed_in):
    client,store,vault,csrf=signed_in;machine,check=monitored(store)
    observe(store,check,False,{});incident=store.rows('SELECT * FROM incidents')[0]
    _,other=monitored(store,'http',machine=machine)
    with store.connect() as c:c.execute('INSERT INTO incident_sources(incident_id,check_id,report) VALUES(?,?,?)',(incident['id'],other,'{}'))
    assert client.post('/hosts/'+machine+'/presence',data={'mode':'offline'}).status_code==403
    assert client.post('/hosts/'+machine+'/presence',data={'csrf':csrf,'mode':'offline'}).status_code==302
    assert store.rows('SELECT closed FROM incidents')[0]['closed'] is None


def test_dashboard_separates_health_retrying_stale_and_maintenance(environment):
    _,store,_=environment;now=time.time()
    m,down=monitored(store,'http');_,retry=monitored(store,'http',machine=m);_,passing=monitored(store,'http',machine=m)
    _,stale=monitored(store,'http',machine=m);_,paused=monitored(store,'http',machine=m)
    with store.connect() as c:
        for identifier,health,failures,at in ((down,'down',3,now),(retry,'healthy',1,now),(passing,'healthy',0,now),(stale,'healthy',0,now-400),(paused,'down',3,now)):
            c.execute('UPDATE checks SET health=?,failures=? WHERE id=?',(health,failures,identifier))
            c.execute('INSERT INTO observations VALUES(?,?,?,?,?)',(uid(),identifier,at,health,'{}'))
        c.execute('UPDATE checks SET maintenance_until=? WHERE id=?',(now+600,paused))
    data=overview_ui.dashboard_data(store,now)
    assert data['check_health']=={'healthy':1,'retrying':1,'down':1,'unknown':1,'paused':1}
    assert data['hosts_attention']==1
    host_presence.set_offline(store,m,True)
    data=overview_ui.dashboard_data(store,now)
    assert data['host_health']['offline']==1 and data['hosts_attention']==0
    assert data['check_health']['down']==1 # Intentional shutdown does not erase application evidence.


def test_dashboard_today_uses_local_dates_and_backlog_includes_older_tickets(environment):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    _,store,_=environment
    now=datetime(2026,10,4,1,0,tzinfo=ZoneInfo('UTC')).timestamp() # Oct 3 in Mountain time.
    machine,check=monitored(store,'http')
    observe(store,check,False,{},now=now-40*86400)
    data=overview_ui.dashboard_data(store,now)
    assert data['recent']==0 and data['open']==1
    assert data['ticket_charts'][1]['latest']==1
    observe(store,check,True,{},now=now-600)
    data=overview_ui.dashboard_data(store,now)
    assert data['resolved_today']==1 and data['opened_today']==0 and data['resolved_count']==1
    assert data['average_resolution']=='40.0d'
    assert data['date_end']=='2026-10-03'
