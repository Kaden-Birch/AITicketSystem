import json,time
from unittest.mock import patch
import pytest
from aiticket import health_rules as health
from aiticket.diagnostics import metric_probe
from test_diagnostics import agent


def setting(metric='cpu_percent',**kwargs):
    cfg=health.defaults(metric)
    return dict(metric=metric,enabled='yes',unit='percent',threshold=str(cfg['threshold']),recovery=str(cfg['recovery']),sustain_seconds='120',severity='medium',**kwargs)


def checks(store):
    return store.rows("SELECT * FROM checks WHERE kind='agent_metric'")


def test_defaults_new_agents_overrides_and_pause(environment):
    _,store,_=environment;agent(store,time.time())
    assert len(health.cards(store))==5 and not any(c['enabled'] for c in health.cards(store))
    health.sync(store);assert not checks(store)
    health.save(store,'*',setting())
    row=checks(store)[0];ident=row['id']
    assert row['enabled'] and health.cards(store,'m')[0]['inherited']
    custom=setting();custom.update(threshold='95',recovery='85')
    health.save(store,'m',custom)
    assert checks(store)[0]['id']==ident and json.loads(checks(store)[0]['config'])['threshold']==95
    default=setting();default.update(threshold='92')
    health.save(store,'*',default)
    assert json.loads(checks(store)[0]['config'])['threshold']==95
    health.save(store,'*',{'metric':'cpu_percent','action':'pause'})
    assert not checks(store)[0]['enabled'] and health.cards(store,'m')[0]['paused']
    health.save(store,'*',{'metric':'cpu_percent','action':'resume'})
    assert checks(store)[0]['enabled']
    health.save(store,'m',{'metric':'cpu_percent','action':'disable'})
    assert not checks(store)[0]['enabled']
    health.save(store,'m',{'metric':'cpu_percent','action':'reset'})
    assert checks(store)[0]['enabled'] and json.loads(checks(store)[0]['config'])['threshold']==92
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('new','New agent',0)")
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('new-agent','new','new-secret')")
    health.sync(store)
    assert len(checks(store))==2 and all(c['enabled'] for c in checks(store))


def test_host_override_can_enable_with_disabled_defaults_and_reset_fences_lease(environment):
    _,store,_=environment;agent(store,time.time())
    health.save(store,'m',setting())
    row=checks(store)[0]
    with store.connect() as c:c.execute("UPDATE checks SET lease_token='old',failures=3,first_failure_at=1 WHERE id=?",(row['id'],))
    health.save(store,'m',{'metric':'cpu_percent','action':'reset'})
    row=checks(store)[0]
    assert not row['enabled'] and row['lease_token'] is None and row['failures']==0
    assert not health.cards(store,'m')[0]['enabled']


def test_bytes_threshold_hysteresis_missing_and_stale(environment):
    _,store,_=environment;now=time.time();agent(store,now)
    cfg=setting('disk_used_percent');cfg.update(unit='bytes',threshold='50 GB',recovery='0.06 TB')
    health.save(store,'m',cfg);row=checks(store)[0];cfg=json.loads(row['config']);cfg['_check_id']=row['id']
    assert cfg['threshold']==50e9 and cfg['recovery']==60e9
    with store.connect() as c:c.execute('UPDATE agents SET telemetry=?',(json.dumps({'disk_free_bytes':45e9,'disk_total_bytes':1e12}),))
    assert metric_probe(store,cfg)[0] is False
    with store.connect() as c:
        c.execute("UPDATE checks SET health='down' WHERE id=?",(row['id'],))
        c.execute('UPDATE agents SET telemetry=?',(json.dumps({'disk_free_bytes':55e9}),))
    assert metric_probe(store,cfg)[0] is False
    with store.connect() as c:c.execute('UPDATE agents SET telemetry=?',(json.dumps({'disk_free_bytes':65e9}),))
    assert metric_probe(store,cfg)[0] is True
    with store.connect() as c:c.execute('UPDATE agents SET telemetry=?',('{}',))
    assert metric_probe(store,cfg)[0] is None
    with patch('aiticket.diagnostics.time.time',return_value=now+500):assert metric_probe(store,cfg)[0] is None


def test_unit_input_validation_and_free_percentage(environment):
    _,store,_=environment;agent(store,time.time())
    assert health.amount('500 mb','bytes')==500e6
    assert health.amount('1 tb','bytes')==1e12
    assert health.amount('50','bytes')==50e9
    for text in ('nan','-1','50%','hello'):
        with pytest.raises(ValueError):health.amount(text,'bytes')
    for text in ('nan','inf','101'):
        with pytest.raises(ValueError):health.amount(text,'percent')
    bad=setting();bad.update(unit='bytes')
    with pytest.raises(ValueError):health.save(store,'*',bad)
    health.save(store,'*',setting('memory_used_percent'))
    cfg=json.loads(checks(store)[0]['config'])
    # Test fixture reports half of memory available.
    assert metric_probe(store,cfg)[0] is True
    with store.connect() as c:c.execute('UPDATE agents SET telemetry=?',(json.dumps({'memory_total_bytes':1000,'memory_available_bytes':2000}),))
    assert metric_probe(store,cfg)[0] is None
    with store.connect() as c:c.execute('UPDATE agents SET telemetry=?',(json.dumps({'memory_total_bytes':1000}),))
    assert metric_probe(store,cfg)[0] is None


def test_existing_rules_migrate_preserve_check_and_incident(environment):
    from aiticket.db import Store
    _,store,_=environment;agent(store,time.time())
    old={'agent_id':'a','metric':'disk_used_percent','fail_above':90,'recover_below':80,'sustain_seconds':300}
    with store.connect() as c:
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('legacy','m','Old disk','agent_metric',?,30)",(json.dumps(old),))
        c.execute('DROP TABLE health_rules');c.execute('UPDATE schema_version SET version=31')
    migrated=Store(store.path);health.sync(migrated)
    row=checks(migrated)[0];assert row['id']=='legacy' and row['enabled']
    cfg=json.loads(row['config']);assert cfg['threshold']==10 and cfg['recovery']==20 and cfg['sustain_seconds']==300
    assert next(r for r in health.cards(migrated,'m') if r['metric']=='disk_used_percent')['override']


def test_clean_forms_and_csrf(signed_in):
    client,store,vault,csrf=signed_in;agent(store,time.time())
    page=client.get('/resources').data
    for label in (b'CPU usage',b'Available memory',b'Memory pressure',b'Free storage',b'Available file entries'):assert label in page
    assert b'<pre>' not in page and b'Create rule' not in page and b'type="range"' in page
    assert client.post('/resources',data=setting()).status_code==403
    assert client.post('/resources',data=dict(setting(),csrf=csrf)).status_code==302
    assert b'Using defaults' in client.get('/hosts/m/settings').data
    assert client.post('/hosts/m/health',data=dict(setting(),csrf=csrf)).status_code==302
    page=client.get('/hosts/m/settings').data;assert b'Host override' in page and b'Use defaults' in page
    assert client.post('/hosts/m/health',data={'metric':'cpu_percent','action':'reset','csrf':csrf}).status_code==302
    assert client.post('/hosts/m/health',data=dict(setting(),unit='bytes',csrf=csrf)).status_code==400


def test_disabled_health_retains_ticket_but_suppresses_auto_ai_and_delivery(environment):
    from aiticket.engine import observe,claim
    from aiticket import ai,worker
    _,store,vault=environment;now=time.time();agent(store,now)
    with store.connect() as c:c.execute("UPDATE incidents SET closed=?,status='Resolved'",(now,))
    health.save(store,'m',setting());row=checks(store)[0]
    observe(store,row['id'],False,{'sampled_at':now-200},now=now-200)
    observe(store,row['id'],False,{'sampled_at':now},now=now)
    incident=store.rows('SELECT * FROM incidents WHERE check_id=?',(row['id'],))[0]
    health.save(store,'m',{'metric':'cpu_percent','action':'disable'})
    assert store.rows('SELECT closed FROM incidents WHERE id=?',(incident['id'],))[0]['closed'] is None
    store.save('hermes_config',{'enabled':True,'automatic':True,'minimum':'low'})
    with patch('aiticket.ai.request_job') as request:
        assert ai.automatic_tick(store,vault)==0
        request.assert_not_called()
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/fixture'))
    with store.connect() as c:c.execute("UPDATE deliveries SET state='superseded' WHERE incident_id<>?",(incident['id'],))
    job=claim(store,'deliveries')
    with patch('aiticket.worker.requests.post') as post:
        worker.deliver(store,vault,job);post.assert_not_called()
    assert store.rows('SELECT state FROM deliveries WHERE id=?',(job['id'],))[0]['state']=='superseded'
    with store.connect() as c:
        c.execute('INSERT INTO incident_sources(incident_id,check_id,report) VALUES(?,?,?)',(incident['id'],'c','{}'))
        assert not health.incident_paused(c,incident['id'])


def test_inventory_import_keeps_health_disabled_pending_review(environment):
    from aiticket.inventory import export_inventory,import_inventory
    _,store,vault=environment;agent(store,time.time())
    health.save(store,'*',setting());health.save(store,'m',setting())
    with store.connect() as c:c.execute('UPDATE checks SET config=? WHERE id=?',(json.dumps({'url':'http://127.0.0.1','status':200}),'c'))
    exported=export_inventory(store);import_inventory(store,vault,exported)
    health.sync(store)
    assert not checks(store)[0]['enabled']
    assert health.cards(store,'m')[0]['override'] and not health.cards(store,'m')[0]['enabled']
