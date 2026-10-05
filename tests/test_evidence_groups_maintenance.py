import json,time,uuid
from unittest.mock import patch
import pytest
from aiticket import ai,commands,evidence,ticket_groups,maintenance_ai
from aiticket.engine import observe
from test_ai import configured
from test_codex_mode import configure
from aiticket.security import digest


def window(store,machine=None,start=None,end=None):
    now=time.time()
    with store.connect() as c:c.execute("INSERT INTO maintenance_windows VALUES('w','Updates',?,'once','America/Edmonton',?,?,NULL,NULL,NULL,1)",(machine,start or now-10,end or now+300))


def operational(store,vault,automatic=False,changes=False):
    incident=configure(store,vault,command_tools=True,automatic=True,minimum='medium')
    commands.configure(store,'m',{'enabled':'yes','hermes':'yes','approval':'immediate'})
    with store.connect() as c:c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES('a','m',?,?,?)",(digest('agent-secret'),time.time(),json.dumps({'shell_commands':True})))
    job=ai.request_job(store,vault,incident,automatic=automatic,maintenance_changes=changes)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    return incident,job


def test_automatic_admission_manual_diagnostics_and_explicit_change(environment):
    _,store,vault=environment
    incident,job=operational(store,vault,automatic=True)
    window(store,'m')
    assert ai.request_job(store,vault,incident,automatic=True) is None
    with pytest.raises(ValueError,match='Maintenance'):
        commands.queue(store,vault,'m','touch /tmp/fixture',str(uuid.uuid4()),incident,job)
    identifier=commands.queue(store,vault,'m','uptime',str(uuid.uuid4()),incident,job)
    with store.connect() as c:assert commands.poll(c,store,vault,'a',time.time())[0]['id']==identifier
    ai.cancel(store,job)
    with store.connect() as c:c.execute("UPDATE command_jobs SET state='cancelled'")
    job=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    with pytest.raises(ValueError,match='Maintenance'):
        commands.queue(store,vault,'m','touch /tmp/fixture',str(uuid.uuid4()),incident,job)
    ai.cancel(store,job)
    job=ai.request_job(store,vault,incident,maintenance_changes=True)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    assert commands.queue(store,vault,'m','touch /tmp/fixture',str(uuid.uuid4()),incident,job)


def test_window_starts_after_queue_cancels_new_changes_not_running(environment):
    _,store,vault=environment
    incident,job=operational(store,vault,automatic=True)
    identifier=commands.queue(store,vault,'m','touch /tmp/fixture',str(uuid.uuid4()),incident,job)
    window(store,'m')
    with store.connect() as c:assert commands.poll(c,store,vault,'a',time.time())==[]
    assert commands.view(store,vault,identifier)['state']=='cancelled'
    with store.connect() as c:c.execute("DELETE FROM maintenance_windows")
    identifier=commands.queue(store,vault,'m','touch /tmp/fixture2',str(uuid.uuid4()),incident,job)
    with store.connect() as c:dispatch=commands.poll(c,store,vault,'a',time.time())[0]
    assert commands.permission(store,'a',dispatch)['allowed']
    window(store,'m')
    assert commands.permission(store,'a',dispatch)['allowed'] # never terminate admitted running work


def test_queued_automatic_waits_for_post_window_result(environment):
    _,store,vault=environment
    incident,_=configured(store,vault)
    store.save('hermes_config',{**store.setting('hermes_config'),'automatic':True,'minimum':'medium'})
    now=time.time()+5
    job=ai.request_job(store,vault,incident,automatic=True,now=now)
    window(store,'m',now-1,now+30)
    with patch('aiticket.ai.bridge_request') as send:
        assert ai.tick(store,vault,now=now) is False
        assert not send.called
        assert ai.tick(store,vault,now=now+31) is False
        assert not send.called
        observe(store,'c',False,{'reason':'still failed'},now=now+32)
        send.return_value={'state':'running'}
        ai.tick(store,vault,now=now+50)
        assert send.called


def other(store,identifier='other',check='other-check'):
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(identifier,'Other host',time.time()))
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES(?,?,?,'http','{}',60)",(check,identifier,'Dependent app'))
    now=time.time()
    for n in range(3):observe(store,check,False,{'reason':'unavailable'},now=now+n)
    return store.rows('SELECT id FROM incidents WHERE machine_id=?',(identifier,))[0]['id']


def test_groups_retain_recovery_history_detach_excludes_automatic_regroup(environment):
    _,store,vault=environment
    primary,_=configured(store,vault);child=other(store)
    ticket_groups.attach(store,primary,child,'Shared storage dependency')
    with store.connect() as c:
        assert ticket_groups.active_primary(c,child)==primary
        assert len(ticket_groups.context(c,primary)['tickets'])==2
        assert ticket_groups.machines(c,primary)=={'m','other'}
    now=time.time()+5
    observe(store,'c',True,{},now=now);observe(store,'c',True,{},now=now+1)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(child,))[0]['status']!='Resolved'
    ticket_groups.detach(store,primary,child)
    assert store.rows('SELECT * FROM ticket_group_exclusions')
    with store.connect() as c:assert ticket_groups.active_primary(c,child) is None


def test_dependency_auto_group_and_no_timing_only_group(environment):
    _,store,vault=environment
    primary,_=configured(store,vault);child=other(store)
    ticket_groups.tick(store,time.time()+5)
    assert not store.rows('SELECT * FROM ticket_groups')
    from aiticket.applications import save
    save(store,'Storage consumers',['c','other-check'],[('other-check','c')])
    ticket_groups.tick(store,time.time()+5)
    assert store.rows('SELECT primary_id FROM ticket_groups WHERE member_id=?',(child,))[0]['primary_id']==primary
    ticket_groups.detach(store,primary,child)
    ticket_groups.tick(store,time.time()+5)
    assert not store.rows('SELECT * FROM ticket_groups')


def test_grouped_context_does_not_grant_other_host_commands(environment):
    app,store,vault=environment
    incident,job=operational(store,vault);child=other(store)
    ticket_groups.attach(store,incident,child,'Related storage')
    token=vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(job,))[0]['credential'])
    client=app.test_client();headers={'Authorization':'Bearer '+token}
    path='/api/hermes/'+job+'/command'
    response=client.post(path,json={'action':'targets'},headers=headers)
    assert response.status_code==200
    targets={x['id']:x for x in response.json['targets']}
    assert targets['other']['shell']['available'] is False
    assert client.post(path,json={'action':'evidence','machine_id':'other','source':'checks'},headers=headers).status_code==200
    assert client.post(path,json={'action':'run','machine_id':'other','command':'uptime','id':str(uuid.uuid4())},headers=headers).status_code==400
    assert client.post(path,json={'action':'evidence','machine_id':'not-linked','source':'checks'},headers=headers).status_code==403


def test_paged_evidence_freshness_redaction_history(environment):
    _,store,vault=environment
    configured(store,vault)
    with store.connect() as c:
        c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,sampled_at,telemetry) VALUES('a','m','digest',?,?,?)",(time.time(),time.time()+3600,json.dumps({'cpu_percent':10,'api_key':'secret'})))
        c.execute('INSERT INTO agent_discovery VALUES(?,?,?)',('m',time.time(),json.dumps({'processes':[{'name':'process'+str(i)} for i in range(100)],'containers':[],'containers_truncated':True})))
        c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',('m','agent',time.time(),json.dumps({'cpu_percent':10})))
        summary=evidence.summary(c,'m')
        assert next(x for x in summary if x['source']=='metrics')['state']=='stale'
        first=evidence.page(c,'m','processes',limit=20);second=evidence.page(c,'m','processes',offset=20,limit=20)
        assert first['next_offset']==20 and first['total']==100 and first['items']!=second['items']
        assert 'secret' not in json.dumps(evidence.page(c,'m','metrics'))
        assert evidence.page(c,'m','history')['items'][0]['metrics']['cpu_percent']==10
        with pytest.raises(ValueError):evidence.page(c,'m','processes',limit=100)


def test_ticket_ui_csrf_groups_targets_and_maintenance(signed_in):
    client,store,vault,csrf=signed_in
    primary,_=configured(store,vault);child=other(store)
    window(store,'m')
    page=client.get('/incidents/'+primary)
    assert page.status_code==200 and b'Evidence available' in page.data and b'Maintenance active' in page.data
    path='/incidents/'+primary+'/related'
    fields={'operation':'attach','ticket_id':child,'reason':'Related outage'}
    assert client.post(path,data=fields).status_code==403
    assert client.post(path,data={**fields,'csrf':csrf}).status_code==302
    assert b'Dependent app' in client.get('/incidents/'+primary).data
    assert client.post(path,data={'csrf':csrf,'operation':'add_host','machine_id':'other'}).status_code==302
    assert client.post(path,data={'csrf':csrf,'operation':'detach','ticket_id':child}).status_code==302
    with store.connect() as c:assert 'other' in ticket_groups.machines(c,primary)


def test_proxmox_queued_write_rechecks_maintenance_even_admin_approval(environment):
    _,store,vault=environment
    incident,job=operational(store,vault,automatic=True)
    from test_proxmox_operations import host,payload
    from aiticket import proxmox_operations as px
    machine,_=host(store,vault,'required')
    with store.connect() as c:c.execute('UPDATE incidents SET machine_id=? WHERE id=?',(machine,incident))
    identifier=px.queue(store,vault,machine,payload(),ai_job=job)
    window(store,machine)
    with patch('aiticket.proxmox_operations.requests.request') as send:
        with pytest.raises(ValueError,match='Maintenance'):px.execute(store,vault,identifier)
        assert not send.called


def test_related_refresh_is_read_only_scoped_and_credentials_excluded(environment):
    app,store,vault=environment
    incident,job=operational(store,vault)
    from aiticket import integrations
    from test_storage_services import CFG,sample
    connection=integrations.save(store,vault,'m','truenas','Voyager',CFG,'private-test-key',snapshot=sample())
    token=vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(job,))[0]['credential']);headers={'Authorization':'Bearer '+token}
    client=app.test_client();path='/api/hermes/'+job+'/command'
    with patch('aiticket.integrations.read',return_value=sample()) as read:
        result=client.post(path,json={'action':'refresh','connection_id':connection},headers=headers)
        assert result.status_code==200 and result.json['state']=='refreshed'
        assert read.call_args.args[2]=='private-test-key'
        assert 'private-test-key' not in result.text
        result=client.post(path,json={'action':'evidence','source':'services'},headers=headers)
        assert result.status_code==200 and 'private-test-key' not in result.text
        assert any(x['collection']=='apps' for x in result.json['items'])
        assert client.post(path,json={'action':'refresh','connection_id':'unrelated'},headers=headers).status_code==400


def test_maintained_primary_does_not_pause_other_host(environment):
    _,store,vault=environment
    primary,_=configured(store,vault);child=other(store)
    ticket_groups.attach(store,primary,child,'Explicit dependency')
    store.save('hermes_config',{**store.setting('hermes_config'),'automatic':True,'minimum':'medium'})
    window(store,'m')
    with store.connect() as c:
        assert ticket_groups.coordinating_primary(c,child) is None
        assert not maintenance_ai.state(c,'other',incident=child)['active']
    assert ai.request_job(store,vault,child,automatic=True)


def test_schema37_upgrade_preserves_data_and_recovers_automatic_origin(environment):
    _,store,vault=environment
    incident,_=configured(store,vault)
    store.save('hermes_config',{**store.setting('hermes_config'),'automatic':True,'minimum':'medium'})
    job=ai.request_job(store,vault,incident,automatic=True)
    with store.connect() as c:
        from conftest import remove_schema38
        remove_schema38(c);c.execute('UPDATE schema_version SET version=37')
    from aiticket.db import Store
    upgraded=Store(store.path)
    assert upgraded.rows('SELECT automatic,maintenance_changes FROM ai_jobs WHERE id=?',(job,))==[{'automatic':1,'maintenance_changes':0}]
    assert upgraded.rows('SELECT id FROM incidents WHERE id=?',(incident,))


def test_group_notifications_consolidate_openings_but_not_recovery(environment):
    _,store,vault=environment
    primary,_=configured(store,vault);child=other(store)
    ticket_groups.attach(store,primary,child,'Shared dependency')
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/fixture'))
    from aiticket.engine import claim
    from aiticket.worker import deliver
    now=time.time()+10
    with store.connect() as c:c.execute('UPDATE deliveries SET next_attempt=0')
    with patch('aiticket.worker.requests.post') as send:
        send.return_value.status_code=204
        for _ in range(2):deliver(store,vault,claim(store,'deliveries',now=now))
        assert send.call_count==1
        assert 'Affected:' in send.call_args.kwargs['json']['content']
        assert store.rows("SELECT state FROM deliveries WHERE incident_id=?",(child,))[0]['state']=='superseded'
        observe(store,'other-check',True,{},now=now+1);observe(store,'other-check',True,{},now=now+2)
        deliver(store,vault,claim(store,'deliveries',now=now+3))
        assert send.call_count==2
    assert store.rows('SELECT closed FROM incidents WHERE id=?',(primary,))[0]['closed'] is None


def test_evidence_contains_thresholds_and_pool_application_history(environment):
    _,store,vault=environment
    configured(store,vault)
    from aiticket import integrations
    from test_storage_services import CFG,sample
    identifier=integrations.save(store,vault,'m','truenas','NAS',CFG,'fixture',snapshot=sample())
    now=time.time()
    with store.connect() as c:
        c.execute("UPDATE checks SET config=? WHERE id='c'",(json.dumps({'fail_above':90,'password':'hidden'}),))
        for suffix in (':pool:1',':app:plex'):
            c.execute('INSERT INTO metric_samples VALUES(?,?,?,?)',(identifier+suffix,'storage',now,'{"used_percent":55}'))
        checks=evidence.page(c,'m','checks',now=now)['items']
        config=next(x for x in checks if x['id']=='c')['configuration']
        assert config['fail_above']==90 and 'hidden' not in json.dumps(config)
        history=evidence.page(c,'m','history',now=now)
        assert any(x['entity_id'].endswith(':pool:1') for x in history['items'])
        assert any(x['entity_id'].endswith(':app:plex') for x in history['items'])


def test_maintenance_global_and_descendant_scope_with_manual_ticket(environment):
    _,store,vault=environment
    incident,_=configured(store,vault);other(store)
    with store.connect() as c:c.execute("UPDATE machines SET parent_id='m' WHERE id='other'")
    window(store,'m')
    with store.connect() as c:
        assert maintenance_ai.state(c,'other')['active']
        c.execute('UPDATE maintenance_windows SET machine_id=NULL')
        assert maintenance_ai.state(c,'other')['active']
        c.execute("UPDATE checks SET kind='manual' WHERE id='c'")
        c.execute("UPDATE observations SET at=0 WHERE check_id='c'")
        assert maintenance_ai.fresh_after_pause(c,incident,time.time())
