import json,time,uuid
from unittest.mock import patch,Mock
import pytest
from aiticket import ai,engine
from aiticket.applications import save,upstream_incident,view
from aiticket.host_admin import open_ticket
from aiticket.reliability import issues,start_test,test_probe,repair_budget,RepairLimit
from aiticket.machine_context import context
from aiticket.ticket_updates import readable
from test_codex_mode import configure


def test_manual_ticket_queues_immediately_below_automatic_threshold(signed_in):
    client,store,vault,csrf=signed_in;configure(store,vault,command_tools=True)
    response=client.post('/tickets/new',data={'csrf':csrf,'machine_id':'m','title':'Install Docker','description':'Install Docker and verify it works.','severity':'low'})
    assert response.status_code==302
    ticket=response.location.rsplit('/',1)[1]
    job=store.rows('SELECT * FROM ai_jobs WHERE incident_id=?',(ticket,))[0]
    assert job['state']=='pending' and json.loads(job['evidence'])['administrator_task']=='Install Docker and verify it works.'
    assert len(store.rows('SELECT * FROM incidents WHERE id=?',(ticket,)))==1


def test_automatic_dispatch_recovers_manual_creation_without_page_route(environment):
    _,store,vault=environment;configure(store,vault)
    bridge=store.setting('hermes_config');bridge.update(automatic=True,minimum='critical');store.save('hermes_config',bridge)
    ticket=open_ticket(store,'m','Check app','Investigate','low')
    assert ai.automatic_tick(store,vault)==1
    assert store.rows('SELECT incident_id FROM ai_jobs')[0]['incident_id']==ticket


def test_context_current_metrics_checks_redaction_and_missing_agent(environment):
    _,store,vault=environment;configure(store,vault);now=time.time()
    with store.connect() as c:
        c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,sampled_at,telemetry,host_info,capabilities) VALUES('a','m','private-credential',?,?,?,?,'{}')",(now,now,json.dumps({'cpu_percent':17,'custom_metric':5,'api_token':'do-not-export'}),json.dumps({'os':'Windows 2025Server'})))
        result=context(c,'m',now)
    assert result['telemetry']['fresh'] and result['telemetry']['metrics']['cpu_percent']==17
    assert result['telemetry']['metrics']['custom_metric']==5
    assert 'do-not-export' not in json.dumps(result) and 'private-credential' not in json.dumps(result)
    assert result['checks'][0]['name']=='App'
    assert context_no_agent(store)['telemetry']['fresh'] is False


def context_no_agent(store):
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('bare','Bare host',0)")
        return context(c,'bare')


def test_clock_drift_is_monitoring_issue_not_pressure(environment):
    _,store,vault=environment;configure(store,vault);now=time.time()
    with store.connect() as c:
        c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,sampled_at) VALUES('a','m','fixture',?,?)",(now,now+3600))
    assert issues(store)[0]['title']=='Clock needs attention'
    assert len(store.rows('SELECT * FROM incidents'))==1


def test_dependencies_group_only_fresh_confirmed_upstream(environment):
    _,store,vault=environment;incident=configure(store,vault);now=time.time()
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('nas','NAS',0)")
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after) VALUES('storage','nas','Storage','tcp','{}',30,1,1)")
    save(store,'Immich',['c','storage'],[('c','storage')])
    engine.observe(store,'storage',False,{'reason':'Storage unavailable'},now)
    upstream=store.rows("SELECT id FROM incidents WHERE check_id='storage'")[0]['id']
    with store.connect() as c:
        assert upstream_incident(c,incident,now)==upstream
        assert upstream_incident(c,incident,now+181) is None
    assert view(store)[0]['health']=='down'
    with pytest.raises(ValueError,match='cycle'):save(store,'Loop',['c','storage'],[('c','storage'),('storage','c')])
    bridge=store.setting('hermes_config');bridge.update(automatic=True,minimum='medium');store.save('hermes_config',bridge)
    assert ai.automatic_tick(store,vault)==1
    assert store.rows('SELECT incident_id FROM ai_jobs')[0]['incident_id']==upstream
    assert store.rows('SELECT * FROM incident_links')
    engine.observe(store,'storage',True,{'reason':'Recovered'},now+1)
    assert ai.automatic_tick(store,vault)==1
    assert len(store.rows('SELECT * FROM ai_jobs'))==2


def test_harmless_workflow_dispatch_blocks_commands_and_verifies_completion(environment):
    app,store,vault=environment;configure(store,vault,command_tools=True,incident_runs=5)
    ticket=start_test(store,vault,'m');job=store.rows('SELECT * FROM ai_jobs WHERE incident_id=?',(ticket,))[0]
    evidence=json.loads(job['evidence']);assert evidence['workflow_test'] and evidence['machine']['checks']
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job['id'],))
    client=app.test_client();headers={'Authorization':'Bearer '+vault.decrypt(job['credential'])}
    denied=client.post('/api/hermes/'+job['id']+'/command',headers=headers,json={'action':'run','id':str(uuid.uuid4()),'command':'touch /tmp/forbidden'})
    assert denied.status_code==400 and not store.rows('SELECT * FROM command_jobs')
    check=store.rows('SELECT check_id FROM incidents WHERE id=?',(ticket,))[0]['check_id']
    assert test_probe(store,check)[0] is None
    reply=client.post('/api/hermes/'+job['id']+'/command',headers=headers,json={'action':'resolve','summary':'The test reached AI and its diagnostic context was available.'})
    assert reply.status_code==200
    ai.apply_status(store,job['id'],{'execution_id':job['id'],'state':'completed','execution_mode':'codex','model':job['model'],'reasoning':job['reasoning_effort'],'summary':'Workflow test completed.'})
    healthy,evidence=test_probe(store,check);assert healthy is True
    engine.observe(store,check,healthy,evidence)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(ticket,))[0]['status']=='Resolved'
    assert not store.rows('SELECT * FROM command_jobs')

# Avoid collecting the imported probe as a pytest test.
test_probe.__test__=False


def test_repeat_budget_spans_sessions_and_keeps_diagnostics(environment):
    _,store,vault=environment;incident=configure(store,vault);job_id=ai.request_job(store,vault,incident)
    now=time.time()
    with store.connect() as c:
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('a','m','fixture')")
        for _ in range(2):
            c.execute("INSERT INTO command_jobs(id,machine_id,agent_id,incident_id,ai_job_id,command,fingerprint,policy_version,timeout,output_limit,state,created,expires) VALUES(?,'m','a',?,?,?,'fixture',1,120,8192,'failed',?,?)",(str(uuid.uuid4()),incident,job_id,vault.encrypt('systemctl restart immich'),now,now+600))
        with pytest.raises(RepairLimit):repair_budget(c,vault,job_id,command='systemctl restart immich')
        repair_budget(c,vault,job_id,command='hostname')


def test_note_presentation_hides_bookkeeping_preserves_original(environment):
    app,store,vault=environment;incident=configure(store,vault)
    raw='Docker is installed. **Closure is pending independent monitoring verification.** Once healthy monitoring is confirmed, the server will close the ticket and send the configured recovery notification. · Execution 02d585de-a9e8-49d6-94d7-7f7014b8f4a2'
    with store.connect() as c:store.timeline(c,incident,'ai_completed',raw,actor='hermes')
    assert readable(raw)=='Docker is installed.'
    assert store.rows("SELECT text FROM timeline WHERE kind='ai_completed'")[0]['text']==raw
    with app.test_client() as client:
        with client.session_transaction() as session:session.update(admin=True,csrf='fixture',auth_generation=store.setting('auth_generation'))
        page=client.get('/incidents/'+incident).get_data(as_text=True)
    conversation=page.split('<section class="ticket-conversation">')[1].split('<div class="ticket-tools">')[0]
    assert 'update-tags' in conversation and 'Session complete' in conversation
    assert 'Closure is pending' not in conversation and '02d585de' not in conversation
    assert 'Technical event history' in page and raw.replace('**','**') in page


def test_new_pages_save_edit_delete_and_validation(signed_in):
    client,store,vault,csrf=signed_in;configure(store,vault)
    assert client.get('/applications').status_code==200
    assert client.get('/monitoring-health').status_code==200
    assert client.post('/applications',data={'csrf':csrf,'name':'App','checks':'c'}).status_code==302
    identifier=store.rows('SELECT id FROM applications')[0]['id']
    assert client.get('/applications').status_code==200
    assert client.post('/applications',data={'csrf':csrf,'id':identifier,'operation':'delete'}).status_code==302
    assert not store.rows('SELECT * FROM applications')
    assert client.post('/monitoring-health',data={'csrf':csrf,'repeat_limit':0}).status_code==400


def test_cross_application_cycle_is_rejected(environment):
    _,store,vault=environment;configure(store,vault)
    with store.connect() as c:
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('other','m','Other','tcp','{}',30)")
    save(store,'First',['c','other'],[('c','other')])
    with pytest.raises(ValueError,match='cycle'):save(store,'Second',['c','other'],[('other','c')])


def test_api_failure_is_missing_telemetry_not_outage(environment):
    from aiticket.unifi import probe
    _,store,vault=environment
    snapshot={'sampled_at':time.time(),'errors':{'devices':'HTTP 404'},'readings':{},'warnings':[]}
    with patch('aiticket.unifi.refresh',return_value=snapshot):
        healthy,evidence=probe(store,vault,{'connection_id':'fixture'})
    assert healthy is None and evidence['monitoring_issue'] is True


def test_old_healthy_sample_cannot_verify_new_repair(environment):
    _,store,vault=environment;configure(store,vault)
    ticket=open_ticket(store,'m','Repair','Install a program','low');job=ai.request_job(store,vault,ticket)
    now=time.time()
    with store.connect() as c:
        report=json.loads(c.execute('SELECT report FROM incidents WHERE id=?',(ticket,)).fetchone()[0]);report['verification_requested_at']=now+10
        c.execute('UPDATE incidents SET report=? WHERE id=?',(json.dumps(report),ticket))
        c.execute("UPDATE ai_jobs SET state='completed',resolution_summary='Installed.' WHERE id=?",(job,))
        c.execute("UPDATE checks SET health='healthy' WHERE id='c'")
        c.execute("INSERT INTO observations VALUES(?,'c',?,'healthy','{}')",(str(uuid.uuid4()),now+1))
    engine.resolution_tick(store,now+11)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(ticket,))[0]['status']=='Open'
    with store.connect() as c:c.execute("INSERT INTO observations VALUES(?,'c',?,'healthy','{}')",(str(uuid.uuid4()),now+12))
    engine.resolution_tick(store,now+13)
    assert store.rows('SELECT status FROM incidents WHERE id=?',(ticket,))[0]['status']=='Resolved'


def test_workflow_fence_exists_before_first_dispatch(environment):
    _,store,vault=environment;configure(store,vault)
    def first_dispatch(store,vault,ticket):
        incident=store.rows('SELECT * FROM incidents WHERE id=?',(ticket,))[0]
        assert json.loads(incident['report'])['workflow_test']
        check=store.rows('SELECT * FROM checks WHERE id=?',(incident['check_id'],))[0]
        assert check['kind']=='workflow_test' and check['enabled']
        assert store.rows('SELECT * FROM incident_sources WHERE incident_id=?',(ticket,))
    with patch('aiticket.ai.queue_manual',side_effect=first_dispatch):start_test(store,vault,'m')
