import concurrent.futures
import json
import sqlite3
import time
from unittest.mock import patch
import pytest
from aiticket import ai,handoff
from aiticket.db import uid
from aiticket.diagnostics import request_job as diagnostic
from test_workspace import setup,request,finish
from test_ai import payload


def test_pause_fences_existing_and_new_calls_and_saves_checkpoint(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    job=request(store,vault,incident,source_ids=['c'],diagnostic_ids=['diagnostic'])
    state=handoff.view(store,incident)
    checkpoint=handoff.pause(store,incident,state['generation'])
    assert store.rows('SELECT state FROM ai_jobs')[0]['state']=='cancelled'
    state=handoff.view(store,incident)
    assert state['owner']=='user' and state['checkpoint_id']==checkpoint
    assert state['checkpoint']['data']['source_ids']==['c']
    with pytest.raises(ValueError): ai.admit(store,job,payload())
    with pytest.raises(ValueError,match='User has control'): request(store,vault,incident)
    assert ai.request_job(store,vault,incident,automatic=True) is None
    ai.apply_status(store,job,{'execution_id':job,'state':'failed','summary':'late'})
    assert handoff.view(store,incident)['owner']=='user'


def test_resume_new_job_current_evidence_and_duplicate_safe(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    job=request(store,vault,incident,source_ids=['c'])
    state=handoff.view(store,incident)
    checkpoint=handoff.pause(store,incident,state['generation'])
    with store.connect() as c:
        report=json.loads(c.execute('SELECT report FROM incidents WHERE id=?',(incident,)).fetchone()[0])
        report['cause']='Updated evidence'
        c.execute('UPDATE incidents SET report=? WHERE id=?',(json.dumps(report),incident))
    state=handoff.view(store,incident)
    identity=uid()
    resumed=handoff.resume(store,vault,incident,checkpoint,state['generation'],identity)
    assert resumed!=job
    context=json.loads(store.rows('SELECT evidence FROM ai_jobs WHERE id=?',(resumed,))[0]['evidence'])
    assert context['checkpoint']['id']==checkpoint
    assert context['facts']['cause']=='Updated evidence'
    assert handoff.resume(store,vault,incident,checkpoint,state['generation'],identity)==resumed
    assert handoff.view(store,incident)['owner']=='ai'
    assert len(store.rows('SELECT * FROM ai_jobs'))==2


def test_stale_control_version_rejected_and_pause_idempotent(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    state=handoff.view(store,incident)
    checkpoint=handoff.pause(store,incident,state['generation'])
    with pytest.raises(ValueError,match='changed'):
        handoff.pause(store,incident,state['generation'])
    current=handoff.view(store,incident)
    assert handoff.pause(store,incident,current['generation'])==checkpoint
    assert len(store.rows('SELECT * FROM handoff_checkpoints'))==1
    with pytest.raises(ValueError): handoff.resume(store,vault,incident,checkpoint,state['generation'],uid())


def test_unknown_usage_survives_pause_and_blocks_resume_calls(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    job=request(store,vault,incident)
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    ai.admit(store,job,payload())
    state=handoff.view(store,incident)
    checkpoint=handoff.pause(store,incident,state['generation'])
    state=handoff.view(store,incident)
    assert 'Unknown API model usage' in state['waiting']
    resumed=handoff.resume(store,vault,incident,checkpoint,state['generation'],uid())
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(resumed,))
    with pytest.raises(ValueError,match='unknown usage'): ai.admit(store,resumed,payload())
    assert ai.meter(store)['held']==1


def test_generation_blocks_old_request_even_if_state_wrongly_reactivated(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    job=request(store,vault,incident)
    state=handoff.view(store,incident)
    handoff.pause(store,incident,state['generation'])
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    with pytest.raises(ValueError,match='ownership'): ai.admit(store,job,payload())


def test_diagnostics_cannot_overlap_ai_investigation(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    with store.connect() as c:
        c.execute('UPDATE agents SET capabilities=? WHERE id=\'agent\'',(json.dumps({'operations':['process_summary']}),))
    job=request(store,vault,incident)
    with pytest.raises(ValueError,match='take control'): diagnostic(store,'agent',incident,'process_summary')
    state=handoff.view(store,incident)
    checkpoint=handoff.pause(store,incident,state['generation'])
    diagnostic(store,'agent',incident,'process_summary')
    state=handoff.view(store,incident)
    with pytest.raises(ValueError,match='queued diagnostics'): handoff.resume(store,vault,incident,checkpoint,state['generation'],uid())
    assert handoff.view(store,incident)['owner']=='user'


def test_terminal_completion_releases_control_but_not_new_generation(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    job=request(store,vault,incident)
    finish(store,job,cfg)
    assert handoff.view(store,incident)['owner']=='available'
    handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    ai.apply_status(store,job,{'execution_id':job,'state':'completed','summary':'late duplicate'})
    assert handoff.view(store,incident)['owner']=='user'


def test_checkpoint_immutable_and_disabled_resume_rolls_back(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    checkpoint=handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    state=handoff.view(store,incident)
    bridge=store.setting('hermes_config');bridge['enabled']=False;store.save('hermes_config',bridge)
    with pytest.raises(ValueError): handoff.resume(store,vault,incident,checkpoint,state['generation'],uid())
    assert handoff.view(store,incident)['owner']=='user'
    for sql in ('DELETE FROM handoff_checkpoints','UPDATE handoff_checkpoints SET snapshot=\'{}\''):
        with pytest.raises(sqlite3.IntegrityError,match='immutable'):
            with store.connect() as c: c.execute(sql)


def test_ui_handoff_csrf_and_manual_resolution_atomic(signed_in):
    client,store,vault,csrf=signed_in
    incident,_=setup(store,vault)
    request(store,vault,incident)
    state=handoff.view(store,incident)
    route='/incidents/'+incident+'/handoff'
    assert client.post(route,data={'operation':'pause','generation':state['generation']}).status_code==403
    assert client.get('/incidents/'+incident).status_code==200
    assert client.post('/incidents/'+incident+'/note',data={'csrf':csrf,'operation':'resolve','note':'User resolution'}).status_code==302
    assert handoff.view(store,incident)['owner']=='user'
    assert store.rows('SELECT state FROM ai_jobs')[0]['state']=='cancelled'


def test_concurrent_pause_and_queue_leave_one_owner(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    state=handoff.view(store,incident)
    def pause():
        try: handoff.pause(store,incident,state['generation'])
        except ValueError: pass
    def queue():
        try: request(store,vault,incident)
        except ValueError: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda f:f(),[pause,queue]))
    final=handoff.view(store,incident)
    active=store.rows("SELECT * FROM ai_jobs WHERE state IN ('pending','dispatching','running','unknown')")
    assert (final['owner']=='user' and not active) or (final['owner']=='ai' and len(active)==1)


def test_restart_preserves_user_control_and_checkpoint(environment):
    from aiticket.db import Store
    _,store,vault=environment
    incident,_=setup(store,vault)
    checkpoint=handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    recovered=Store(store.path)
    state=handoff.view(recovered,incident)
    assert state['owner']=='user' and state['checkpoint_id']==checkpoint
    assert state['checkpoint']['data']['version']==1


def test_schema_nine_upgrade_preserves_active_ai_ownership(tmp_path):
    from aiticket.db import Store,SCHEMA
    from aiticket.migrations import MIGRATIONS
    path=tmp_path/'nine.db'
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        for version in range(2,10):
            for statement in MIGRATIONS[version]: c.execute(statement)
        c.execute('INSERT INTO schema_version VALUES(9)')
        c.execute("INSERT INTO machines(id,name,parent_id,created) VALUES('m','Machine',NULL,1)")
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('c','m','Check','http','{}',60)")
        c.execute("INSERT INTO incidents(id,machine_id,check_id,severity,status,first_seen,last_seen,report) VALUES('i','m','c','high','Open',1,2,'{}')")
        c.execute("INSERT INTO ai_jobs(id,incident_id,state,created,expires,model,allowance,max_calls,evidence,credential_digest,credential,endpoint,bridge_secret,next_attempt) VALUES('j','i','pending',1,2,'model',100,1,'{}','digest','encrypted','https://192.0.2.20','encrypted',1)")
    store=Store(path)
    assert store.rows('SELECT version FROM schema_version')==[{'version': __import__('aiticket.migrations',fromlist=['CURRENT_VERSION']).CURRENT_VERSION}]
    assert handoff.view(store,'i')['owner']=='ai'
    assert store.rows('SELECT control_generation FROM ai_jobs')==[{'control_generation':0}]


def test_resumed_current_task_overrides_generic_history_and_is_idempotent(environment):
    from test_codex_mode import configure
    _,store,vault=environment
    incident=configure(store,vault,command_tools=True)
    checkpoint=handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    state=handoff.view(store,incident);identity=uid()
    task='Execute id; hostname; uptime now and report actual output.'
    resumed=handoff.resume(store,vault,incident,checkpoint,state['generation'],identity,current_task=task)
    evidence=json.loads(store.rows('SELECT evidence FROM ai_jobs WHERE id=?',(resumed,))[0]['evidence'])
    assert evidence['administrator_task']==task and evidence['question']==task
    assert evidence['checkpoint']['id']==checkpoint
    assert handoff.resume(store,vault,incident,checkpoint,state['generation'],identity,current_task=task)==resumed
    with pytest.raises(ValueError,match='different parameters'):
        handoff.resume(store,vault,incident,checkpoint,state['generation'],identity,current_task='Different task')


def test_checkpoint_preserves_operational_triage_task(environment):
    from test_codex_mode import configure
    _,store,vault=environment;incident=configure(store,vault,command_tools=True)
    with store.connect() as c:
        report=json.loads(c.execute('SELECT report FROM incidents WHERE id=?',(incident,)).fetchone()[0])
        report.update(manual_ticket=True,description='Execute id and inspect the linked VM.')
        c.execute('UPDATE incidents SET report=? WHERE id=?',(json.dumps(report),incident))
    ai.request_job(store,vault,incident)
    checkpoint=handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    assert handoff.view(store,incident)['checkpoint']['data']['question']=='Execute id and inspect the linked VM.'
