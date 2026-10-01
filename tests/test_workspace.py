import json
import sqlite3
import time
from unittest.mock import patch
import pytest
from aiticket import ai
from aiticket.db import uid
from test_ai import configured,payload
from test_hermes_bridge import FakeAgent,envelope
from aiticket.hermes_runner import execute


def setup(store,vault):
    incident,cfg=configured(store,vault)
    store.save('hermes_validation',{'workspace_modes':['advice','exploration']})
    with store.connect() as c:
        c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('agent','m','fixture-digest')")
        c.execute("INSERT INTO diagnostic_jobs(id,agent_id,incident_id,operation,parameters,state,created,expires,result,completed) VALUES('diagnostic','agent',?,'process_summary','{}','completed',1,99999999999,?,2)",(incident,json.dumps({'output':'nginx running token=must-redact'})))
    return incident,cfg


def request(store,vault,incident,**kwargs):
    return ai.request_job(store,vault,incident,mode='advice',question='What does the evidence suggest?',request_id=uid(),**kwargs)


def finish(store,job,cfg,summary='An uncertain hypothesis'):
    with store.connect() as c:
        c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    call,_,_,_=ai.admit(store,job,payload())
    ai.reconcile(store,call,{'prompt_tokens':20,'completion_tokens':10},cfg)
    ai.apply_status(store,job,{'execution_id':job,'state':'completed','summary':summary})


def test_scoped_selected_context_redacted_and_no_network(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    with patch('aiticket.ai.requests.post') as network:
        job=request(store,vault,incident,source_ids=['c'],diagnostic_ids=['diagnostic'])
        network.assert_not_called()
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0]
    context=json.loads(row['evidence'])
    assert context['mode']=='advice' and context['sources'][0]['id']=='c'
    assert context['diagnostics'][0]['id']=='diagnostic'
    assert 'must-redact' not in row['evidence']
    assert len(store.rows("SELECT * FROM timeline WHERE kind='ai_question'"))==1


def test_unselected_outputs_are_excluded(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    job=request(store,vault,incident)
    context=json.loads(store.rows('SELECT evidence FROM ai_jobs')[0]['evidence'])
    assert context['sources']==[] and context['diagnostics']==[]
    assert 'nginx' not in json.dumps(context)


def test_duplicate_submission_no_extra_message_and_changed_payload_rejected(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    identity=uid()
    args=dict(mode='advice',question='Explain this',request_id=identity)
    job=ai.request_job(store,vault,incident,**args)
    assert ai.request_job(store,vault,incident,**args)==job
    assert len(store.rows('SELECT * FROM ai_messages'))==1
    with pytest.raises(ValueError,match='different'):
        ai.request_job(store,vault,incident,**{**args,'question':'Changed'})
    with pytest.raises(ValueError,match='already active'):
        request(store,vault,incident)


@pytest.mark.parametrize('selected', [{'source_ids':['foreign']},{'diagnostic_ids':['foreign']},{'source_ids':['c','c']},{'diagnostic_ids':['diagnostic']*4}])
def test_foreign_or_invalid_selection_rolls_back(environment,selected):
    _,store,vault=environment
    incident,_=setup(store,vault)
    with pytest.raises(ValueError):
        request(store,vault,incident,**selected)
    assert not store.rows('SELECT * FROM ai_messages')
    assert not store.rows('SELECT * FROM ai_jobs')


def test_pending_diagnostic_cannot_be_context(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    with store.connect() as c:
        c.execute("UPDATE diagnostic_jobs SET state='pending' WHERE id='diagnostic'")
    with pytest.raises(ValueError):
        request(store,vault,incident,diagnostic_ids=['diagnostic'])


def test_reply_and_history_durable_immutable_and_duplicate_safe(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    job=request(store,vault,incident)
    finish(store,job,cfg,'First hypothesis')
    ai.apply_status(store,job,{'execution_id':job,'state':'completed','summary':'duplicate'})
    assert len(store.rows('SELECT * FROM ai_messages'))==2
    second=request(store,vault,incident)
    context=json.loads(store.rows('SELECT evidence FROM ai_jobs WHERE id=?',(second,))[0]['evidence'])
    assert context['conversation'][0]['answer']=='First hypothesis'
    for statement in ('DELETE FROM ai_messages','UPDATE ai_messages SET text=\'edited\''):
        with pytest.raises(sqlite3.IntegrityError,match='immutable'):
            with store.connect() as c: c.execute(statement)


def test_advice_uses_incident_ceiling_not_triage_allowance(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    store.save('ai_config',{**cfg,'triage_tokens':1})
    job=request(store,vault,incident)
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    ai.admit(store,job,payload())
    assert ai.meter(store)['held']==1


def test_modes_share_cumulative_incident_allowance(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    first=request(store,vault,incident)
    finish(store,first,cfg)
    second=ai.request_job(store,vault,incident,mode='exploration',question='Explore these results',request_id=uid())
    store.save('ai_config',{**cfg,'incident_tokens':31})
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(second,))
    with pytest.raises(ValueError,match='allowance'): ai.admit(store,second,payload())


def test_legacy_bridge_does_not_support_workspace(environment):
    _,store,vault=environment
    incident,_=setup(store,vault)
    store.save('hermes_validation',{'workspace_modes':[]})
    with pytest.raises(ValueError,match='companion'):
        request(store,vault,incident)


def test_workspace_post_auth_csrf_and_render(signed_in):
    client,store,vault,csrf=signed_in
    incident,_=setup(store,vault)
    url='/incidents/'+incident+'/workspace'
    data={'mode':'advice','question':'Explain this','request_id':uid()}
    assert client.post(url,data=data).status_code==403
    assert client.post(url,data={**data,'csrf':csrf}).status_code==302
    page=client.get('/incidents/'+incident)
    assert page.status_code==200 and b'Explain this' in page.data
    assert client.post(url,data={**data,'csrf':csrf}).status_code==302
    assert len(store.rows('SELECT * FROM ai_messages'))==1


def test_runner_workspace_does_not_execute_diagnostics():
    class WorkspaceAgent(FakeAgent):
        def run_conversation(self,prompt):
            assert 'Do not execute commands' in prompt
            assert 'selected evidence' in prompt
            assert 'diagnostic-id' in prompt
            return {'completed':True,'final_response':'Read-only analysis'}
    job=envelope()
    job['evidence']=json.dumps({'format':'aiticket-workspace','version':1,'mode':'exploration','diagnostics':[{'id':'diagnostic-id','output':'untrusted'}]})
    assert execute(WorkspaceAgent,job,'https://192.0.2.10')['summary']=='Read-only analysis'


def test_zero_triage_still_allows_budgeted_advice(environment):
    _,store,vault=environment
    incident,cfg=setup(store,vault)
    store.save('ai_config',{**cfg,'triage_tokens':0})
    with pytest.raises(ValueError): ai.request_job(store,vault,incident)
    job=request(store,vault,incident)
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    ai.admit(store,job,payload())


def test_schema_eight_upgrade_preserves_prior_ai_jobs(tmp_path):
    from aiticket.db import SCHEMA,Store
    from aiticket.migrations import MIGRATIONS
    path=tmp_path/'eight.db'
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        for version in range(2,9):
            for statement in MIGRATIONS[version]: c.execute(statement)
        c.execute('INSERT INTO schema_version VALUES(8)')
        c.execute("INSERT INTO machines(id,name,parent_id,created) VALUES('m','Machine',NULL,1)")
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES('c','m','Check','http','{}',60)")
        c.execute("INSERT INTO incidents(id,machine_id,check_id,severity,status,first_seen,last_seen,report) VALUES('i','m','c','high','Open',1,2,'{}')")
        c.execute("INSERT INTO ai_jobs(id,incident_id,state,created,expires,model,allowance,max_calls,evidence,credential_digest,credential,endpoint,bridge_secret,next_attempt) VALUES('j','i','completed',1,2,'model',100,1,'{}','digest','encrypted','https://192.0.2.20','encrypted',1)")
    store=Store(path)
    assert store.rows('SELECT mode FROM ai_jobs')==[{'mode':'triage'}]
    assert store.rows('SELECT version FROM schema_version')==[{'version': __import__('aiticket.migrations',fromlist=['CURRENT_VERSION']).CURRENT_VERSION}]
