import json
import sqlite3
from unittest.mock import patch
import pytest
from aiticket import ai,actions,handoff
from aiticket.db import uid
from aiticket.recovery_drafts import request_draft,adopt
from aiticket.hermes_runner import execute
from test_actions import environment_setup,dispatch
from test_workspace import finish
from test_hermes_bridge import FakeAgent,envelope


def setup_draft(store,vault):
    incident,now=environment_setup(store,vault)
    store.save('hermes_validation',{'workspace_modes':['advice','exploration','recovery_proposal']})
    return incident,now


def text(**changes):
    return {'rationale':'Exact service is reported failed; cause remains uncertain.','impact':'Brief application interruption.','risk':'Existing connections may drop.','alternatives':'Review logs and involve the administrator.',**changes}


def request(store,vault,incident,identity=None):
    return request_draft(store,vault,incident,'agent','web','diagnostic',identity or uid())


def test_budgeted_bound_draft_requires_user_review_and_separate_approval(environment):
    _,store,vault=environment
    incident,now=setup_draft(store,vault)
    identity=uid()
    with patch('aiticket.ai.requests.post') as network:
        job=request(store,vault,incident,identity)
        assert request(store,vault,incident,identity)==job
        network.assert_not_called()
    document=json.loads(store.rows('SELECT evidence FROM ai_jobs WHERE id=?',(job,))[0]['evidence'])
    assert document['recovery_target']['unit']=='nginx.service'
    assert document['diagnostics'][0]['id']=='diagnostic'
    assert not store.rows('SELECT * FROM action_proposals')
    finish(store,job,store.setting('ai_config'),json.dumps(text()))
    assert len(store.rows('SELECT * FROM recovery_drafts'))==1
    assert ai.meter(store,incident)['incident']['tokens']>0
    with pytest.raises(ValueError,match='manual control'):
        adopt(store,incident,job)
    handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    proposal=adopt(store,incident,job)
    assert adopt(store,incident,job)==proposal
    row=store.rows('SELECT * FROM action_proposals')[0]
    assert row['state']=='awaiting'
    payload=json.loads(row['payload'])
    assert payload['origin']['job_id']==job and payload['parameters']=={'service_id':'web','unit':'nginx.service'}
    assert dispatch(store,now)==[]
    with pytest.raises(ValueError,match='hash'):
        actions.decide(store,proposal,'wrong','approve')
    actions.decide(store,proposal,row['payload_hash'],'approve')
    assert len(dispatch(store,now+1))==1
    with pytest.raises(sqlite3.IntegrityError,match='immutable'):
        with store.connect() as c: c.execute("UPDATE recovery_drafts SET payload='{}'")


@pytest.mark.parametrize('summary',['not JSON',json.dumps(text(action='shell')),json.dumps(text(risk='')),json.dumps(text(rationale='x'*1001))])
def test_malformed_or_authority_changing_drafts_fail_closed(environment,summary):
    _,store,vault=environment
    incident,_=setup_draft(store,vault)
    job=request(store,vault,incident)
    finish(store,job,store.setting('ai_config'),summary)
    assert store.rows('SELECT state FROM ai_jobs')[0]['state']=='failed'
    assert not store.rows('SELECT * FROM recovery_drafts') and not store.rows('SELECT * FROM action_proposals')
    assert ai.meter(store,incident)['incident']['tokens']>0


def test_stale_mapping_and_protected_targets_rechecked(environment):
    _,store,vault=environment
    incident,now=setup_draft(store,vault)
    job=request(store,vault,incident)
    finish(store,job,store.setting('ai_config'),json.dumps(text()))
    handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    with store.connect() as c:
        caps=json.loads(c.execute("SELECT capabilities FROM agents WHERE id='agent'").fetchone()[0])
        caps['action_services']['web']='other.service'
        c.execute("UPDATE agents SET capabilities=? WHERE id='agent'",(json.dumps(caps),))
    with pytest.raises(ValueError,match='mapping changed'): adopt(store,incident,job)
    with store.connect() as c: c.execute("UPDATE machines SET recovery_role='protected'")
    with pytest.raises(ValueError,match='Protected'): request(store,vault,incident)
    assert not store.rows('SELECT * FROM action_proposals')


def test_cancelled_completion_cannot_create_draft(environment):
    _,store,vault=environment
    incident,_=setup_draft(store,vault)
    job=request(store,vault,incident)
    with store.connect() as c: c.execute("UPDATE ai_jobs SET state='running'")
    ai.cancel(store,job)
    ai.apply_status(store,job,{'execution_id':job,'state':'completed','summary':json.dumps(text())})
    assert not store.rows('SELECT * FROM recovery_drafts')


def test_disabled_ai_or_missing_companion_capability_no_job(environment):
    _,store,vault=environment
    incident,_=setup_draft(store,vault)
    store.save('hermes_validation',{'workspace_modes':['advice','exploration']})
    with pytest.raises(ValueError,match='companion'): request(store,vault,incident)
    store.save('hermes_config',{**store.setting('hermes_config'),'enabled':False})
    with pytest.raises(ValueError,match='disabled'): request(store,vault,incident)
    assert not store.rows('SELECT * FROM ai_jobs')


def test_adapter_prompt_has_no_approval_or_execution_authority():
    class DraftAgent(FakeAgent):
        def run_conversation(self,prompt):
            assert 'exactly four string fields' in prompt and 'cannot approve or execute recovery' in prompt
            assert self.options['enabled_toolsets']==[]
            return {'completed':True,'final_response':json.dumps(text())}
    job=envelope()
    job['evidence']=json.dumps({'format':'aiticket-workspace','version':1,'mode':'recovery_proposal','recovery_target':{'unit':'nginx.service'}})
    assert execute(DraftAgent,job,'https://192.0.2.10')['state']=='completed'


def test_draft_ui_review_and_incident_binding(signed_in):
    client,store,vault,csrf=signed_in
    incident,_=setup_draft(store,vault)
    data={'csrf':csrf,'agent_id':'agent','service_id':'web','diagnostic_id':'diagnostic','request_id':uid()}
    assert client.post('/incidents/'+incident+'/recovery-draft',data=data).status_code==302
    job=store.rows('SELECT id FROM ai_jobs')[0]['id']
    finish(store,job,store.setting('ai_config'),json.dumps(text()))
    handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    url='/incidents/'+incident+'/recovery-draft/'+job+'/adopt'
    assert client.post(url,data={'csrf':csrf}).status_code==400
    assert b'Unverified AI draft' in client.get('/incidents/'+incident).data
    assert client.post(url,data={'csrf':csrf,'reviewed':'yes'}).status_code==302
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='awaiting'
    with pytest.raises(ValueError): adopt(store,'other-incident',job)


def test_concurrent_adoption_creates_one_proposal_and_recovered_precondition_denied(environment):
    from concurrent.futures import ThreadPoolExecutor
    _,store,vault=environment
    incident,_=setup_draft(store,vault)
    job=request(store,vault,incident)
    finish(store,job,store.setting('ai_config'),json.dumps(text()))
    handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    with store.connect() as c:
        c.execute("UPDATE diagnostic_jobs SET result=? WHERE id='diagnostic'",(json.dumps({'output':'Id=nginx.service\nLoadState=loaded\nActiveState=active'}),))
    with pytest.raises(ValueError): adopt(store,incident,job)
    assert not store.rows('SELECT * FROM action_proposals')
    with store.connect() as c:
        c.execute("UPDATE diagnostic_jobs SET result=? WHERE id='diagnostic'",(json.dumps({'output':'Id=nginx.service\nLoadState=loaded\nActiveState=failed'}),))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:adopt(store,incident,job),range(2)))
    assert results[0]==results[1] and len(store.rows('SELECT * FROM action_proposals'))==1
