import json
import sqlite3
import time
from unittest.mock import patch
import pytest
from aiticket import actions,ai,handoff
from aiticket.security import digest
from aiticket.engine import observe
from test_workspace import setup


def environment_setup(store,vault):
    incident,cfg=setup(store,vault)
    now=time.time()
    with store.connect() as c:
        c.execute("UPDATE machines SET recovery_role='application' WHERE id='m'")
        c.execute("UPDATE agents SET capabilities=?,last_seen=?,action_credential_digest=? WHERE id='agent'",(json.dumps({'operations':['service_status'],'services':['web'],'actions':['service_restart'],'action_services':{'web':'nginx.service'}}),now,digest('action-fixture-credential')))
        c.execute("UPDATE diagnostic_jobs SET operation='service_status',parameters=?,completed=?,result=? WHERE id='diagnostic'",(json.dumps({'service_id':'web'}),now,json.dumps({'output':'Id=nginx.service\nLoadState=loaded\nActiveState=failed'})))
    store.save('action_policy',{'enabled':True,'validated':True,'cooldown_seconds':3600,'targets':{'m':['web']}})
    handoff.pause(store,incident,handoff.view(store,incident)['generation'])
    return incident,now


def proposal(store,incident,now=None,parent=None):
    return actions.propose(store,incident,'agent','web','diagnostic','Service failed','Brief service interruption','Connections may drop','Investigate logs first',parent_id=parent,now=now)


def approve(store,identifier,now=None):
    row=store.rows('SELECT * FROM action_proposals WHERE id=?',(identifier,))[0]
    actions.decide(store,identifier,row['payload_hash'],'approve',now=now)


def dispatch(store,now):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        return actions.poll(c,store,'agent',now)


def test_disabled_policy_and_protected_targets(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    store.save('action_policy',{**actions.DEFAULTS,'targets':{'m':['web']}})
    identifier=proposal(store,incident)
    with pytest.raises(ValueError,match='disabled'): approve(store,identifier)
    assert dispatch(store,now)==[]
    with store.connect() as c: c.execute("UPDATE machines SET recovery_role='protected' WHERE id='m'")
    with pytest.raises(ValueError,match='Protected'): proposal(store,incident)


def test_hash_denial_expiry_and_immutable_payload(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now)
    with pytest.raises(ValueError,match='hash'): actions.decide(store,identifier,'wrong','approve')
    row=store.rows('SELECT * FROM action_proposals')[0]
    actions.decide(store,identifier,row['payload_hash'],'deny',now)
    assert dispatch(store,now)==[]
    with pytest.raises(ValueError): approve(store,identifier)
    next_id=proposal(store,incident,now)
    actions.tick(store,now+601)
    assert store.rows('SELECT state FROM action_proposals WHERE id=?',(next_id,))[0]['state']=='expired'
    for sql in ("UPDATE action_proposals SET payload='{}'","DELETE FROM action_proposals"):
        with pytest.raises(sqlite3.IntegrityError,match='immutable'):
            with store.connect() as c: c.execute(sql)


def test_revision_invalidates_old_approval(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    old=proposal(store,incident,now);approve(store,old,now)
    new=proposal(store,incident,now,parent=old)
    assert store.rows('SELECT state FROM action_proposals WHERE id=?',(old,))[0]['state']=='superseded'
    assert dispatch(store,now)==[]
    approve(store,new,now)
    assert dispatch(store,now)[0]['id']==new


def test_once_delivery_authorization_and_result_idempotency(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now)
    job=dispatch(store,now)[0]
    assert dispatch(store,now+1)==[]
    assert actions.authorize(store,'agent',job,now+1)['status']=='authorized'
    with pytest.raises(ValueError): actions.authorize(store,'agent',job,now+2)
    result={'id':identifier,'dispatch_token':job['dispatch_token'],'status':'completed','output':'Accepted'}
    assert actions.complete(store,'agent',result,now+2)=='accepted'
    assert actions.complete(store,'agent',result,now+3)=='duplicate'
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='verifying'
    assert store.rows('SELECT closed FROM incidents')[0]['closed'] is None


@pytest.mark.parametrize('change', ['stale','mapping','recovered','revoked','ownership','disabled'])
def test_revalidate_before_dispatch(environment,change):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now)
    with store.connect() as c:
        if change=='stale': c.execute("UPDATE agents SET last_seen=1")
        elif change=='mapping': c.execute('UPDATE agents SET capabilities=?',(json.dumps({'actions':['service_restart'],'action_services':{'web':'different.service'}}),))
        elif change=='recovered': c.execute("UPDATE incidents SET status='Resolved'")
        elif change=='revoked': c.execute('UPDATE agents SET revoked=1')
        elif change=='ownership': c.execute('UPDATE incident_control SET generation=generation+1')
    if change=='disabled': store.save('action_policy',actions.DEFAULTS)
    assert dispatch(store,now+1)==[]
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='cancelled'


def test_network_failure_is_not_service_failure(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    with store.connect() as c: c.execute('UPDATE diagnostic_jobs SET result=?',(json.dumps({'output':'Id=nginx.service\nLoadState=loaded\nActiveState=active'}),))
    with pytest.raises(ValueError,match='independent proof'): proposal(store,incident,now)


def test_unknown_delivery_never_reissues_and_one_attempt_consumed(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now);dispatch(store,now)
    actions.tick(store,now+91)
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='unknown'
    assert dispatch(store,now+92)==[]
    assert len(store.rows("SELECT * FROM audit WHERE action='action.dispatched'"))==1


def test_independent_verification_requires_post_result_samples(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now)
    job=dispatch(store,now)[0];actions.authorize(store,'agent',job,now+1)
    actions.complete(store,'agent',{'id':identifier,'dispatch_token':job['dispatch_token'],'status':'completed','output':'Accepted'},now+2)
    actions.tick(store,now+3)
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='verifying'
    with store.connect() as c:
        c.execute('UPDATE diagnostic_jobs SET completed=?,result=?',(now+4,json.dumps({'output':'Id=nginx.service\nLoadState=loaded\nActiveState=active'})))
    observe(store,'c',True,{},now=now+5);observe(store,'c',True,{},now=now+6)
    actions.tick(store,now+7)
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='verified'
    assert len(store.rows("SELECT * FROM timeline WHERE kind='action_verified'"))==1


def test_monitoring_credential_cannot_authorize_action(signed_in):
    client,store,vault,csrf=signed_in
    incident,now=environment_setup(store,vault)
    with store.connect() as c: c.execute('UPDATE agents SET credential_digest=?',(digest('monitor-fixture'),))
    identifier=proposal(store,incident,now);approve(store,identifier,now);job=dispatch(store,now)[0]
    assert client.post('/api/agent/action-authorize',json=job,headers={'Authorization':'Bearer monitor-fixture'}).status_code==401
    assert client.post('/api/agent/action-authorize',json=job,headers={'Authorization':'Bearer action-fixture-credential'}).status_code==200
    assert client.get('/recovery-policy').status_code==200
    assert client.get('/incidents/'+incident).status_code==200
    assert client.post('/proposals/'+identifier+'/decide',data={'decision':'approve'}).status_code==403


def test_cancel_approved_and_recheck_before_agent_execution(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now)
    row=store.rows('SELECT * FROM action_proposals')[0]
    actions.decide(store,identifier,row['payload_hash'],'cancel',now)
    assert dispatch(store,now)==[]
    next_id=proposal(store,incident,now);approve(store,next_id,now)
    job=dispatch(store,now)[0]
    store.save('action_policy',actions.DEFAULTS)
    with pytest.raises(ValueError,match='disabled'): actions.authorize(store,'agent',job,now+1)


def test_one_attempt_blocks_next_proposal_even_after_failure(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    first=proposal(store,incident,now);approve(store,first,now)
    job=dispatch(store,now)[0];actions.authorize(store,'agent',job,now+1)
    actions.complete(store,'agent',{'id':first,'dispatch_token':job['dispatch_token'],'status':'failed','output':'Failure'},now+2)
    second=proposal(store,incident,now);approve(store,second,now)
    assert dispatch(store,now+3)==[]
    assert store.rows('SELECT state FROM action_proposals WHERE id=?',(second,))[0]['state']=='cancelled'


def test_unknown_can_clear_target_lock_only_with_independent_recovery(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now);dispatch(store,now)
    actions.tick(store,now+91)
    with store.connect() as c:
        c.execute('UPDATE diagnostic_jobs SET completed=?,result=?',(now+92,json.dumps({'output':'Id=nginx.service\nLoadState=loaded\nActiveState=active'})))
    observe(store,'c',True,{},now=now+93);observe(store,'c',True,{},now=now+94)
    actions.tick(store,now+95)
    assert store.rows('SELECT state FROM action_proposals')[0]['state']=='recovered_outcome_unknown'
    assert json.loads(store.rows('SELECT verification FROM action_proposals')[0]['verification'])['execution_outcome']=='unknown'


def test_ai_resume_blocked_by_outstanding_recovery(environment):
    _,store,vault=environment
    incident,now=environment_setup(store,vault)
    identifier=proposal(store,incident,now);approve(store,identifier,now)
    state=handoff.view(store,incident)
    with pytest.raises(ValueError,match='outstanding'):
        handoff.resume(store,vault,incident,state['checkpoint_id'],state['generation'],__import__('uuid').uuid4().hex)
