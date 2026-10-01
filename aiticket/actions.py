"""Default-deny, once-approved service restart broker; no shell or host reboot."""
import hashlib
import json
import secrets
import time
from .db import uid
from .diagnostics import redact
from .handoff import control

DEFAULTS = {'enabled': False, 'validated': False, 'cooldown_seconds': 3600, 'targets': {}}
ACTIVE = ('dispatched', 'authorized', 'verifying', 'unknown')


def policy(c):
    row=c.execute("SELECT value FROM settings WHERE key='action_policy'").fetchone()
    return json.loads(row[0]) if row else DEFAULTS


def proof(c, incident_id, agent_id, service_id, unit, diagnostic_id, now):
    row=c.execute("SELECT * FROM diagnostic_jobs WHERE id=? AND incident_id=? AND agent_id=? AND operation='service_status' AND state='completed'",(diagnostic_id,incident_id,agent_id)).fetchone()
    if not row or not row['completed'] or not 0<=now-row['completed']<=180 or json.loads(row['parameters']).get('service_id')!=service_id:
        raise ValueError('A fresh completed service-status diagnostic is required.')
    output=json.loads(row['result'] or '{}').get('output','')
    properties=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
    if properties.get('Id')!=unit or properties.get('LoadState')!='loaded' or properties.get('ActiveState')!='failed':
        raise ValueError('Service restart requires independent proof of this exact loaded, failed unit; network failure alone is insufficient.')


def eligible(c, incident_id, agent_id, service_id, now, require_enabled=True):
    cfg=policy(c)
    if require_enabled and (not cfg.get('enabled') or not cfg.get('validated')):
        raise ValueError('Recovery execution is disabled or unvalidated.')
    incident=c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
    agent=c.execute('SELECT * FROM agents WHERE id=? AND revoked=0',(agent_id,)).fetchone()
    if not incident or incident['closed'] is not None or incident['status']=='Resolved' or not agent or agent['machine_id']!=incident['machine_id']:
        raise ValueError('Action target must be the enrolled agent of an active incident.')
    machine=c.execute('SELECT * FROM machines WHERE id=?',(incident['machine_id'],)).fetchone()
    if machine['recovery_role']!='application' or c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND kind IN ('node','storage')",(machine['id'],)).fetchone():
        raise ValueError('Protected infrastructure is excluded from recovery.')
    if service_id not in cfg.get('targets',{}).get(machine['id'],[]):
        raise ValueError('Machine/service is not explicitly allowed for recovery.')
    caps=json.loads(agent['capabilities'])
    unit=caps.get('action_services',{}).get(service_id)
    if 'service_restart' not in caps.get('actions',[]) or not unit or not agent['action_credential_digest']:
        raise ValueError('Agent has no locally enabled service-restart capability.')
    if not agent['last_seen'] or not 0<=now-agent['last_seen']<=180:
        raise ValueError('Agent heartbeat is stale.')
    if control(c,incident_id)['owner']!='user':
        raise ValueError('Take manual control before proposing or executing recovery.')
    return incident,agent,unit,cfg


def propose(store, incident_id, agent_id, service_id, diagnostic_id, rationale, impact, risk, alternatives, parent_id=None, now=None, draft_job_id=None):
    now=time.time() if now is None else now
    texts=[rationale,impact,risk,alternatives]
    if any(not isinstance(t,str) or not 1<=len(t.strip())<=1000 for t in texts):
        raise ValueError('Supply rationale, impact, risk and alternatives (1–1000 characters each).')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        draft_data=None
        if draft_job_id:
            previous=c.execute('SELECT proposal_id FROM draft_adoptions WHERE job_id=?',(draft_job_id,)).fetchone()
            if previous:
                existing=c.execute('SELECT incident_id FROM action_proposals WHERE id=?',(previous[0],)).fetchone()
                if existing[0]!=incident_id:
                    raise ValueError('Draft belongs to another incident.')
                return previous[0]
            draft=c.execute("SELECT d.* FROM recovery_drafts d JOIN ai_jobs j ON j.id=d.job_id WHERE d.job_id=? AND d.incident_id=? AND j.state='completed'",(draft_job_id,incident_id)).fetchone()
            if not draft or now-draft['created']>600:
                raise ValueError('Draft is missing or stale; request a new draft with fresh evidence.')
            draft_data=json.loads(draft['payload'])
            target=draft_data['target']
            if (target['agent_id'],target['service_id'],target['diagnostic_id'])!=(agent_id,service_id,diagnostic_id) or [draft_data['texts'][k] for k in ('rationale','impact','risk','alternatives')]!=texts:
                raise ValueError('Draft target or text changed; create a separate manual proposal for revisions.')
        incident,agent,unit,cfg=eligible(c,incident_id,agent_id,service_id,now,require_enabled=False)
        if draft_data and draft_data['target']['unit']!=unit:
            raise ValueError('Service mapping changed; request a new draft.')
        proof(c,incident_id,agent_id,service_id,unit,diagnostic_id,now)
        version=1
        if parent_id:
            parent=c.execute('SELECT * FROM action_proposals WHERE id=? AND incident_id=?',(parent_id,incident_id)).fetchone()
            if not parent or parent['state'] not in ('awaiting','approved','denied','expired','cancelled','superseded'):
                raise ValueError('Only an unexecuted proposal can be revised.')
            version=parent['version']+1
            c.execute("UPDATE action_proposals SET state='superseded' WHERE id=?",(parent_id,))
        identifier=uid()
        document={'version':version,'incident_id':incident_id,'machine_id':incident['machine_id'],'agent_id':agent_id,'action':'service_restart','parameters':{'service_id':service_id,'unit':unit},'precondition_diagnostic':diagnostic_id,'rationale':redact(rationale.strip()),'impact':redact(impact.strip()),'risk':redact(risk.strip()),'alternatives':redact(alternatives.strip()),'verification':{'check_id':incident['check_id'],'method':'New service-status diagnostic plus fresh healthy incident sources after execution; no AI assertion proves recovery.'},'budget_impact':'No model call; one recovery attempt.','expires':now+600}
        if draft_data:
            document['origin']=draft_data['origin']
            document['budget_impact']='AI drafting is recorded in the incident usage ledger; execution makes no model call.'
        payload=json.dumps(document,sort_keys=True,separators=(',',':'))
        fingerprint=hashlib.sha256(payload.encode()).hexdigest()
        c.execute("INSERT INTO action_proposals(id,incident_id,agent_id,version,parent_id,payload,payload_hash,state,created,expires) VALUES(?,?,?,?,?,?,?,'awaiting',?,?)",(identifier,incident_id,agent_id,version,parent_id,payload,fingerprint,now,now+600))
        store.timeline(c,incident_id,'action_proposed','Service restart proposed for '+unit+' · Proposal '+identifier+' · Hash '+fingerprint,actor='user',now=now)
        if draft_job_id:
            c.execute('INSERT INTO draft_adoptions VALUES(?,?)',(draft_job_id,identifier))
        store.audit(c,'action.proposed',identifier,{'payload_hash':fingerprint,'version':version})
        return identifier


def decide(store, proposal_id, fingerprint, decision, now=None):
    now=time.time() if now is None else now
    if decision not in ('approve','deny','cancel'):
        raise ValueError('Choose Approve Once, Deny or Cancel.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM action_proposals WHERE id=?',(proposal_id,)).fetchone()
        if not row or not secrets.compare_digest(row['payload_hash'],str(fingerprint)):
            raise ValueError('Proposal hash changed; reload before deciding.')
        if row['state'] not in (('awaiting','approved') if decision=='cancel' else ('awaiting',)) or row['expires']<=now:
            raise ValueError('Proposal is no longer awaiting a valid decision.')
        data=json.loads(row['payload'])
        if decision=='approve':
            eligible(c,row['incident_id'],row['agent_id'],data['parameters']['service_id'],now)
            proof(c,row['incident_id'],row['agent_id'],data['parameters']['service_id'],data['parameters']['unit'],data['precondition_diagnostic'],now)
        generation=control(c,row['incident_id'])['generation']
        state={'approve':'approved','deny':'denied','cancel':'cancelled'}[decision]
        c.execute('UPDATE action_proposals SET state=?,approved_generation=? WHERE id=?',(state,generation if decision=='approve' else None,proposal_id))
        store.audit(c,'action.'+state,proposal_id,{'payload_hash':fingerprint})
        store.timeline(c,row['incident_id'],'action_'+state,'Proposal '+proposal_id+' · Hash '+fingerprint,actor='user',now=now)


def validate_execution(c,row,now):
    data=json.loads(row['payload'])
    incident,agent,unit,cfg=eligible(c,row['incident_id'],row['agent_id'],data['parameters']['service_id'],now)
    if unit!=data['parameters']['unit'] or control(c,row['incident_id'])['generation']!=row['approved_generation']:
        raise ValueError('Target mapping or investigation ownership changed after approval.')
    proof(c,row['incident_id'],row['agent_id'],data['parameters']['service_id'],unit,data['precondition_diagnostic'],now)
    if c.execute("SELECT 1 FROM action_proposals WHERE incident_id=? AND id!=? AND dispatched IS NOT NULL",(row['incident_id'],row['id'])).fetchone():
        raise ValueError('One recovery attempt has already been consumed for this incident.')
    if c.execute("SELECT 1 FROM action_proposals WHERE agent_id=? AND id!=? AND dispatched>?",(row['agent_id'],row['id'],now-cfg['cooldown_seconds'])).fetchone():
        raise ValueError('Target recovery cooldown is active.')
    if c.execute("SELECT 1 FROM ai_jobs WHERE incident_id=? AND state IN ('pending','dispatching','running','unknown')",(row['incident_id'],)).fetchone() or c.execute("SELECT 1 FROM diagnostic_jobs WHERE incident_id=? AND state IN ('pending','leased') AND expires>?",(row['incident_id'],now)).fetchone():
        raise ValueError('Another investigation operation is still active.')
    return data


def poll(c, store, agent_id, now):
    rows=c.execute("SELECT * FROM action_proposals WHERE agent_id=? AND state='approved' ORDER BY created",(agent_id,)).fetchall()
    for row in rows:
        try:
            if row['expires']<=now:
                raise ValueError('Approval expired.')
            if c.execute("SELECT 1 FROM action_proposals WHERE agent_id=? AND state IN ('dispatched','authorized','verifying','unknown')",(agent_id,)).fetchone():
                return []
            data=validate_execution(c,row,now)
        except ValueError as exc:
            c.execute("UPDATE action_proposals SET state='cancelled',result=? WHERE id=?",(str(exc),row['id']))
            store.audit(c,'action.cancelled',row['id'])
            store.timeline(c,row['incident_id'],'action_cancelled',str(exc)+' · Proposal '+row['id'],now=now)
            continue
        token=secrets.token_urlsafe(32)
        # Consume attempt before delivery. An ambiguous delivery never causes reissue.
        c.execute("UPDATE action_proposals SET state='dispatched',dispatch_token=?,dispatched=? WHERE id=?",(token,now,row['id']))
        store.audit(c,'action.dispatched',row['id'])
        return [{'id':row['id'],'proposal_hash':row['payload_hash'],'operation':'service_restart','parameters':data['parameters'],'expires':min(row['expires'],now+60),'dispatch_token':token}]
    return []


def authorize(store, agent_id, payload, now=None):
    now=time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM action_proposals WHERE id=? AND agent_id=?',(payload.get('id'),agent_id)).fetchone()
        if not row or row['state']!='dispatched' or row['dispatched']+60<=now or row['expires']<=now or row['dispatch_token']!=payload.get('dispatch_token') or row['payload_hash']!=payload.get('proposal_hash'):
            raise ValueError('Action delivery is expired, changed or already authorized.')
        validate_execution(c,row,now)
        c.execute("UPDATE action_proposals SET state='authorized' WHERE id=?",(row['id'],))
        store.audit(c,'action.authorized',row['id'],actor='agent')
        data=json.loads(row['payload'])
        return {'status':'authorized','proposal_hash':row['payload_hash'],'operation':data['action'],'parameters':data['parameters']}


def complete(store, agent_id, payload, now=None):
    now=time.time() if now is None else now
    if not isinstance(payload,dict) or payload.get('status') not in ('completed','failed','unknown') or not isinstance(payload.get('output'),str) or len(payload['output'])>16000:
        raise ValueError('Invalid action result.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM action_proposals WHERE id=? AND agent_id=?',(payload.get('id'),agent_id)).fetchone()
        if not row or row['dispatch_token']!=payload.get('dispatch_token'):
            raise ValueError('Unknown action delivery.')
        if row['completed'] is not None:
            return 'duplicate'
        if row['state'] not in ('authorized','unknown') and not (row['state']=='dispatched' and payload['status']=='unknown'):
            raise ValueError('Action was not authorized.')
        state='verifying' if payload['status']=='completed' else payload['status']
        c.execute('UPDATE action_proposals SET state=?,result=?,completed=? WHERE id=?',(state,json.dumps({'status':payload['status'],'output':redact(payload['output'])}),now,row['id']))
        store.timeline(c,row['incident_id'],'action_result','Agent reported '+payload['status']+'; recovery is not yet verified. Proposal '+row['id'],actor='agent',now=now)
        store.audit(c,'action.result',row['id'],{'status':payload['status']},actor='agent')
        return 'accepted'


def tick(store,now=None):
    now=time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        for row in c.execute("SELECT * FROM action_proposals WHERE state IN ('awaiting','approved') AND expires<=?",(now,)).fetchall():
            c.execute("UPDATE action_proposals SET state='expired' WHERE id=?",(row['id'],))
            store.timeline(c,row['incident_id'],'action_expired','Proposal expired without execution: '+row['id'],now=now)
            store.audit(c,'action.expired',row['id'])
        for row in c.execute("SELECT * FROM action_proposals WHERE state IN ('dispatched','authorized') AND dispatched+90<=? AND completed IS NULL",(now,)).fetchall():
            c.execute("UPDATE action_proposals SET state='unknown',result='Delivery/execution outcome unknown; never replay automatically.' WHERE id=?",(row['id'],))
            store.timeline(c,row['incident_id'],'action_unknown','Action outcome unknown; no automatic replay. Proposal '+row['id'],now=now)
            store.audit(c,'action.unknown',row['id'])
        for row in c.execute("SELECT * FROM action_proposals WHERE state IN ('verifying','unknown')").fetchall():
            data=json.loads(row['payload']); unit=data['parameters']['unit']
            baseline=row['completed'] if row['completed'] is not None else row['dispatched']
            diagnostics=c.execute("SELECT result FROM diagnostic_jobs WHERE incident_id=? AND agent_id=? AND operation='service_status' AND state='completed' AND completed>? AND completed>=? AND parameters=? ORDER BY completed DESC LIMIT 1",(row['incident_id'],row['agent_id'],baseline,now-180,json.dumps({'service_id':data['parameters']['service_id']}))).fetchone()
            good=False
            if diagnostics:
                output=json.loads(diagnostics['result']).get('output','')
                props=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
                good=props.get('Id')==unit and props.get('ActiveState')=='active'
            sources=c.execute('SELECT c.id,c.health,c.enabled,o.at FROM incident_sources s JOIN checks c ON c.id=s.check_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=c.id ORDER BY at DESC LIMIT 1) WHERE s.incident_id=?',(row['incident_id'],)).fetchall()
            healthy=bool(sources) and all(s['enabled'] and s['health']=='healthy' and s['at'] and s['at']>baseline and 0<=now-s['at']<=180 for s in sources)
            if good and healthy:
                verified_state='recovered_outcome_unknown' if row['state']=='unknown' else 'verified'
                c.execute("UPDATE action_proposals SET state=?,verification=? WHERE id=?",(verified_state,json.dumps({'at':now,'service':'active','sources':[s['id'] for s in sources],'execution_outcome':'unknown' if row['state']=='unknown' else 'agent_reported_completed'}),row['id']))
                store.timeline(c,row['incident_id'],'action_verified','Fresh service status and independent monitoring confirm recovery. Proposal '+row['id'],now=now)
                store.audit(c,'action.verified',row['id'])
            elif row['state']=='verifying' and now-baseline>=600:
                c.execute("UPDATE action_proposals SET state='verification_failed',verification='Fresh independent evidence did not confirm recovery within ten minutes.' WHERE id=?",(row['id'],))
                store.timeline(c,row['incident_id'],'action_verification_failed','Recovery unconfirmed; user intervention required. No automatic retry. Proposal '+row['id'],now=now)
                store.audit(c,'action.verification_failed',row['id'])
