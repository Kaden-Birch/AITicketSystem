"""Tool-free AI text drafting, with server-bound targets and explicit user review."""
import json
from .diagnostics import redact

TEXTS=('rationale','impact','risk','alternatives')


def request_draft(store,vault,incident_id,agent_id,service_id,diagnostic_id,request_id):
    from .ai import request_job
    return request_job(store,vault,incident_id,mode='recovery_proposal',question='Draft an approval-required restart proposal for the administrator-selected failed service.',request_id=request_id,diagnostic_ids=[diagnostic_id],recovery_target={'agent_id':agent_id,'service_id':service_id,'diagnostic_id':diagnostic_id})


def target(c,incident_id,selected,now):
    from .actions import eligible,proof
    if not isinstance(selected,dict) or set(selected)!={'agent_id','service_id','diagnostic_id'} or any(not isinstance(v,str) for v in selected.values()):
        raise ValueError('Select an exact agent/service and completed diagnostic.')
    _,_,unit,_=eligible(c,incident_id,selected['agent_id'],selected['service_id'],now,require_enabled=False)
    proof(c,incident_id,selected['agent_id'],selected['service_id'],unit,selected['diagnostic_id'],now)
    return {**selected,'unit':unit,'operation':'service_restart','authority':'Text draft only; administrator review and exact one-time broker approval required.'}


def record(c,store,job,summary,now):
    try:
        document=json.loads(summary)
    except (ValueError,RecursionError):
        raise ValueError('AI draft must return the required JSON object; no proposal created.') from None
    if not isinstance(document,dict) or set(document)!=set(TEXTS) or any(not isinstance(document[k],str) or not 1<=len(document[k].strip())<=1000 for k in TEXTS):
        raise ValueError('AI draft has unsupported fields or text bounds; no proposal created.')
    envelope=json.loads(job['evidence'])
    selected=envelope.get('recovery_target')
    if not isinstance(selected,dict) or selected.get('operation')!='service_restart':
        raise ValueError('AI draft target envelope is invalid.')
    payload={'target':selected,'texts':{k:redact(document[k].strip()) for k in TEXTS},'origin':{'kind':'ai','job_id':job['id'],'status':'Unverified AI draft reviewed by administrator; no execution authority.'}}
    c.execute('INSERT OR IGNORE INTO recovery_drafts VALUES(?,?,?,?)',(job['id'],job['incident_id'],json.dumps(payload),now))
    store.timeline(c,job['incident_id'],'recovery_draft','Unverified AI recovery draft ready for administrator review. No proposal approved or action authorized. Execution '+job['id'],actor='hermes',now=now)
    store.audit(c,'recovery.drafted',job['id'],actor='hermes')
    return json.dumps(payload['texts'])


def adopt(store,incident_id,job_id):
    from .actions import propose
    rows=store.rows('SELECT * FROM recovery_drafts WHERE job_id=? AND incident_id=?',(job_id,incident_id))
    if not rows:
        raise ValueError('Choose a completed draft from this incident.')
    data=json.loads(rows[0]['payload']); selected=data['target']
    return propose(store,incident_id,selected['agent_id'],selected['service_id'],selected['diagnostic_id'],**data['texts'],draft_job_id=job_id)
