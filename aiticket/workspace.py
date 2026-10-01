"""Incident-scoped, explicitly selected context. No tool or action dispatch."""
import json
import time
from .ai import evidence_snapshot
from .diagnostics import redact


def context(c, incident, mode, question, source_ids, diagnostic_ids, checkpoint=None):
    if len(source_ids)>5 or len(diagnostic_ids)>3 or len(set(source_ids))!=len(source_ids) or len(set(diagnostic_ids))!=len(diagnostic_ids):
        raise ValueError('Choose at most five sources and three diagnostic results.')
    report=json.loads(incident['report'])
    facts={k:report[k] for k in ('target','check','observed','cause','expected','severity') if k in report}
    sources=[]
    for identifier in source_ids:
        row=c.execute('SELECT s.report,c.name,c.enabled FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=? AND s.check_id=?',(incident['id'],identifier)).fetchone()
        if not row:
            raise ValueError('Selected evidence must belong to this incident.')
        sources.append({'id':identifier,'name':row['name'],'enabled':bool(row['enabled']),'snapshot':evidence_snapshot(json.loads(row['report']))})
    diagnostics=[]
    for identifier in diagnostic_ids:
        row=c.execute("SELECT id,operation,result,completed FROM diagnostic_jobs WHERE id=? AND incident_id=? AND state='completed' AND result IS NOT NULL",(identifier,incident['id'])).fetchone()
        if not row:
            raise ValueError('Choose a completed diagnostic from this incident.')
        result=json.loads(row['result'])
        diagnostics.append({'id':row['id'],'operation':row['operation'],'completed_at':row['completed'],'output':redact(result.get('output',''))[:2000]})
    # Only completed exchanges; incomplete/cancelled questions are not silently reused.
    history=c.execute("SELECT u.text AS question,a.text AS answer FROM ai_messages u JOIN ai_messages a ON a.job_id=u.job_id AND a.role='assistant' JOIN ai_jobs j ON j.id=u.job_id WHERE u.incident_id=? AND u.role='user' AND j.state='completed' ORDER BY u.created DESC LIMIT 3",(incident['id'],)).fetchall()
    conversation=[{'question':r['question'][:1000],'answer':r['answer'][:1000]} for r in reversed(history)]
    document={'format':'aiticket-workspace','version':1,'mode':mode,'snapshot_at':time.time(),'question':redact(question.strip()),'facts':evidence_snapshot(facts),'sources':sources,'diagnostics':diagnostics,'conversation':conversation}
    if checkpoint:
        document['checkpoint'] = {'id':checkpoint['id'], 'previous_findings':checkpoint['previous_findings'][:2000], 'evidence_at_pause':checkpoint['evidence_at_pause'][:2000], 'note':'Historical checkpoint; current facts and selected evidence may differ. No old execution is replayed.'}
    serialized=json.dumps(document,ensure_ascii=True)
    if len(serialized)>16000:
        raise ValueError('Selected context is too large. Choose fewer sources or diagnostic results.')
    return serialized
