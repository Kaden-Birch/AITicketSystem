"""Transactional incident ownership and immutable read-only handoff checkpoints."""
import json
import time
from .db import uid
from .diagnostics import redact

ACTIVE = ('pending', 'dispatching', 'running', 'unknown')


def control(c, incident_id):
    c.execute("INSERT OR IGNORE INTO incident_control(incident_id,owner,generation,checkpoint_id,updated) VALUES(?,'available',0,NULL,?)", (incident_id, time.time()))
    return c.execute('SELECT * FROM incident_control WHERE incident_id=?', (incident_id,)).fetchone()


def release(c, job):
    # A stale completion cannot release a newer user/AI ownership generation.
    c.execute("UPDATE incident_control SET owner='available',updated=? WHERE incident_id=? AND owner='ai' AND generation=?", (time.time(), job['incident_id'], job['control_generation']))


def take_control(c, store, incident_id, expected_generation=None):
    incident = c.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
    if not incident:
        raise ValueError('Unknown incident.')
    current = control(c, incident_id)
    if expected_generation is not None and current['generation'] != expected_generation:
        raise ValueError('Incident control changed; reload before handing off.')
    if current['owner']=='user':
        return current['checkpoint_id']
    job = c.execute('SELECT * FROM ai_jobs WHERE incident_id=? ORDER BY created DESC LIMIT 1', (incident_id,)).fetchone()
    from .ai import evidence_snapshot
    snapshot = {'version':1, 'question':'Review the current incident and suggest the next read-only checks.', 'source_ids':[], 'diagnostic_ids':[], 'previous_findings':'', 'evidence_at_pause':json.dumps(evidence_snapshot(json.loads(incident['report'])))[:4000]}
    report=json.loads(incident['report'])
    if report.get('manual_ticket'): snapshot['question']=redact(report.get('description',''))[:2000] or snapshot['question']
    if job:
        snapshot['previous_findings'] = redact(job['summary'] or '')[:4000]
        try:
            context = json.loads(job['evidence'])
        except ValueError:
            context = {}
        if isinstance(context,dict) and context.get('administrator_task'):
            snapshot['question']=redact(context['administrator_task'])[:2000]
        if isinstance(context,dict) and context.get('format')=='aiticket-workspace':
            snapshot['question'] = redact(context.get('administrator_task') or context.get('question',''))[:2000] or snapshot['question']
            snapshot['source_ids'] = [s['id'] for s in context.get('sources',[])][:5]
            snapshot['diagnostic_ids'] = [d['id'] for d in context.get('diagnostics',[])][:3]
    checkpoint_id, now = uid(), time.time()
    c.execute('INSERT INTO handoff_checkpoints VALUES(?,?,?,?,?)', (checkpoint_id, incident_id, job['id'] if job else None, now, json.dumps(snapshot)))
    for active in c.execute("SELECT id FROM ai_jobs WHERE incident_id=? AND state IN ('pending','dispatching','running','unknown')", (incident_id,)).fetchall():
        c.execute("UPDATE ai_jobs SET state='cancelled',completed=?,lease_until=NULL,lease_token=NULL WHERE id=?", (now, active['id']))
    from .worklog import end
    end(c, incident_id, 'hermes', 'Paused', now)
    c.execute("UPDATE incident_control SET owner='user',handling_mode='human',generation=generation+1,checkpoint_id=?,updated=? WHERE incident_id=?", (checkpoint_id, now, incident_id))
    store.timeline(c, incident_id, 'handoff_user', 'User took control. Further AI calls denied; in-flight usage remains held. Checkpoint '+checkpoint_id, actor='user')
    store.audit(c, 'handoff.user', incident_id, {'checkpoint_id':checkpoint_id})
    return checkpoint_id


def pause(store, incident_id, expected_generation):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        return take_control(c, store, incident_id, expected_generation)


def view(store, incident_id):
    with store.connect() as c:
        current = dict(control(c, incident_id))
        checkpoint = c.execute('SELECT * FROM handoff_checkpoints WHERE id=?', (current['checkpoint_id'],)).fetchone()
        current['checkpoint'] = {**dict(checkpoint), 'data':json.loads(checkpoint['snapshot'])} if checkpoint else None
        current['waiting'] = 'AI paused; user has control.' if current['owner']=='user' else 'No active AI execution.'
        job = c.execute("SELECT state,execution_mode FROM ai_jobs WHERE incident_id=? AND state IN ('pending','dispatching','running','unknown') ORDER BY created DESC LIMIT 1", (incident_id,)).fetchone()
        if job:
            current['waiting'] = {'pending':'Queued for the bridge.', 'dispatching':'Waiting for bridge acceptance.', 'running':'Waiting for metered AI findings.', 'unknown':'Execution outcome unknown; polling without replay.'}[job['state']]
        if job and job['execution_mode']=='codex' and job['state']=='running':
            current['waiting']='Waiting for Codex subscription findings; local cancellation is monitored.'
        if c.execute("SELECT 1 FROM ai_calls WHERE state!='known'").fetchone():
            current['waiting'] += ' Unknown API model usage blocks further API-mode admission globally.'
        return current


def resume(store, vault, incident_id, checkpoint_id, expected_generation, request_id, current_task=None):
    from .ai import request_job
    if not isinstance(checkpoint_id, str) or not checkpoint_id:
        raise ValueError('Choose a saved checkpoint before resuming.')
    return request_job(store, vault, incident_id, mode='exploration', question='Resume the checkpoint investigation with current evidence.', request_id=request_id, resume_checkpoint=checkpoint_id, expected_generation=expected_generation,resume_task=current_task.strip() if current_task and current_task.strip() else None)
