"""Durable read-only Hermes jobs and transactional per-model-call admission."""
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
import requests
from .db import uid
from .diagnostics import redact
from .security import digest, hermes_headers, validate_url
from .engine import SEVERITIES

BRIDGE_DEFAULTS = {'url': '', 'ca': '', 'enabled': False, 'automatic': False, 'minimum': 'high', 'runtime_verified': False, 'execution_mode':'gateway'}
PROVIDER_DEFAULTS = {'url': '', 'ca': '', 'verified': False, 'input_overhead': 8192, 'output_tokens': 1000, 'verified_model': ''}
TERMINAL = ('completed', 'failed', 'cancelled', 'expired')


def setting(c, name, default=None):
    row = c.execute('SELECT value FROM settings WHERE key=?', (name,)).fetchone()
    return json.loads(row[0]) if row else default


def write(c, name, value):
    c.execute('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (name, json.dumps(value, allow_nan=False)))


def cost(input_tokens, output_tokens, cfg):
    # Integer microdollars, rounded up. Cached input is charged at the full input price.
    return int((Decimal(input_tokens) * Decimal(str(cfg['input_price'])) + Decimal(output_tokens) * Decimal(str(cfg['output_price']))).to_integral_value(rounding=ROUND_CEILING))


def valid_configuration(cfg, bridge, provider, mode='triage'):
    if bridge.get('execution_mode','gateway')=='codex':
        from .codex_mode import options
        options(bridge)
        if not bridge.get('enabled') or not bridge.get('runtime_verified') or not cfg.get('model'):
            raise ValueError('Configure the model and validate the restricted Codex runtime before enabling.')
        validate_url(bridge.get('url',''),('https',))
        return
    if not bridge.get('enabled') or not bridge.get('runtime_verified') or not provider.get('verified'):
        raise ValueError('AI is disabled or the provider token-bound contract has not been verified.')
    if provider.get('verified_model') != cfg.get('model'):
        raise ValueError('Revalidate provider bounds after changing the model.')
    if not cfg.get('model') or any(cfg.get(k, 0) <= 0 for k in (('triage_tokens',) if mode=='triage' else ()) + ('incident_tokens', 'daily_tokens', 'monthly_tokens', 'max_turns', 'daily_cost', 'monthly_cost')):
        raise ValueError('Configure a model and positive AI allowances; zero prohibits dispatch.')
    if cfg.get('input_price', 0) <= 0 or cfg.get('output_price', 0) <= 0:
        raise ValueError('Configure positive conservative input and output prices before dispatch.')
    validate_url(bridge.get('url', ''), ('https',))
    validate_url(provider.get('url', ''), ('https',))


def evidence_snapshot(value):
    import re
    if isinstance(value, dict):
        return {str(k): ('[REDACTED]' if re.search(r'(?i)(password|passwd|secret|token|api[_-]?key|authorization)', str(k)) else evidence_snapshot(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [evidence_snapshot(v) for v in value[:100]]
    return redact(value) if isinstance(value, str) else value


def request_job(store, vault, incident_id, automatic=False, now=None, mode='triage', question='', request_id=None, source_ids=(), diagnostic_ids=(), resume_checkpoint=None, expected_generation=None, recovery_target=None, resume_task=None, maintenance_changes=False, read_only=False, knowledge_draft=None, workflow_article=None):
    now = time.time() if now is None else now
    if resume_task is not None and (not resume_checkpoint or not isinstance(resume_task,str) or not 1<=len(resume_task.strip())<=2000):
        raise ValueError('Supply a current checkpoint task of 1–2000 characters.')
    if mode not in ('triage', 'advice', 'exploration','recovery_proposal') or (automatic and mode != 'triage'):
        raise ValueError('Unsupported AI workspace mode.')
    if mode != 'triage':
        import uuid
        if not isinstance(question, str) or not 1 <= len(question.strip()) <= 2000:
            raise ValueError('Supply a question of 1–2000 characters.')
        try:
            uuid.UUID(request_id)
        except (ValueError, TypeError, AttributeError):
            raise ValueError('Invalid request identity; reload the incident page.')
    fingerprint = hashlib.sha256(json.dumps({'mode': mode, 'question': question.strip(), 'sources': sorted(source_ids), 'diagnostics': sorted(diagnostic_ids), 'checkpoint': resume_checkpoint, 'generation': expected_generation,'recovery_target':recovery_target,'maintenance_changes':bool(maintenance_changes),'read_only':bool(read_only),**({'workflow_article':workflow_article} if workflow_article else {}),**({'resume_task':resume_task.strip()} if resume_task else {})}, sort_keys=True).encode()).hexdigest()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if request_id:
            previous = c.execute('SELECT id,incident_id,request_fingerprint FROM ai_jobs WHERE request_id=?', (request_id,)).fetchone()
            if previous:
                if previous['incident_id'] != incident_id or previous['request_fingerprint'] != fingerprint:
                    raise ValueError('Request identity was reused with different parameters.')
                return previous['id']
        bridge = setting(c, 'hermes_config', BRIDGE_DEFAULTS)
        provider = setting(c, 'ai_provider', PROVIDER_DEFAULTS)
        cfg = setting(c, 'ai_config', {})
        valid_configuration(cfg, bridge, provider, mode)
        if mode != 'triage' and mode not in (setting(c, 'hermes_validation', {}) or {}).get('workspace_modes', []):
            raise ValueError('Update the companion bridge and run its compatibility check for workspace support.')
        if not setting(c, 'hermes_secret') or (bridge.get('execution_mode','gateway')=='gateway' and not setting(c, 'ai_provider_secret')):
            raise ValueError('Save both bridge and model-provider credentials.')
        incident = c.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if not incident or incident['closed'] is not None or incident['status'] == 'Resolved':
            raise ValueError('Investigation requires an active unresolved incident.')
        from .maintenance_ai import state as maintenance_state
        if automatic:
            from .maintenance_ai import post_window_ready
            if maintenance_state(c,incident['machine_id'],now,incident_id)['active'] or not post_window_ready(c,incident_id,incident['machine_id'],now):return None
        from .ticket_groups import coordinating_primary
        if automatic and coordinating_primary(c,incident_id,now):return None
        from .handoff import control
        ownership = control(c, incident_id)
        checkpoint_data = None
        if resume_checkpoint:
            if ownership['owner']!='user' or ownership['generation']!=expected_generation or ownership['checkpoint_id']!=resume_checkpoint:
                raise ValueError('Checkpoint or control changed; reload before resuming.')
            checkpoint = c.execute('SELECT snapshot FROM handoff_checkpoints WHERE id=? AND incident_id=?', (resume_checkpoint, incident_id)).fetchone()
            if not checkpoint:
                raise ValueError('Unknown incident checkpoint.')
            checkpoint_data = json.loads(checkpoint['snapshot'])
            checkpoint_data['id'] = resume_checkpoint
            question = resume_task.strip() if resume_task else checkpoint_data['question']
            # Refresh selected sources; detached selections are explicitly omitted from the new run.
            source_ids = [identifier for identifier in checkpoint_data['source_ids'] if c.execute('SELECT 1 FROM incident_sources WHERE incident_id=? AND check_id=?',(incident_id,identifier)).fetchone()]
            diagnostic_ids = [identifier for identifier in checkpoint_data['diagnostic_ids'] if c.execute("SELECT 1 FROM diagnostic_jobs WHERE incident_id=? AND id=? AND state='completed'",(incident_id,identifier)).fetchone()]
        elif ownership['owner']=='user' and mode!='recovery_proposal':
            if automatic:
                return None
            raise ValueError('User has control; resume from the saved checkpoint before requesting AI.')
        bound_target=None
        if mode=='recovery_proposal':
            from .recovery_drafts import target
            bound_target=target(c,incident_id,recovery_target,now)
        elif recovery_target is not None:
            raise ValueError('Recovery targets are valid only for proposal drafting.')
        if automatic and (not bridge.get('automatic') or (not json.loads(incident['report']).get('manual_ticket') and SEVERITIES.index(incident['severity']) < SEVERITIES.index(bridge['minimum']))):
            return None
        if c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('approved','dispatched','authorized','verifying','unknown')",(incident['machine_id'],)).fetchone():
            if automatic: return None
            raise ValueError('Host power execution is outstanding; independently reconcile it before AI.')
        if c.execute("SELECT 1 FROM action_proposals WHERE incident_id=? AND state IN ('approved','dispatched','authorized','verifying','unknown')", (incident_id,)).fetchone():
            if automatic: return None
            raise ValueError('Recovery approval/execution is outstanding; cancel it or verify the outcome before starting AI.')
        if c.execute("SELECT 1 FROM diagnostic_jobs WHERE incident_id=? AND state IN ('pending','leased') AND expires>?", (incident_id, now)).fetchone():
            if automatic:
                return None
            raise ValueError('Wait for this incident’s queued diagnostics to finish or expire before starting AI.')
        existing = c.execute("SELECT id FROM ai_jobs WHERE incident_id=? AND state IN ('pending','dispatching','running','unknown')", (incident_id,)).fetchone()
        if existing:
            if mode != 'triage':
                raise ValueError('An AI execution is already active for this incident; wait or cancel it first.')
            return existing['id']
        if c.execute("SELECT count(*) FROM ai_jobs WHERE state IN ('pending','dispatching','running','unknown')").fetchone()[0] >= 10:
            raise ValueError('AI queue is full; review existing jobs.')
        codex=None
        if bridge.get('execution_mode','gateway')=='codex':
            validation=setting(c,'hermes_validation',{}) or {}
            if validation.get('execution_mode')!='codex' or validation.get('url')!=bridge['url'] or now-validation.get('at',0)>86400:
                raise ValueError('Run a recent signed Codex bridge check first.')
            from .codex_mode import admit
            codex=admit(c,incident_id,bridge,now)
        job_id, token = uid(), secrets.token_urlsafe(48)
        # Snapshot only the deterministic report; notes, credentials and raw configs are excluded.
        evidence = json.dumps(evidence_snapshot(json.loads(incident['report'])), ensure_ascii=True)[:16000]
        if mode != 'triage':
            from .workspace import context
            evidence = context(c, incident, mode, question, source_ids, diagnostic_ids, checkpoint_data)
            if bound_target:
                document=json.loads(evidence)
                document['recovery_target']=bound_target
                evidence=json.dumps(document)
                if len(evidence)>16000:
                    raise ValueError('Recovery draft context exceeds limits.')
        from .unifi import ai_context as unifi_context
        unifi_facts=unifi_context(c,incident['machine_id'])
        if unifi_facts:
            document=json.loads(evidence)
            document['unifi_read_only']=unifi_facts
            evidence=json.dumps(document)
            if len(evidence)>16000: raise ValueError('Selected context including UniFi exceeds limits.')
        from .topology import context as topology_context,bounded as bounded_topology
        document=json.loads(evidence)
        document['network_topology']=bounded_topology(topology_context(c,incident['machine_id']),max(500,min(3500,15000-len(evidence))))
        evidence=json.dumps(document)
        if len(evidence)>16000:
            document['network_topology']={'coverage':'Topology omitted due to context size; use targets/network for current read-only facts.'}
            evidence=json.dumps(document)
        from .machine_context import context as machine_context
        document=json.loads(evidence)
        document['machine']=machine_context(c,incident['machine_id'],now)
        from .evidence import summary as evidence_summary
        from .ticket_groups import context as group_context
        document['evidence_available']=evidence_summary(c,incident['machine_id'],now)
        document['affected_targets']=group_context(c,incident_id,now)
        from .knowledge import context as kb_context
        from .ticket_groups import machines as group_machines
        from .changes import context as change_context
        from .knowledge import related_scope
        affected=related_scope(c,group_machines(c,incident_id))
        document['network_events']={'on_demand':True,'note':'Logs are not attached automatically. Request host-specific logs only when they can answer an investigation question.'}
        document['historical_archive']={'local_available':True,'available':bool(store.setting('network_log_smb',{}).get('server')),'note':'Use archive_search with tier local first, or tier smb for older history; choose archive_type network or telemetry, machine_id, an explicit start/end interval and optional query/record_type. Start with limit 10 and narrow filters. Local results return immediately; poll SMB searches using archive_status and id without resubmitting. Use archive_record with record_key, optional SMB search id, pointer and offset to retrieve needed fields beyond previews. Request evidence only when useful; cite references as observed facts, never proven causes or repair authority.'}
        document['knowledge']=kb_context(c,affected)
        document['recent_changes']=[{k:v for k,v in item.items() if k!='details'} for item in change_context(c,affected)[:8]]
        from .knowledge import ticket_context
        report=json.loads(incident['report'])
        document['ticket_history']=ticket_context(c,affected,report.get('knowledge_source') if report.get('knowledge_task') else None,incident_id)
        document['read_only_task']=bool(read_only)
        document['maintenance']=maintenance_state(c,incident['machine_id'],now,incident_id)
        document['maintenance']['changes_allowed']=bool(maintenance_changes) and not automatic

        if json.loads(incident['report']).get('workflow_test'):document['workflow_test']=True
        evidence=json.dumps(evidence_snapshot(document))
        if len(evidence)>16000:
            # Preserve the primary incident/task; large inventories remain available via targets.
            document['affected_targets']={'coverage':'Retrieve affected hosts and linked tickets using targets. No extra command permissions granted.'}
            document['machine']={'id':incident['machine_id'],'coverage':'Full current host context is available through targets; snapshot omitted to preserve incident evidence.'}
            evidence=json.dumps(evidence_snapshot(document))
        if len(evidence)>14500:
            document['knowledge']={'coverage':'Search knowledge for saved articles; optional article creation only when useful.'}
            document['recent_changes']={'coverage':'Use changes for observed change history.'}
            document['network_events']={'coverage':'Retrieve network_logs evidence for untrusted historical events; no extra permissions granted.'}
            if not report.get('knowledge_task'):document['ticket_history']={'coverage':'Use ticket_history to retrieve prior tickets.'}
            evidence=json.dumps(evidence_snapshot(document))
        if codex and bridge.get('command_tools'):
            document=json.loads(evidence)
            report=json.loads(incident['report'])
            task=question.strip() or (report.get('description','') if report.get('manual_ticket') else 'Investigate the incident using current read-only diagnostics. Report findings; do not change systems without an explicit administrator task.')
            from .machine_context import context as machine_context
            document['administrator_task']=task
            document['task_origin']='Monitoring automatically requested this investigation.' if automatic else 'Administrator selected this operational investigation; checkpoint resumption restates its saved question as the current task.'
            from .proxmox_operations import context as proxmox_context
            document['linked_proxmox']=proxmox_context(c,incident['machine_id'])
            evidence=json.dumps(document)
            if len(evidence)>16000: raise ValueError('Operational task context exceeds limits.')
        c.execute('INSERT INTO ai_jobs(id,incident_id,state,created,expires,model,allowance,max_calls,evidence,credential_digest,credential,endpoint,bridge_secret,next_attempt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (job_id, incident_id, 'pending', now, now+3600, cfg['model'], min(cfg['triage_tokens'], cfg['incident_tokens']), min(cfg['max_turns'], 100), evidence, digest(token), vault.encrypt(token), bridge['url'].rstrip('/'), setting(c, 'hermes_secret'), now))
        c.execute('UPDATE ai_jobs SET automatic=?,maintenance_changes=?,read_only=? WHERE id=?',(int(automatic),int(bool(maintenance_changes) and not automatic),int(read_only),job_id))
        if workflow_article:
            if not bridge.get('command_tools'):raise ValueError('Enable AI host tools before running a saved procedure.')
            from .knowledge_workflows import start
            start(c,store,workflow_article,incident['machine_id'],incident_id,job_id)
        if knowledge_draft:
            c.execute('INSERT INTO kb_requests VALUES(?,?,?,NULL)',(job_id,*knowledge_draft))
        c.execute('UPDATE ai_jobs SET mode=?,request_id=?,request_fingerprint=?,allowance=? WHERE id=?', (mode, request_id, fingerprint, min(cfg['triage_tokens'], cfg['incident_tokens']) if mode=='triage' else cfg['incident_tokens'], job_id))
        if bridge.get('command_tools'):
            if not codex: raise ValueError('Command tools currently require Codex mode.')
            c.execute('UPDATE ai_jobs SET command_tools=1 WHERE id=?',(job_id,))
        if codex:
            c.execute("UPDATE ai_jobs SET execution_mode='codex',reasoning_effort=?,run_timeout=?,allowance=0,max_calls=1 WHERE id=?",(codex['reasoning'],codex['timeout_seconds'],job_id))
        generation = ownership['generation']+1
        c.execute("UPDATE incident_control SET owner='ai',generation=?,updated=? WHERE incident_id=?", (generation, now, incident_id))
        c.execute('UPDATE ai_jobs SET control_generation=? WHERE id=?', (generation, job_id))
        from .worklog import clear
        clear(c, incident_id, now)
        c.execute("UPDATE incident_control SET handling_mode='automatic' WHERE incident_id=?",(incident_id,))
        if resume_checkpoint:
            store.timeline(c, incident_id, 'handoff_ai', 'New read-only execution resumed from checkpoint '+resume_checkpoint+' · '+job_id, actor='user', now=now)
            store.audit(c, 'handoff.ai', incident_id, {'checkpoint_id':resume_checkpoint, 'job_id':job_id})
        if mode != 'triage':
            c.execute('INSERT INTO ai_messages VALUES(?,?,?,?,?,?)', (uid(), incident_id, job_id, 'user', redact(question.strip()), now))
            store.timeline(c, incident_id, 'ai_question', mode+': '+redact(question.strip())+' · Execution '+job_id, actor='user', now=now)
        store.timeline(c, incident_id, 'ai_queued', 'Investigation queued.', actor='user' if not automatic else 'monitor', now=now)
        store.audit(c, 'ai.queued', job_id, {'incident_id': incident_id, 'automatic': automatic})
        return job_id


def periods(now):
    day = datetime.fromtimestamp(now, timezone.utc)
    return day.replace(hour=0, minute=0, second=0, microsecond=0).timestamp(), day.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()


def usage(c, where='', args=()):
    return dict(c.execute('SELECT COALESCE(SUM(CASE WHEN state=\'known\' THEN input_tokens+output_tokens ELSE input_reserved+output_reserved END),0) AS tokens, COALESCE(SUM(CASE WHEN state=\'known\' THEN cost_actual ELSE cost_reserved END),0) AS microdollars FROM ai_calls '+where, args).fetchone())


def meter(store, incident_id=None, now=None):
    now = time.time() if now is None else now
    day, month = periods(now)
    with store.connect() as c:
        result = {'day': usage(c, 'WHERE created>=?', (day,)), 'month': usage(c, 'WHERE created>=?', (month,)), 'held': c.execute("SELECT count(*) FROM ai_calls WHERE state!='known'").fetchone()[0]}
        if incident_id:
            result['incident'] = usage(c, 'WHERE job_id IN (SELECT id FROM ai_jobs WHERE incident_id=?)', (incident_id,))
        return result


def admit(store, job_id, payload, now=None):
    now = time.time() if now is None else now
    if not isinstance(payload, dict) or set(payload) - {'model', 'messages', 'stream', 'max_tokens', 'max_completion_tokens', 'temperature', 'tools', 'tool_choice', 'parallel_tool_calls'}:
        raise ValueError('Unsupported model request fields.')
    if payload.get('tools') or payload.get('stream') not in (None, False):
        raise ValueError('Only nonstreaming, tool-free model requests are permitted.')
    messages = payload.get('messages')
    if not isinstance(messages, list) or not 1 <= len(messages) <= 100 or any(not isinstance(m, dict) or set(m) != {'role', 'content'} or m['role'] not in ('system', 'user', 'assistant') or not isinstance(m['content'], str) for m in messages):
        raise ValueError('Only bounded text messages are permitted.')
    serialized = json.dumps(messages, ensure_ascii=False, separators=(',', ':')).encode()
    if len(serialized) > 32000:
        raise ValueError('AI context is too large.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job = c.execute('SELECT * FROM ai_jobs WHERE id=?', (job_id,)).fetchone()
        cfg, bridge, provider = setting(c, 'ai_config', {}), setting(c, 'hermes_config', BRIDGE_DEFAULTS), setting(c, 'ai_provider', PROVIDER_DEFAULTS)
        if job and job['execution_mode']!=bridge.get('execution_mode','gateway'):
            raise ValueError('AI execution mode changed; this job is no longer authorized.')
        valid_configuration(cfg, bridge, provider, job['mode'] if job else 'triage')
        incident = c.execute('SELECT closed,status FROM incidents WHERE id=?', (job['incident_id'],)).fetchone() if job else None
        if job and job['execution_mode']!='gateway':
            raise ValueError('Codex subscription jobs cannot access the API budget gateway.')
        if not job or job['state'] not in ('dispatching', 'running') or job['expires'] <= now or not incident or incident['closed'] is not None or incident['status']=='Resolved' or payload.get('model') != job['model'] or cfg['model'] != job['model']:
            raise ValueError('This execution is no longer authorized.')
        from .handoff import control
        ownership = control(c, job['incident_id'])
        if ownership['owner']!='ai' or ownership['generation']!=job['control_generation']:
            raise ValueError('Incident ownership changed; this AI execution is fenced.')
        # Unknown usage globally fences new calls across UTC resets until resolved.
        if c.execute("SELECT 1 FROM ai_calls WHERE state!='known'").fetchone():
            raise ValueError('An earlier model request has unknown usage; admission is paused.')
        count = c.execute('SELECT count(*) FROM ai_calls WHERE job_id=?', (job_id,)).fetchone()[0]
        if count >= min(job['max_calls'], cfg['max_turns']):
            raise ValueError('Maximum model-call count reached.')
        input_bound = len(serialized) + provider['input_overhead']
        output_bound = provider['output_tokens']
        for key in ('max_tokens', 'max_completion_tokens'):
            if key in payload:
                if type(payload[key]) is not int or payload[key] <= 0:
                    raise ValueError('Output cap must be positive.')
                output_bound = min(output_bound, payload[key])
        total = input_bound+output_bound
        amount = cost(input_bound, output_bound, cfg)
        day, month = periods(now)
        checks = ((usage(c, 'WHERE job_id=?', (job_id,))['tokens'], min(job['allowance'], cfg['triage_tokens'] if job['mode']=='triage' else cfg['incident_tokens']), total),
                  (usage(c, 'WHERE job_id IN (SELECT id FROM ai_jobs WHERE incident_id=?)', (job['incident_id'],))['tokens'], cfg['incident_tokens'], total),
                  (usage(c, 'WHERE created>=?', (day,))['tokens'], cfg['daily_tokens'], total),
                  (usage(c, 'WHERE created>=?', (month,))['tokens'], cfg['monthly_tokens'], total),
                  (usage(c, 'WHERE created>=?', (day,))['microdollars'], int(Decimal(str(cfg['daily_cost']))*1000000), amount),
                  (usage(c, 'WHERE created>=?', (month,))['microdollars'], int(Decimal(str(cfg['monthly_cost']))*1000000), amount))
        if any(used+reserve > limit for used, limit, reserve in checks):
            raise ValueError('AI allowance exhausted; increase the relevant limit to continue.')
        call_id = uid()
        c.execute("INSERT INTO ai_calls(id,job_id,created,state,input_reserved,output_reserved,cost_reserved,prices) VALUES(?,?,?,'held',?,?,?,?)", (call_id, job_id, now, input_bound, output_bound, amount, json.dumps({'input_price': cfg['input_price'], 'output_price': cfg['output_price']})))
        store.audit(c, 'ai.call_admitted', call_id, {'job_id': job_id, 'reserved_tokens': total, 'reserved_microdollars': amount}, actor='budget-gate')
        return call_id, {'model': job['model'], 'messages': messages, 'stream': False, 'max_completion_tokens': output_bound}, provider, cfg


def reconcile(store, call_id, reported, cfg, manual=False):
    if not isinstance(reported, dict):
        return False
    inp, out = reported.get('prompt_tokens'), reported.get('completion_tokens')
    details = reported.get('prompt_tokens_details') or {}
    cached = details.get('cached_tokens', 0) if isinstance(details, dict) else None
    if any(type(v) is not int or not 0 <= v <= 10**9 for v in (inp, out, cached)) or cached > inp:
        return False
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT * FROM ai_calls WHERE id=?', (call_id,)).fetchone()
        if not row or row['state']=='known':
            return False
        if manual:
            job = c.execute('SELECT state FROM ai_jobs WHERE id=?', (row['job_id'],)).fetchone()
            if time.time()-row['created'] < 60 or job['state'] not in (*TERMINAL, 'unknown'):
                return False
            store.audit(c, 'ai.manual_usage_override', call_id, actor='user')
        violated = inp > row['input_reserved'] or out > row['output_reserved']
        c.execute("UPDATE ai_calls SET state='known',input_tokens=?,output_tokens=?,cached_tokens=?,cost_actual=? WHERE id=?", (inp, out, cached, cost(inp, out, json.loads(row['prices'])), call_id))
        if violated:
            provider = setting(c, 'ai_provider', PROVIDER_DEFAULTS)
            provider['verified'] = False
            write(c, 'ai_provider', provider)
            store.audit(c, 'ai.provider_bound_violation', call_id, actor='budget-gate')
        return not violated


def bounded_json(response, limit=64000):
    data = bytearray()
    deadline = time.monotonic()+20
    for chunk in response.iter_content(4096):
        data.extend(chunk)
        if len(data)>limit or time.monotonic()>deadline:
            raise ValueError('Bridge/provider reply exceeds bounds.')
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        raise ValueError('Invalid bridge/provider reply.')


def model_call(store, vault, job_id, payload):
    call_id, outgoing, provider, cfg = admit(store, job_id, payload)
    secret = store.setting('ai_provider_secret')
    try:
        with requests.post(provider['url'].rstrip('/')+'/chat/completions', json=outgoing, headers={'Authorization': 'Bearer '+vault.decrypt(secret)}, verify=provider.get('ca') or True, timeout=(3, 15), stream=True, allow_redirects=False) as response:
            if response.status_code != 200:
                raise ValueError('Provider request failed; reserved usage remains held.')
            document = bounded_json(response)
        # Reconcile even malformed findings if trustworthy numeric usage is present.
        known = reconcile(store, call_id, document.get('usage') if isinstance(document, dict) else None, cfg)
        choices = document.get('choices') if isinstance(document, dict) else None
        message = choices[0].get('message') if isinstance(choices, list) and len(choices)==1 and isinstance(choices[0], dict) else None
        if not known or not isinstance(message, dict) or message.get('tool_calls') or not isinstance(message.get('content'), str) or len(message['content']) > 16000:
            raise ValueError('Provider reply or usage is invalid; review AI usage before continuing.')
        return {'id': call_id, 'object': 'chat.completion', 'model': outgoing['model'], 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': redact(message['content'])}, 'finish_reason': 'stop'}], 'usage': document['usage']}
    except requests.RequestException:
        raise ValueError('Provider outcome is unknown; reservation retained and further calls paused.')


def authenticate(secret, body, headers, now=None):
    now = time.time() if now is None else now
    stamp = headers.get('X-Webhook-Timestamp', '')
    try:
        if abs(now-int(stamp))>300:
            return False
    except (ValueError, TypeError):
        return False
    signature = hmac.new(secret.encode(), stamp.encode()+b'.'+body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, headers.get('X-Webhook-Signature-V2', ''))


def apply_status(store, job_id, document, now=None):
    now = time.time() if now is None else now
    if not isinstance(document, dict) or document.get('execution_id') != job_id or document.get('state') not in ('accepted', 'running', 'completed', 'failed', 'interrupted', 'not_found'):
        raise ValueError('Invalid bridge execution status.')
    summary = document.get('summary', '')
    if not isinstance(summary, str) or len(summary)>16000:
        raise ValueError('Summary exceeds bounds.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job = c.execute('SELECT * FROM ai_jobs WHERE id=?', (job_id,)).fetchone()
        if not job or job['state'] in TERMINAL:
            return
        state = 'failed' if document['state']=='not_found' else 'running' if document['state'] in ('accepted','running') else ('unknown' if document['state']=='interrupted' else document['state'])
        if state=='completed' and job['execution_mode']=='codex' and (document.get('execution_mode')!='codex' or document.get('model')!=job['model'] or document.get('reasoning')!=job['reasoning_effort']):
            raise ValueError('Codex result does not match the execution mode/model/reasoning.')
        if state=='completed' and job['execution_mode']=='gateway' and not c.execute('SELECT 1 FROM ai_calls WHERE job_id=?', (job_id,)).fetchone():
            raise ValueError('Completion without a metered model call is invalid.')
        if state=='completed' and job['mode']=='recovery_proposal':
            from .recovery_drafts import record
            try:
                summary=record(c,store,job,summary,now)
            except ValueError as exc:
                state='failed'
                summary=str(exc)
        if state=='completed':
            from .knowledge import record_draft
            record_draft(c,store,job,redact(summary))
        c.execute('UPDATE ai_jobs SET state=?,summary=?,completed=?,error=?,next_attempt=?,lease_until=NULL,lease_token=NULL WHERE id=?', (state, redact(summary), now if state in TERMINAL else None, 'Bridge interrupted; execution must not be replayed.' if state=='unknown' else None, now+30, job_id))
        from .knowledge_workflows import job_ended
        job_ended(c,job_id,state,summary,now)
        from .worklog import update_job
        if job['state']=='unknown' and state in ('running','completed'):
            c.execute("UPDATE ticket_blockers SET cleared=? WHERE job_id=? AND cleared IS NULL AND reason=?",(now,job_id,'The investigation connection was interrupted. Its outcome is being checked; commands will not be replayed.'))
        update_job(c, store, dict(job), state, now, redact(summary))
        if state in TERMINAL:
            from .handoff import release
            release(c, job)
        if state in ('completed', 'failed') and summary and job['mode'] != 'triage':
            c.execute('INSERT OR IGNORE INTO ai_messages VALUES(?,?,?,?,?,?)', (uid(), job['incident_id'], job_id, 'assistant', redact(summary), now))
        if (state in TERMINAL or state=='unknown') and state != job['state']:
            store.timeline(c, job['incident_id'], 'ai_'+state, redact(summary or document['state']), actor='hermes', now=now)
            store.audit(c, 'ai.'+state, job_id, actor='hermes')


def cancel(store, job_id):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job = c.execute('SELECT * FROM ai_jobs WHERE id=?', (job_id,)).fetchone()
        if not job:
            raise ValueError('Unknown AI execution.')
        if job['state'] not in TERMINAL:
            c.execute("UPDATE ai_jobs SET state='cancelled',completed=?,lease_until=NULL,lease_token=NULL WHERE id=?", (time.time(), job_id))
            from .knowledge_workflows import job_ended
            job_ended(c,job_id,'cancelled','Investigation stopped by administrator.',time.time())
            from .worklog import end
            end(c,job['incident_id'],'hermes','Stopped',time.time())
            store.timeline(c, job['incident_id'], 'ai_cancelled', 'Further model requests denied; in-flight usage remains reserved.', actor='user')
            store.audit(c, 'ai.cancelled', job_id)
            from .handoff import release
            release(c, job)


def bridge_request(vault, job, method, path, body=b'', ca=True):
    secret = vault.decrypt(job['bridge_secret'])
    headers = hermes_headers(secret, body, job['id'])
    with requests.request(method, job['endpoint']+path, data=body, headers=headers, verify=ca or True, timeout=(3, 10), stream=True, allow_redirects=False) as response:
        data = bounded_json(response)
        if response.status_code != 200 or not authenticate(secret, json.dumps(data, separators=(',', ':'), sort_keys=True).encode(), response.headers):
            raise ValueError('Bridge response is unavailable or unauthenticated.')
        return data


def tick(store, vault, now=None):
    now = time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        # Expiry fences calls, but never releases uncertain provider usage.
        for job in c.execute("SELECT * FROM ai_jobs WHERE expires<=? AND state NOT IN ('completed','failed','cancelled','expired')", (now,)).fetchall():
            c.execute("UPDATE ai_jobs SET state='expired',completed=? WHERE id=?", (now, job['id']))
            from .knowledge_workflows import job_ended
            job_ended(c,job['id'],'expired','The investigation timed out before verification.',now)
            from .handoff import release
            release(c, job)
            from .worklog import update_job
            update_job(c,store,dict(job),'expired',now,'The investigation timed out. Review its last result before continuing.')
            store.timeline(c, job['incident_id'], 'ai_expired', 'AI execution expired; unknown usage remains reserved.', now=now)
        active = c.execute("SELECT 1 FROM ai_jobs WHERE state IN ('dispatching','running','unknown')").fetchone()
        sql = "SELECT * FROM ai_jobs WHERE state IN ('dispatching','running','unknown') AND next_attempt<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY created LIMIT 1" if active else "SELECT * FROM ai_jobs WHERE state='pending' AND next_attempt<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY created LIMIT 1"
        row = c.execute(sql, (now, now)).fetchone()
        bridge = setting(c, 'hermes_config', BRIDGE_DEFAULTS)
        if not row or not bridge.get('enabled'):
            return False
        job = dict(row)
        incident = c.execute('SELECT status,closed FROM incidents WHERE id=?', (job['incident_id'],)).fetchone()
        if incident['closed'] is not None or incident['status']=='Resolved':
            c.execute("UPDATE ai_jobs SET state='cancelled',completed=? WHERE id=?", (now, job['id']))
            from .handoff import release
            release(c, job)
            from .worklog import end
            end(c,job['incident_id'],'hermes','Stopped',time.time())
            store.timeline(c, job['incident_id'], 'ai_cancelled', 'Incident resolved; further model calls denied.', now=now)
            return True
        from .maintenance_ai import blocked,fresh_after_pause
        if job['state']=='pending' and job['automatic']:
            if blocked(c,job,now=now):
                c.execute('UPDATE ai_jobs SET maintenance_paused_at=coalesce(maintenance_paused_at,?),next_attempt=? WHERE id=?',(now,now+15,job['id']))
                return False
            if job['maintenance_paused_at'] is not None:
                from .maintenance_ai import post_window_ready
                target_machine=c.execute('SELECT machine_id FROM incidents WHERE id=?',(job['incident_id'],)).fetchone()[0]
                if not post_window_ready(c,job['incident_id'],target_machine,now) or not fresh_after_pause(c,job['incident_id'],now) or c.execute("SELECT 1 FROM incident_sources s JOIN checks ch ON ch.id=s.check_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE s.incident_id=? AND ch.enabled=1 AND ch.kind!='manual' AND (o.at IS NULL OR o.at<?)",(job['incident_id'],job['maintenance_paused_at'])).fetchone():
                    c.execute('UPDATE checks SET next_run=0 WHERE id IN (SELECT check_id FROM incident_sources WHERE incident_id=?)',(job['incident_id'],))
                    c.execute('UPDATE ai_jobs SET next_attempt=? WHERE id=?',(now+15,job['id']))
                    return False
                # Replace stale snapshots before dispatch, preserving task and incident evidence.
                from .machine_context import context as current_context
                from .evidence import summary as current_summary
                document=json.loads(job['evidence']);document['machine']=current_context(c,c.execute('SELECT machine_id FROM incidents WHERE id=?',(job['incident_id'],)).fetchone()[0],now)
                document['evidence_available']=current_summary(c,target_machine,now)
                from .ticket_groups import context as group_context
                document['affected_targets']=group_context(c,job['incident_id'],now)
                document['maintenance']={'active':False,'note':'Maintenance ended; fresh monitoring required before dispatch.'}
                encoded=json.dumps(evidence_snapshot(document))
                if len(encoded)>16000:document['machine']={'coverage':'Use targets/evidence for fresh host readings.'};encoded=json.dumps(evidence_snapshot(document))
                job['evidence']=encoded
                c.execute('UPDATE ai_jobs SET evidence=?,maintenance_paused_at=NULL WHERE id=?',(encoded,job['id']))
        token = uid()
        was_pending = job['state']=='pending'
        c.execute("UPDATE ai_jobs SET state=CASE WHEN state='pending' THEN 'dispatching' ELSE state END,lease_until=?,lease_token=?,attempts=attempts+1 WHERE id=?", (now+45, token, job['id']))
    try:
        if was_pending:
            body = json.dumps({'version': 1, 'execution_id': job['id'], 'model': job['model'], 'evidence': job['evidence'], 'credential': vault.decrypt(job['credential']), 'max_calls': job['max_calls'], 'expires': job['expires']}, separators=(',', ':'), sort_keys=True).encode()
            if job['execution_mode']=='codex':
                payload=json.loads(body)
                if job['command_tools']: payload['command_tools']=True
                payload.update(execution_mode='codex',reasoning=job['reasoning_effort'],timeout_seconds=job['run_timeout'])
                body=json.dumps(payload,separators=(',',':'),sort_keys=True).encode()
            document = bridge_request(vault, job, 'POST', '/v1/executions', body, bridge.get('ca'))
        else:
            # Never POST again after ambiguous acceptance. Durable status query only.
            document = bridge_request(vault, job, 'GET', '/v1/executions/'+job['id'], ca=bridge.get('ca'))
        apply_status(store, job['id'], document, now)
    except (requests.RequestException, ValueError):
        with store.connect() as c:
            c.execute("UPDATE ai_jobs SET state=CASE WHEN state='dispatching' THEN 'unknown' ELSE state END,error='Bridge outcome unknown; polling without replay.',next_attempt=?,lease_until=NULL,lease_token=NULL WHERE id=? AND lease_token=?", (now+min(3600, 10*2**min(job['attempts'], 8)), job['id'], token))
            if was_pending:
                from .worklog import update_job
                update_job(c,store,job,'unknown',now,'The investigation connection was interrupted. Its outcome is being checked; commands will not be replayed.')
    return True


def automatic_tick(store,vault):
    """One opt-in automatic run per incident; a blocked ticket cannot starve others."""
    from .ticket_groups import tick as group_tick
    group_tick(store)
    bridge=store.setting('hermes_config',BRIDGE_DEFAULTS)
    if not bridge.get('enabled') or not bridge.get('automatic'): return 0
    eligible=SEVERITIES[SEVERITIES.index(bridge.get('minimum','high')):]
    placeholders=','.join('?' for _ in eligible)
    candidates=store.rows("SELECT id FROM incidents WHERE closed IS NULL AND status!='Resolved' AND (severity IN ("+placeholders+") OR json_extract(report,'$.manual_ticket')=1) AND NOT EXISTS (SELECT 1 FROM ai_jobs WHERE incident_id=incidents.id) AND NOT EXISTS (SELECT 1 FROM incident_control WHERE incident_id=incidents.id AND owner='user') AND NOT EXISTS (SELECT 1 FROM timeline WHERE incident_id=incidents.id AND kind='ai_auto_blocked' AND at>?) ORDER BY first_seen LIMIT 100",(*eligible,time.time()-900))
    queued=0
    for incident in candidates:
        from .health_rules import incident_paused
        with store.connect() as c:
            if incident_paused(c,incident['id']):continue
        with store.connect() as c:
            from .applications import upstream_incident
            root=upstream_incident(c,incident['id'],time.time())
            root_row=c.execute('SELECT severity FROM incidents WHERE id=?',(root,)).fetchone() if root else None
            if root and root_row and root_row['severity'] in eligible:
                left,right=sorted((incident['id'],root))
                c.execute('INSERT OR IGNORE INTO incident_links VALUES(?,?,?)',(left,right,'Explicit application dependency: investigating the upstream failure first; cause unconfirmed.'))
                continue
        try:
            if request_job(store,vault,incident['id'],automatic=True): queued+=1
        except ValueError as exc:
            # Record a useful blocker without repeatedly adding the same timeline entry.
            reason=str(exc)[:500]
            with store.connect() as c:
                previous=c.execute("SELECT text FROM timeline WHERE incident_id=? AND kind='ai_auto_blocked' ORDER BY at DESC LIMIT 1",(incident['id'],)).fetchone()
                if not previous or previous['text']!=reason:
                    store.timeline(c,incident['id'],'ai_auto_blocked',reason,actor='monitor')
            continue
    return queued


def run(store, vault, stop):
    """Separate bounded orchestration loop; external AI never blocks check probes."""
    import logging
    while not stop.is_set():
        try:
            automatic_tick(store,vault)
            tick(store,vault)
        except Exception:
            logging.getLogger(__name__).exception('AI orchestration paused; durable jobs retained')
        stop.wait(5)


def automatic_status(store,incident):
    """Explain automatic admission without changing configuration or submitting work."""
    resolved=incident['closed'] is not None or incident['status']=='Resolved'
    with store.connect() as c:
        from .maintenance_ai import state
        if not resolved and state(c,incident['machine_id'],incident=incident['id'])['active']:return 'Maintenance active: automatic investigations and changes are paused. Manual diagnostics remain available.'
        from .ticket_groups import coordinating_primary
        if not resolved and coordinating_primary(c,incident['id']):return 'Related failure: the primary ticket coordinates automatic investigation. This ticket keeps its own recovery checks.'
    jobs=store.rows('SELECT id,state,error FROM ai_jobs WHERE incident_id=? ORDER BY created DESC LIMIT 1',(incident['id'],))
    if jobs:
        job=jobs[0]
        return 'Ticket resolved.' if resolved else {'pending':'AI investigation pending.','dispatching':'Starting the investigation.','running':'AI is investigating.','completed':'Investigation complete.','failed':'Investigation needs attention.','unknown':'Investigation interrupted; review before continuing.','cancelled':'AI investigation stopped.','expired':'Investigation timed out.'}.get(job['state'],'Waiting for AI.')
    bridge=store.setting('hermes_config',BRIDGE_DEFAULTS)
    if resolved: return 'No AI execution recorded for this ticket. It is resolved, so no automatic investigation will start now. Current ticket severity: '+incident['severity'].capitalize()+'; configured AI minimum: '+bridge.get('minimum','high').capitalize()+'.'
    if not bridge.get('enabled'): return 'Automatic AI not queued: AI is disabled. Enable it under Hermes & usage.'
    if not bridge.get('automatic'): return 'Automatic AI not queued: automatic triage is disabled under Hermes & usage.'
    minimum=bridge.get('minimum','high')
    if not json.loads(incident['report']).get('manual_ticket') and SEVERITIES.index(incident['severity'])<SEVERITIES.index(minimum): return 'Automatic AI not queued: this ticket is '+incident['severity'].capitalize()+', below the '+minimum.capitalize()+' minimum under Hermes & usage.'
    control=store.rows('SELECT owner,handling_mode FROM incident_control WHERE incident_id=?',(incident['id'],))
    if control and (control[0]['owner']=='user' or control[0]['handling_mode']!='automatic'): return 'Automatic AI not queued: ticket handling is paused or under human control.'
    blocked=store.rows("SELECT text FROM timeline WHERE incident_id=? AND kind='ai_auto_blocked' ORDER BY at DESC LIMIT 1",(incident['id'],))
    if blocked: return 'Automatic AI admission blocked: '+blocked[0]['text']
    return 'Eligible for automatic AI; waiting for the dispatcher. Queueing still requires available run limits and a compatible bridge.'


def queue_manual(store,vault,incident_id):
    """Queue administrator work immediately, with a durable actionable blocker on failure."""
    try:
        return request_job(store,vault,incident_id)
    except ValueError as exc:
        from .worklog import block
        with store.connect() as c:
            block(c,store,incident_id,None,str(exc),time.time())
        return None
