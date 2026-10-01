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

BRIDGE_DEFAULTS = {'url': '', 'ca': '', 'enabled': False, 'automatic': False, 'minimum': 'high', 'runtime_verified': False}
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


def request_job(store, vault, incident_id, automatic=False, now=None, mode='triage', question='', request_id=None, source_ids=(), diagnostic_ids=(), resume_checkpoint=None, expected_generation=None, recovery_target=None):
    now = time.time() if now is None else now
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
    fingerprint = hashlib.sha256(json.dumps({'mode': mode, 'question': question.strip(), 'sources': sorted(source_ids), 'diagnostics': sorted(diagnostic_ids), 'checkpoint': resume_checkpoint, 'generation': expected_generation,'recovery_target':recovery_target}, sort_keys=True).encode()).hexdigest()
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
        if not setting(c, 'hermes_secret') or not setting(c, 'ai_provider_secret'):
            raise ValueError('Save both bridge and model-provider credentials.')
        incident = c.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if not incident or incident['closed'] is not None or incident['status'] == 'Resolved':
            raise ValueError('Investigation requires an active unresolved incident.')
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
            question = checkpoint_data['question']
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
        if automatic and (not bridge.get('automatic') or SEVERITIES.index(incident['severity']) < SEVERITIES.index(bridge['minimum'])):
            return None
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
        c.execute('INSERT INTO ai_jobs(id,incident_id,state,created,expires,model,allowance,max_calls,evidence,credential_digest,credential,endpoint,bridge_secret,next_attempt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (job_id, incident_id, 'pending', now, now+3600, cfg['model'], min(cfg['triage_tokens'], cfg['incident_tokens']), min(cfg['max_turns'], 100), evidence, digest(token), vault.encrypt(token), bridge['url'].rstrip('/'), setting(c, 'hermes_secret'), now))
        c.execute('UPDATE ai_jobs SET mode=?,request_id=?,request_fingerprint=?,allowance=? WHERE id=?', (mode, request_id, fingerprint, min(cfg['triage_tokens'], cfg['incident_tokens']) if mode=='triage' else cfg['incident_tokens'], job_id))
        generation = ownership['generation']+1
        c.execute("UPDATE incident_control SET owner='ai',generation=?,updated=? WHERE incident_id=?", (generation, now, incident_id))
        c.execute('UPDATE ai_jobs SET control_generation=? WHERE id=?', (generation, job_id))
        if resume_checkpoint:
            store.timeline(c, incident_id, 'handoff_ai', 'New read-only execution resumed from checkpoint '+resume_checkpoint+' · '+job_id, actor='user', now=now)
            store.audit(c, 'handoff.ai', incident_id, {'checkpoint_id':resume_checkpoint, 'job_id':job_id})
        if mode != 'triage':
            c.execute('INSERT INTO ai_messages VALUES(?,?,?,?,?,?)', (uid(), incident_id, job_id, 'user', redact(question.strip()), now))
            store.timeline(c, incident_id, 'ai_question', mode+': '+redact(question.strip())+' · Execution '+job_id, actor='user', now=now)
        store.timeline(c, incident_id, 'ai_queued', 'Read-only AI '+mode+' queued: '+job_id, actor='user' if not automatic else 'monitor', now=now)
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
        valid_configuration(cfg, bridge, provider, job['mode'] if job else 'triage')
        incident = c.execute('SELECT closed,status FROM incidents WHERE id=?', (job['incident_id'],)).fetchone() if job else None
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
        if state=='completed' and not c.execute('SELECT 1 FROM ai_calls WHERE job_id=?', (job_id,)).fetchone():
            raise ValueError('Completion without a metered model call is invalid.')
        if state=='completed' and job['mode']=='recovery_proposal':
            from .recovery_drafts import record
            try:
                summary=record(c,store,job,summary,now)
            except ValueError as exc:
                state='failed'
                summary=str(exc)
        c.execute('UPDATE ai_jobs SET state=?,summary=?,completed=?,error=?,next_attempt=?,lease_until=NULL,lease_token=NULL WHERE id=?', (state, redact(summary), now if state in TERMINAL else None, 'Bridge interrupted; execution must not be replayed.' if state=='unknown' else None, now+30, job_id))
        if state in TERMINAL:
            from .handoff import release
            release(c, job)
        if state in ('completed', 'failed') and summary and job['mode'] != 'triage':
            c.execute('INSERT OR IGNORE INTO ai_messages VALUES(?,?,?,?,?,?)', (uid(), job['incident_id'], job_id, 'assistant', redact(summary), now))
        if (state in TERMINAL or state=='unknown') and state != job['state']:
            store.timeline(c, job['incident_id'], 'ai_'+state, 'AI inference (unverified): '+redact(summary or document['state'])+' · Execution '+job_id, actor='hermes', now=now)
            store.audit(c, 'ai.'+state, job_id, actor='hermes')


def cancel(store, job_id):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job = c.execute('SELECT * FROM ai_jobs WHERE id=?', (job_id,)).fetchone()
        if not job:
            raise ValueError('Unknown AI execution.')
        if job['state'] not in TERMINAL:
            c.execute("UPDATE ai_jobs SET state='cancelled',completed=?,lease_until=NULL,lease_token=NULL WHERE id=?", (time.time(), job_id))
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
            from .handoff import release
            release(c, job)
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
            store.timeline(c, job['incident_id'], 'ai_cancelled', 'Incident resolved; further model calls denied.', now=now)
            return True
        token = uid()
        was_pending = job['state']=='pending'
        c.execute("UPDATE ai_jobs SET state=CASE WHEN state='pending' THEN 'dispatching' ELSE state END,lease_until=?,lease_token=?,attempts=attempts+1 WHERE id=?", (now+45, token, job['id']))
    try:
        if was_pending:
            body = json.dumps({'version': 1, 'execution_id': job['id'], 'model': job['model'], 'evidence': job['evidence'], 'credential': vault.decrypt(job['credential']), 'max_calls': job['max_calls'], 'expires': job['expires']}, separators=(',', ':'), sort_keys=True).encode()
            document = bridge_request(vault, job, 'POST', '/v1/executions', body, bridge.get('ca'))
        else:
            # Never POST again after ambiguous acceptance. Durable status query only.
            document = bridge_request(vault, job, 'GET', '/v1/executions/'+job['id'], ca=bridge.get('ca'))
        apply_status(store, job['id'], document, now)
    except (requests.RequestException, ValueError):
        with store.connect() as c:
            c.execute("UPDATE ai_jobs SET state=CASE WHEN state='dispatching' THEN 'unknown' ELSE state END,error='Bridge outcome unknown; polling without replay.',next_attempt=?,lease_until=NULL,lease_token=NULL WHERE id=? AND lease_token=?", (now+min(3600, 10*2**min(job['attempts'], 8)), job['id'], token))
    return True


def run(store, vault, stop):
    """Separate bounded orchestration loop; external AI never blocks check probes."""
    import logging
    while not stop.is_set():
        try:
            bridge = store.setting('hermes_config', BRIDGE_DEFAULTS)
            if bridge.get('enabled') and bridge.get('automatic'):
                # At most one triage per incident, including previous failures/cancellations.
                candidates = store.rows("SELECT id FROM incidents WHERE closed IS NULL AND status!='Resolved' AND NOT EXISTS (SELECT 1 FROM ai_jobs WHERE incident_id=incidents.id) ORDER BY first_seen LIMIT 20")
                for incident in candidates:
                    try:
                        request_job(store, vault, incident['id'], automatic=True)
                    except ValueError:
                        break
            tick(store, vault)
        except Exception:
            logging.getLogger(__name__).exception('AI orchestration paused; durable jobs retained')
        stop.wait(5)
