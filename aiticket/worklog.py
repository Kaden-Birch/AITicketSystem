"""Server-owned work sessions and durable, deduplicated intervention requests."""
import json
import time
from urllib.parse import urlsplit
from .db import uid
from .diagnostics import redact


def public_url(value):
    value=value.strip().rstrip('/')
    if not value: return ''
    p=urlsplit(value)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.query or p.fragment or len(value)>1000:
        raise ValueError('Public application URL must be an HTTP or HTTPS address without credentials, query or fragment.')
    if p.port is not None and not 1<=p.port<=65535: raise ValueError('Invalid public URL port.')
    return value


def ticket_url(store,incident):
    base=store.setting('public_url','')
    return base+'/incidents/'+incident if base else ''


def end(c,incident,actor,outcome,now,summary=''):
    c.execute('UPDATE work_sessions SET ended=?,outcome=?,summary=? WHERE incident_id=? AND actor=? AND ended IS NULL',(now,outcome,redact(summary)[:1000],incident,actor))


def start(c,incident,actor,now,job=None):
    c.execute('INSERT OR IGNORE INTO work_sessions(id,incident_id,job_id,actor,started) VALUES(?,?,?,?,?)',(uid(),incident,job,actor,now))


def clear(c,incident,now):
    c.execute('UPDATE ticket_blockers SET cleared=? WHERE incident_id=? AND cleared IS NULL',(now,incident))


def block(c,store,incident,job,reason,now):
    reason=redact(reason.strip())[:1000]
    if not reason: raise ValueError('Explain what is needed to continue.')
    current=c.execute('SELECT * FROM ticket_blockers WHERE incident_id=? AND cleared IS NULL',(incident,)).fetchone()
    if current and current['reason']==reason: return current['id']
    clear(c,incident,now)
    identifier=uid()
    c.execute('INSERT INTO ticket_blockers VALUES(?,?,?,?,?,NULL)',(identifier,incident,job,reason,now))
    end(c,incident,'hermes','Waiting for you',now,reason)
    store.timeline(c,incident,'ai_blocker',reason,actor='hermes',now=now)
    from .engine import enqueue
    enqueue(c,incident,'blocker:'+identifier,now,store)
    return identifier


def update_job(c,store,job,state,now,summary=''):
    incident=job['incident_id']
    blocked=c.execute('SELECT 1 FROM ticket_blockers WHERE incident_id=? AND cleared IS NULL',(incident,)).fetchone()
    if state=='running' and not blocked: start(c,incident,'hermes',now,job['id'])
    elif state in ('completed','failed','cancelled','expired','unknown'):
        outcomes={'completed':'Session complete','failed':'Failed','cancelled':'Stopped','expired':'Expired','unknown':'Interrupted — outcome unknown'}
        end(c,incident,'hermes',outcomes[state],now,summary)
        if state in ('failed','expired','unknown') and not blocked:
            block(c,store,incident,job['id'],summary or outcomes[state]+'. Review the execution before resuming.',now)


def tick(store,now=None):
    now=time.time() if now is None else now
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        for session in c.execute('SELECT w.*,i.status FROM work_sessions w JOIN incidents i ON i.id=w.incident_id WHERE w.ended IS NULL').fetchall():
            if session['status']=='Resolved': end(c,session['incident_id'],session['actor'],'Resolved',now)
            elif session['job_id']:
                job=c.execute('SELECT * FROM ai_jobs WHERE id=?',(session['job_id'],)).fetchone()
                update_job(c,store,dict(job),job['state'],now,job['resolution_summary'] or job['summary'] or '')
        for job in c.execute("SELECT * FROM ai_jobs WHERE state='running'").fetchall():
            awaiting=c.execute("SELECT id FROM command_jobs WHERE ai_job_id=? AND state='awaiting' UNION ALL SELECT id FROM proxmox_api_jobs WHERE ai_job_id=? AND state='awaiting'",(job['id'],job['id'])).fetchone()
            if awaiting: block(c,store,job['incident_id'],job['id'],'Approval needed: review the queued operation in the machine command history.',now)
            elif c.execute("SELECT 1 FROM ticket_blockers WHERE job_id=? AND cleared IS NULL AND reason=?",(job['id'],'Approval needed: review the queued operation in the machine command history.')).fetchone(): clear(c,job['incident_id'],now)
            update_job(c,store,dict(job),'running',now)
        for row in c.execute("SELECT t.* FROM timeline t WHERE t.kind='ai_auto_blocked' AND t.at=(SELECT max(latest.at) FROM timeline latest WHERE latest.incident_id=t.incident_id AND latest.kind='ai_auto_blocked') AND NOT EXISTS(SELECT 1 FROM ticket_blockers b WHERE b.incident_id=t.incident_id AND b.created>=t.at) AND EXISTS(SELECT 1 FROM incidents i WHERE i.id=t.incident_id AND i.closed IS NULL AND i.status!='Resolved')").fetchall():
            block(c,store,row['incident_id'],None,row['text'],now)


def view(store,incident):
    now=time.time()
    sessions=store.rows('SELECT * FROM work_sessions WHERE incident_id=? ORDER BY started DESC LIMIT 200',(incident,))
    for s in sessions: s['seconds']=max(0,int((s['ended'] or now)-s['started']))
    totals=store.rows('SELECT actor,sum(COALESCE(ended,?)-started) seconds FROM work_sessions WHERE incident_id=? GROUP BY actor',(now,incident))
    return {'sessions':sessions,'totals':{s['actor']:int(s['seconds']) for s in totals},'blocker':next(iter(store.rows('SELECT * FROM ticket_blockers WHERE incident_id=? AND cleared IS NULL',(incident,))),None),'server_now':now}
