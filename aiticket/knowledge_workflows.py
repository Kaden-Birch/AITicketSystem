"""Versioned procedures guide existing ticket tools; they never grant permissions."""
import json,time
from .db import uid
from .diagnostics import redact

PHASES=('prerequisites','diagnostics','fix','verification')

def definition(c,article):
    row=c.execute('SELECT w.*,a.title,a.status,f.machine_id,f.service_id FROM kb_workflows w JOIN kb_articles a ON a.id=w.article_id JOIN kb_folders f ON f.id=a.folder_id WHERE w.article_id=?',(article,)).fetchone()
    return dict(row)|{'steps':json.loads(row['steps'])} if row else None

def save(store,article,values):
    steps={key:redact(values.get(key,'').strip()) for key in PHASES}
    if any(not 1<=len(value)<=4000 for value in steps.values()):raise ValueError('Fill in all four procedure sections, up to 4,000 characters each.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT version,status FROM kb_articles WHERE id=?',(article,)).fetchone()
        if not row:raise ValueError('Choose an existing article.')
        old=definition(c,article)
        if old and str(old['version'])!=values.get('version'):raise ValueError('This workflow changed. Reload before saving.')
        version=old['version']+1 if old else 1
        c.execute('INSERT INTO kb_workflows VALUES(?,?,?,?,?,?) ON CONFLICT(article_id) DO UPDATE SET version=excluded.version,article_version=excluded.article_version,steps=excluded.steps,enabled=excluded.enabled,updated=excluded.updated',(article,version,row['version'],json.dumps(steps),int(values.get('enabled')=='yes'),time.time()))
        store.audit(c,'knowledge.workflow_saved',article,{'version':version})

def available(c,machines):
    scope="f.machine_id IS NULL";args=[]
    if machines:scope+=' OR f.machine_id IN ('+','.join('?' for _ in machines)+')';args=sorted(machines)
    rows=c.execute("SELECT w.article_id,w.version,a.title,f.machine_id FROM kb_workflows w JOIN kb_articles a ON a.id=w.article_id JOIN kb_folders f ON f.id=a.folder_id WHERE w.enabled=1 AND a.status='published' AND a.version=w.article_version AND ("+scope+") ORDER BY w.updated DESC LIMIT 10",args).fetchall()
    return [dict(r)|stats(c,r['article_id']) for r in rows]


def start(c,store,article,machine,incident,job):
    if not isinstance(article,str) or not 1<=len(article)<=100:raise ValueError('Choose a valid workflow article.')
    plan=definition(c,article)
    if not plan or not plan['enabled'] or plan['status']!='published':raise ValueError('Publish the article and enable its workflow first.')
    article_version=c.execute('SELECT version FROM kb_articles WHERE id=?',(article,)).fetchone()[0]
    if article_version!=plan['article_version']:raise ValueError('The article changed. Review and save its workflow before reusing it.')
    if plan['machine_id'] and plan['machine_id']!=machine:raise ValueError('This workflow belongs to a different host.')
    if not c.execute('SELECT 1 FROM ai_jobs j JOIN incidents i ON i.id=j.incident_id WHERE j.id=? AND i.id=? AND i.machine_id=?',(job,incident,machine)).fetchone():raise ValueError('Procedure runs must match this investigation’s host.')
    active=c.execute('SELECT id,state FROM kb_workflow_runs WHERE article_id=? AND job_id=?',(article,job)).fetchone()
    if active:return active['id']
    identifier=uid();now=time.time()
    c.execute('INSERT INTO kb_workflow_runs(id,article_id,version,plan,machine_id,incident_id,job_id,created) VALUES(?,?,?,?,?,?,?,?)',(identifier,article,plan['version'],json.dumps(plan['steps']),machine,incident,job,now))
    store.timeline(c,incident,'workflow_started','Using saved procedure: '+plan['title'],actor='hermes',now=now)
    store.audit(c,'knowledge.workflow_started',identifier,{'article':article,'version':plan['version']},actor='hermes')
    return identifier

def tool(c,store,payload,machine,incident,job):
    article=payload.get('article_id');run=start(c,store,article,machine,incident,job)
    row=c.execute('SELECT * FROM kb_workflow_runs WHERE id=?',(run,)).fetchone()
    phase=payload.get('phase');outcome=payload.get('outcome')
    if phase or outcome:
        note=payload.get('summary','')
        if not isinstance(note,str):raise ValueError('Describe the current evidence in text.')
        note=note.strip()
        if phase not in PHASES or outcome not in ('passed','failed','blocked') or not 1<=len(note)<=2000:raise ValueError('Record a procedure phase, result and concise current-evidence explanation.')
        if row['finished'] is not None:raise ValueError('This procedure run has ended.')
        prior=PHASES[:PHASES.index(phase)]
        if any(not c.execute("SELECT 1 FROM kb_workflow_events WHERE run_id=? AND phase=? AND outcome='passed'",(run,p)).fetchone() for p in prior):raise ValueError('Check prerequisites and earlier steps before proceeding.')
        if phase=='fix' and outcome=='passed':
            from .maintenance_ai import state
            jobrow=c.execute('SELECT read_only,automatic,maintenance_changes FROM ai_jobs WHERE id=?',(job,)).fetchone()
            if jobrow['read_only']:raise ValueError('Read-only investigations cannot apply a fix.')
            if state(c,machine,time.time(),incident)['active'] and (jobrow['automatic'] or not jobrow['maintenance_changes']):raise ValueError('Changes are paused for maintenance. Manual troubleshooting remains available.')
        now=time.time();state='failed' if outcome=='failed' else 'blocked' if outcome=='blocked' else 'awaiting_verification' if phase=='verification' else 'checking' if phase in ('prerequisites','diagnostics') else 'applying'
        c.execute('INSERT INTO kb_workflow_events VALUES(?,?,?,?,?,?)',(uid(),run,phase,outcome,redact(note),now))
        c.execute('UPDATE kb_workflow_runs SET state=?,phase=?,summary=?,finished=? WHERE id=?',(state,phase,redact(note),now if outcome in ('failed','blocked') else None,run))
        store.audit(c,'knowledge.workflow_step',run,{'phase':phase,'outcome':outcome},actor='hermes')
    return {'run_id':run,'state':c.execute('SELECT state FROM kb_workflow_runs WHERE id=?',(run,)).fetchone()[0],'version':row['version'],'steps':json.loads(row['plan']),'note':'Check current applicability and prerequisites before commands. Record each phase with current evidence using workflow. Results are AI-reported until independent monitoring verifies recovery. Host permissions, approvals and maintenance still apply. Stop on failure; do not replay unknown commands.'}

def verified(c,incident,now):
    # A healthy ticket alone does not establish that every procedure step ran.
    c.execute("UPDATE kb_workflow_runs SET state='verified',finished=? WHERE incident_id=? AND state='awaiting_verification' AND finished IS NULL AND EXISTS(SELECT 1 FROM ai_jobs j WHERE j.id=kb_workflow_runs.job_id AND j.state='completed' AND j.resolution_summary IS NOT NULL)",(now,incident))

def job_ended(c,job,state,summary,now):
    if state in ('failed','cancelled','unknown','expired'):
        c.execute("UPDATE kb_workflow_runs SET state=?,summary=?,finished=? WHERE job_id=? AND finished IS NULL",('failed' if state=='failed' else 'interrupted',redact(summary or 'Investigation ended before verification.')[:2000],now,job))

def history(store,article):
    runs=store.rows('SELECT r.*,m.name host FROM kb_workflow_runs r JOIN machines m ON m.id=r.machine_id WHERE article_id=? ORDER BY created DESC LIMIT 20',(article,))
    for row in runs:row['events']=store.rows('SELECT phase,outcome,note,at FROM kb_workflow_events WHERE run_id=? ORDER BY at',(row['id'],))
    return runs


def check_change(c,job):
    for run in c.execute('SELECT r.*,w.enabled,w.version current_version,w.article_version reviewed_version,a.version source_version,a.status article_status FROM kb_workflow_runs r JOIN kb_workflows w ON w.article_id=r.article_id JOIN kb_articles a ON a.id=r.article_id WHERE r.job_id=?',(job,)).fetchall():
        if not run['enabled'] or run['version']!=run['current_version'] or run['reviewed_version']!=run['source_version'] or run['article_status']!='published':raise ValueError('The saved procedure changed or was disabled. Review it before another change.')
        if run['finished'] is not None or run['state']=='awaiting_verification':raise ValueError('This procedure has ended or is awaiting verification. Start a new reviewed investigation before further changes.')
        if any(not c.execute("SELECT 1 FROM kb_workflow_events WHERE run_id=? AND phase=? AND outcome='passed'",(run['id'],phase)).fetchone() for phase in ('prerequisites','diagnostics')):raise ValueError('Confirm this procedure’s prerequisites and diagnostics before changing the host.')


def stats(c,article):
    latest=c.execute("SELECT finished,m.name host FROM kb_workflow_runs r JOIN machines m ON m.id=r.machine_id WHERE article_id=? AND state='verified' ORDER BY finished DESC LIMIT 1",(article,)).fetchone()
    failed=c.execute("SELECT phase,summary,finished,m.name host FROM kb_workflow_runs r JOIN machines m ON m.id=r.machine_id WHERE article_id=? AND state IN ('failed','blocked','interrupted') ORDER BY finished DESC LIMIT 1",(article,)).fetchone()
    return {'last_verified':dict(latest) if latest else None,'last_failure':dict(failed) if failed else None}
