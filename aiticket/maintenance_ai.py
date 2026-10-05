"""Maintenance fences automatic admission and new AI changes, never running work."""
import json,time
from .policies import maintained


def state(c,machine,now=None,incident=None):
    now=time.time() if now is None else now
    windows=[];targets=set();current=machine
    while current and current not in targets:
        targets.add(current)
        row=c.execute('SELECT parent_id FROM machines WHERE id=?',(current,)).fetchone()
        current=row[0] if row else None
    from .policies import active
    for w in c.execute('SELECT * FROM maintenance_windows WHERE enabled=1'):
        if (w['machine_id'] is None or w['machine_id'] in targets) and active(w,now):
            windows.append({'name':w['name'],'ends_at':w['end'] if w['kind']=='once' else None,'timezone':w['timezone']})
    snooze=c.execute('SELECT max(c.maintenance_until) FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=? AND c.machine_id=?',(incident,machine)).fetchone()[0] if incident else None
    if snooze and snooze>now:windows.append({'name':'Check snooze','ends_at':snooze,'timezone':None})
    return {'active':bool(windows),'windows':windows,'note':'Monitoring continues. Automatic investigations and new automatic changes pause; manually requested diagnostics remain available.'}


def blocked(c,job,machine=None,now=None):
    if not job:return False
    incident=c.execute('SELECT machine_id FROM incidents WHERE id=?',(job['incident_id'],)).fetchone()
    return bool(incident and state(c,machine or incident['machine_id'],now,job['incident_id'])['active'])


def check_change(c,job_id,machine,command=None,method=None,now=None):
    if not job_id:return
    job=c.execute('SELECT * FROM ai_jobs WHERE id=?',(job_id,)).fetchone()
    if not job:return
    from .host_access import read_only
    diagnostic=method=='GET' or (command is not None and read_only(command))
    if job['read_only'] and not diagnostic:raise ValueError('This status/article investigation is read-only. Open a ticket to request changes.')
    if not blocked(c,job,machine,now):return
    from .host_access import read_only
    if method=='GET' or (command is not None and read_only(command)):return
    if job['automatic'] or not job['maintenance_changes']:
        raise ValueError('Maintenance is active on this target. Automatic changes are paused. Start a manual investigation and explicitly allow changes during maintenance to proceed.')


def fresh_after_pause(c,incident,now):
    """Before resuming automatic work, all enabled incident sources need current results."""
    rows=c.execute('SELECT ch.interval,ch.enabled,ch.kind,o.at,o.health FROM incident_sources s JOIN checks ch ON ch.id=s.check_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE s.incident_id=?',(incident,)).fetchall()
    return bool(rows) and all(not r['enabled'] or r['kind']=='manual' or (r['at'] is not None and 0<=now-r['at']<=max(180,r['interval']*3) and r['health']!='unknown') for r in rows)


def last_end(c,machine,now):
    from datetime import datetime,timedelta
    from zoneinfo import ZoneInfo
    targets=set();current=machine
    while current and current not in targets:
        targets.add(current);row=c.execute('SELECT parent_id FROM machines WHERE id=?',(current,)).fetchone();current=row[0] if row else None
    ends=[]
    for w in c.execute('SELECT * FROM maintenance_windows WHERE enabled=1'):
        if w['machine_id'] is not None and w['machine_id'] not in targets:continue
        if w['kind']=='once':
            if w['end']<=now:ends.append(w['end'])
        else:
            local=datetime.fromtimestamp(now,ZoneInfo(w['timezone']))
            day=local-timedelta(days=(local.weekday()-w['weekday'])%7)
            end=day.replace(hour=w['end_minute']//60,minute=w['end_minute']%60,second=0,microsecond=0).timestamp()
            if end>now:end=(day-timedelta(days=7)).replace(hour=w['end_minute']//60,minute=w['end_minute']%60,second=0,microsecond=0).timestamp()
            ends.append(end)
    return max(ends,default=0)


def post_window_ready(c,incident,machine,now):
    end=last_end(c,machine,now)
    if not end:return True
    rows=c.execute("SELECT ch.enabled,ch.kind,o.at,o.health FROM incident_sources s JOIN checks ch ON ch.id=s.check_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE s.incident_id=?",(incident,)).fetchall()
    return all(not r['enabled'] or r['kind']=='manual' or (r['at'] is not None and end<=r['at']<=now and r['health']!='unknown') for r in rows)
