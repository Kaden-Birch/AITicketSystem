"""Persistent maintenance and notification pacing; no AI or action authorization."""
import json
import time
from datetime import datetime
from zoneinfo import ZoneInfo, reset_tzpath

# Use the shipped, versioned tzdata package consistently on hosts and containers.
reset_tzpath(())
from .db import uid

DEFAULTS={'reminder_seconds':0,'escalate_after_seconds':0,'escalate_to':'high'}


def active(window,now):
    if not window['enabled']:
        return False
    if window['kind']=='once':
        return window['start']<=now<window['end']
    local=datetime.fromtimestamp(now,ZoneInfo(window['timezone']))
    minute=local.hour*60+local.minute
    return local.weekday()==window['weekday'] and window['start_minute']<=minute<window['end_minute']


def maintained(c,machine_id,now):
    targets=set()
    current=machine_id
    while current and current not in targets:
        targets.add(current)
        row=c.execute('SELECT parent_id FROM machines WHERE id=?',(current,)).fetchone()
        current=row[0] if row else None
    return any((w['machine_id'] is None or w['machine_id'] in targets) and active(w,now) for w in c.execute('SELECT * FROM maintenance_windows WHERE enabled=1'))


def instant(value,zone):
    local=datetime.fromisoformat(value)
    if local.tzinfo:
        raise ValueError('Use local date/time without an offset; select the timezone explicitly.')
    aware=local.replace(tzinfo=ZoneInfo(zone),fold=0)
    stamp=aware.timestamp()
    if datetime.fromtimestamp(stamp,ZoneInfo(zone)).replace(tzinfo=None)!=local:
        raise ValueError('This local time does not exist due to a clock change.')
    return stamp


def add_window(store,name,machine_id,kind,timezone,values):
    try:
        ZoneInfo(timezone)
    except Exception:
        raise ValueError('Unknown timezone; use an IANA name such as America/Edmonton.') from None
    if not 1<=len(name)<=100 or kind not in ('once','weekly'):
        raise ValueError('Invalid maintenance name or type.')
    start=end=weekday=start_minute=end_minute=None
    if kind=='once':
        start,end=instant(values.get('start',''),timezone),instant(values.get('end',''),timezone)
        if not 0<end-start<=31*86400:
            raise ValueError('Maintenance must end after its start and last at most 31 days.')
    else:
        weekday=int(values.get('weekday',0))
        def minutes(value):
            parsed=datetime.strptime(value,'%H:%M')
            return parsed.hour*60+parsed.minute
        start_minute,end_minute=minutes(values.get('start_time','')),minutes(values.get('end_time',''))
        if not 0<=weekday<=6 or end_minute<=start_minute:
            raise ValueError('Weekly window must end later on the same day; split overnight windows.')
    with store.connect() as c:
        if machine_id and not c.execute('SELECT 1 FROM machines WHERE id=?',(machine_id,)).fetchone():
            raise ValueError('Unknown machine.')
        identifier=uid()
        c.execute('INSERT INTO maintenance_windows VALUES(?,?,?,?,?,?,?,?,?,?,1)',(identifier,name,machine_id,kind,timezone,start,end,weekday,start_minute,end_minute))
        store.audit(c,'maintenance.created',identifier,{'kind':kind,'machine_id':machine_id,'timezone':timezone})
    return identifier


def fresh_failure(c,incident,now):
    for row in c.execute('SELECT s.report,c.enabled,c.interval FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(incident['id'],)):
        report=json.loads(row['report'])
        if row['enabled'] and report.get('observed')=='down' and now-report.get('observed_at',0)<=max(180,row['interval']*3):
            return True
    return False


def notifications(store,now=None):
    from .engine import SEVERITIES,enqueue
    now=time.time() if now is None else now
    settings=store.setting('notification_policy',DEFAULTS)
    if not settings['reminder_seconds'] and not settings['escalate_after_seconds']:
        return
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        for incident in c.execute("SELECT * FROM incidents WHERE closed IS NULL AND status<>'Resolved'").fetchall():
            if incident['silence_until']>now or maintained(c,incident['machine_id'],now) or not fresh_failure(c,incident,now):
                continue
            if c.execute('SELECT 1 FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=? AND c.maintenance_until>?',(incident['id'],now)).fetchone():
                continue
            age=max(0,now-incident['first_seen'])
            delay=settings['escalate_after_seconds']
            severity=incident['severity']
            if delay and age>=delay and SEVERITIES.index(settings['escalate_to'])>SEVERITIES.index(severity):
                severity=settings['escalate_to']
                report=json.loads(incident['report'])
                report['severity']=severity
                report['escalation_reason']='Configured persistence threshold reached; this does not authorize actions.'
                c.execute('UPDATE incidents SET severity=?,severity_floor=?,report=? WHERE id=?',(severity,severity,json.dumps(report),incident['id']))
                store.timeline(c,incident['id'],'escalated','Persistent incident escalated to '+severity+'.',now=now)
                enqueue(c,incident['id'],'escalation-'+severity,now,store)
            interval=settings['reminder_seconds']
            if interval and age>=interval:
                slot=int(age//interval)
                key=incident['id']+':reminder:'+str(slot)
                if c.execute('SELECT 1 FROM deliveries WHERE event_key=?',(key,)).fetchone():
                    continue
                # Coalesce old queued reminders rather than replaying every missed interval.
                c.execute("UPDATE deliveries SET state='superseded',lease_token=NULL,lease_until=NULL WHERE incident_id=? AND event_key LIKE ? AND state IN ('pending','leased')",(incident['id'],incident['id']+':reminder:%'))
                enqueue(c,incident['id'],'reminder:'+str(slot),now,store)
