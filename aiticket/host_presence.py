"""Explicit intentional-offline state; never presents it as observed recovery."""
import json,time
from .db import uid


def reachability(c,check):
    if check['kind']=='agent':return True
    if check['kind']=='proxmox_linked':
        return bool(c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND kind IN ('qemu','lxc')",(check['machine_id'],)).fetchone())
    return False


def suppressed(c,check,now):
    machine=c.execute('SELECT offline_expected FROM machines WHERE id=?',(check['machine_id'],)).fetchone()
    if machine and machine[0] and reachability(c,check):return True
    # A stopped guest explains missing heartbeats, without proving service recovery.
    if check['kind']=='agent':
        return bool(c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND kind IN ('qemu','lxc') AND status='stopped' AND present=1 AND missing_since IS NULL AND last_seen>=?",(check['machine_id'],now-180)).fetchone())
    return False


def set_offline(store,machine,expected):
    from .handoff import take_control
    from .worklog import end,clear
    from .engine import enqueue
    now=time.time();closed=0
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM machines WHERE id=?',(machine,)).fetchone()
        if not row or machine.startswith(('unifi:','unifi-device:')):raise ValueError('Select a host.')
        c.execute('UPDATE machines SET offline_expected=? WHERE id=?',(int(expected),machine))
        if expected:
            for incident in c.execute("SELECT * FROM incidents WHERE machine_id=? AND closed IS NULL AND status<>'Resolved'",(machine,)).fetchall():
                sources=c.execute('SELECT checks.* FROM incident_sources s JOIN checks ON checks.id=s.check_id WHERE s.incident_id=?',(incident['id'],)).fetchall()
                if not sources:sources=c.execute('SELECT * FROM checks WHERE id=?',(incident['check_id'],)).fetchall()
                if not sources or not all(reachability(c,s) for s in sources):continue
                take_control(c,store,incident['id']);clear(c,incident['id'],now)
                summary='Administrator confirmed this host was intentionally powered down; reachability alert dismissed.'
                end(c,incident['id'],'hermes','Resolved',now,summary);end(c,incident['id'],'user','Resolved',now,summary)
                report=json.loads(incident['report']);report.update(manual_resolution=True,recovery_summary=summary)
                c.execute("UPDATE incidents SET status='Resolved',closed=?,last_seen=?,report=? WHERE id=?",(now,now,json.dumps(report),incident['id']))
                store.timeline(c,incident['id'],'resolve',summary,actor='user',now=now);enqueue(c,incident['id'],'recovery',now,store);closed+=1
        c.execute("UPDATE checks SET next_run=0,failures=0,successes=0,first_failure_at=NULL,lease_token=NULL,lease_until=NULL WHERE machine_id=? AND kind IN ('agent','proxmox_linked')",(machine,))
        store.audit(c,'host.presence',machine,{'offline_expected':expected,'resolved':closed})
    return closed
