"""Administrator edits preserve machine identity, enrollment and ticket history."""
import json
import time
from .db import uid
from .engine import SEVERITIES


def edit(store,machine_id,name,parent):
    name=name.strip();parent=parent or None
    if not 1<=len(name)<=100: raise ValueError('Machine name must contain 1–100 characters.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        old=c.execute('SELECT * FROM machines WHERE id=?',(machine_id,)).fetchone()
        if not old: raise ValueError('Unknown machine.')
        current=parent;seen={machine_id}
        while current:
            if current in seen: raise ValueError('Dependencies must not form a cycle.')
            seen.add(current)
            row=c.execute('SELECT parent_id FROM machines WHERE id=?',(current,)).fetchone()
            if not row: raise ValueError('Unknown dependency.')
            current=row[0]
        linked=c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND present=1 AND kind IN ('qemu','lxc')",(machine_id,)).fetchone()
        if linked and parent!=old['parent_id']: raise ValueError('The linked Proxmox guest dependency is managed by its current node.')
        c.execute('UPDATE machines SET name=?,parent_id=? WHERE id=?',(name,parent,machine_id))
        store.audit(c,'machine.updated',machine_id,{'name':name,'parent_id':parent})


def open_ticket(store,machine_id,title,description,severity,notify=False,handling_mode='automatic',*,workflow_test=False):
    if handling_mode not in ('automatic','human','paused'): raise ValueError('Unknown handling mode.')
    title=title.strip();description=description.strip()
    if not 1<=len(title)<=100 or not 1<=len(description)<=4000 or severity not in SEVERITIES:
        raise ValueError('Supply a title (1–100), description (1–4000) and valid severity.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        machine=c.execute('SELECT * FROM machines WHERE id=?',(machine_id,)).fetchone()
        if not machine: raise ValueError('Select an existing machine.')
        now=time.time();identifier=uid();source=uid()
        # A disabled source preserves the existing non-null incident foreign key.
        # It is never a probe, exported monitoring configuration or health evidence.
        c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,enabled,severity) VALUES(?,?,?,'manual','{}',60,0,?)",(source,machine_id,title,severity))
        report={'target':machine['name'],'check':title,'title':title,'description':description,'manual_ticket':True,'cause':'Unknown','observed':'user reported','expected':'Administrator review','evidence':{'description':description},'sources':[],'severity':severity,'ai_status':'disabled','observed_at':now}
        if workflow_test: report['workflow_test']=True
        c.execute("INSERT INTO incidents(id,machine_id,check_id,severity,severity_floor,status,first_seen,last_seen,report,condition_key) VALUES(?,?,?,?,?,'Open',?,?,?,'manual-ticket')",(identifier,machine_id,source,severity,severity,now,now,json.dumps(report)))
        if workflow_test:
            c.execute("UPDATE checks SET kind='workflow_test',enabled=1,interval=5,fail_after=1,recover_after=1 WHERE id=?",(source,))
            c.execute('INSERT INTO incident_sources VALUES(?,?,?)',(identifier,source,json.dumps(report)))
        if handling_mode!='automatic':
            from .handoff import take_control
            take_control(c,store,identifier)
            c.execute('UPDATE incident_control SET handling_mode=? WHERE incident_id=?',(handling_mode,identifier))
        store.timeline(c,identifier,'manual_opened',description,actor='user',now=now)
        store.audit(c,'incident.manual_created',identifier,{'machine_id':machine_id,'severity':severity,'notify':notify})
        if notify:
            from .engine import enqueue
            enqueue(c,identifier,'opened',now,store)
        return identifier
