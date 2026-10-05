"""Shared investigations retain per-ticket evidence, recovery and exact-target authority."""
import json,time


def active_primary(c,incident):
    row=c.execute("SELECT g.primary_id FROM ticket_groups g JOIN incidents p ON p.id=g.primary_id WHERE g.member_id=? AND p.closed IS NULL AND p.status!='Resolved'",(incident,)).fetchone()
    return row[0] if row else None


def ids(c,incident):
    primary=c.execute('SELECT primary_id FROM ticket_groups WHERE member_id=?',(incident,)).fetchone()
    primary=primary[0] if primary else incident
    return primary,[primary]+[r[0] for r in c.execute('SELECT member_id FROM ticket_groups WHERE primary_id=? ORDER BY created,member_id',(primary,))]


def context(c,incident,now=None):
    now=time.time() if now is None else now;primary,members=ids(c,incident);result=[]
    for identifier in members[:30]:
        row=c.execute('SELECT i.id,i.machine_id,i.status,i.closed,i.report,m.name FROM incidents i JOIN machines m ON m.id=i.machine_id WHERE i.id=?',(identifier,)).fetchone()
        if not row:continue
        report=json.loads(row['report'])
        result.append({'ticket_id':row['id'],'machine_id':row['machine_id'],'host':row['name'],'title':report.get('check','Ticket'),'status':row['status'],'recovered':row['closed'] is not None and report.get('observed')=='healthy','primary':identifier==primary,'reason':next((r[0] for r in c.execute('SELECT reason FROM ticket_groups WHERE member_id=?',(identifier,))),None)})
    for item in result:
        sources=[]
        for r in c.execute('SELECT ch.id,ch.name,ch.interval,o.at,o.health,o.evidence FROM incident_sources s JOIN checks ch ON ch.id=s.check_id LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE s.incident_id=? ORDER BY ch.id LIMIT 10',(item['ticket_id'],)):
            evidence=json.loads(r['evidence'] or '{}')
            sources.append({'check_id':r['id'],'name':r['name'],'observed_at':r['at'],'fresh':bool(r['at'] is not None and 0<=now-r['at']<=max(180,r['interval']*3)),'result':r['health'],'reason':evidence.get('reason'),'note':'Use evidence for detailed results.'})
        item['checks']=sources
    targets=[{'machine_id':r['id'],'host':r['name']} for r in c.execute('SELECT m.id,m.name FROM ticket_targets t JOIN machines m ON m.id=t.machine_id WHERE t.incident_id=? ORDER BY m.name LIMIT 30',(primary,))]
    return {'primary_id':primary,'tickets':result,'additional_hosts':targets,'truncated':len(members)>30,'note':'Relationships are troubleshooting evidence, not proof of cause. Tickets recover independently. Commands remain limited to the execution’s original ticket target; inspect related hosts read-only or start a separate explicit investigation.'}


def machines(c,incident):
    _,members=ids(c,incident)
    result=set()
    for identifier in members:
        row=c.execute('SELECT machine_id FROM incidents WHERE id=?',(identifier,)).fetchone()
        if row:result.add(row[0])
        result.update(r[0] for r in c.execute('SELECT machine_id FROM ticket_targets WHERE incident_id=?',(identifier,)))
    return result


def attach(store,primary,member,reason,automatic=False,now=None):
    now=time.time() if now is None else now
    if primary==member or not isinstance(reason,str) or not 1<=len(reason.strip())<=500:raise ValueError('Choose another ticket and explain the relationship.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        rows=[c.execute('SELECT * FROM incidents WHERE id=?',(i,)).fetchone() for i in (primary,member)]
        if any(not r or r['closed'] is not None or r['status']=='Resolved' or r['merged_into'] for r in rows):raise ValueError('Select active tickets that have not been merged.')
        if c.execute('SELECT 1 FROM ticket_groups WHERE member_id=? OR primary_id=?',(primary,member)).fetchone():raise ValueError('A ticket group cannot be nested. Detach it before regrouping.')
        prior=c.execute('SELECT primary_id FROM ticket_groups WHERE member_id=?',(member,)).fetchone()
        if prior:
            if prior[0]==primary:return
            raise ValueError('This ticket already belongs to another investigation.')
        if c.execute('SELECT count(*) FROM ticket_groups WHERE primary_id=?',(primary,)).fetchone()[0]>=29:raise ValueError('A shared investigation supports up to 30 tickets.')
        pair=sorted((primary,member))
        if automatic and c.execute('SELECT 1 FROM ticket_group_exclusions WHERE left_id=? AND right_id=?',pair).fetchone():return
        if automatic and (json.loads(rows[1]['report']).get('manual_ticket') or c.execute("SELECT 1 FROM ai_jobs WHERE incident_id=?",(member,)).fetchone() or c.execute("SELECT 1 FROM incident_control WHERE incident_id=? AND (owner='user' OR handling_mode!='automatic')",(member,)).fetchone()):return
        c.execute('INSERT INTO ticket_groups VALUES(?,?,?,?,?)',(primary,member,reason.strip(),int(automatic),now))
        c.execute('INSERT OR REPLACE INTO incident_links VALUES(?,?,?)',(*pair,reason.strip()))
        for identifier in (primary,member):store.timeline(c,identifier,'ticket_grouped','Related failure attached to a shared investigation. '+reason.strip(),actor='monitor' if automatic else 'user',now=now)
        store.audit(c,'ticket.grouped',primary,{'member_id':member,'automatic':automatic})


def detach(store,primary,member):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('DELETE FROM ticket_groups WHERE primary_id=? AND member_id=?',(primary,member)).rowcount:raise ValueError('This ticket is no longer in that group.')
        c.execute('INSERT OR IGNORE INTO ticket_group_exclusions VALUES(?,?)',sorted((primary,member)))
        c.execute('DELETE FROM incident_links WHERE left_id=? AND right_id=?',sorted((primary,member)))
        for identifier in (primary,member):store.timeline(c,identifier,'ticket_separated','Related ticket separated; independent monitoring and history retained.',actor='user')
        store.audit(c,'ticket.separated',primary,{'member_id':member})


def target(store,incident,machine,remove=False):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT machine_id,closed FROM incidents WHERE id=?',(incident,)).fetchone()
        if not row or row['closed'] is not None:raise ValueError('Choose an active ticket.')
        if not c.execute('SELECT 1 FROM machines WHERE id=?',(machine,)).fetchone():raise ValueError('Choose an existing host.')
        if row['machine_id']==machine:raise ValueError('The original ticket target is already included.')
        if remove:c.execute('DELETE FROM ticket_targets WHERE incident_id=? AND machine_id=?',(incident,machine))
        else:
            if c.execute('SELECT count(*) FROM ticket_targets WHERE incident_id=?',(incident,)).fetchone()[0]>=20:raise ValueError('Up to 20 additional hosts may be attached.')
            c.execute('INSERT OR IGNORE INTO ticket_targets VALUES(?,?,?)',(incident,machine,time.time()))
        store.audit(c,'ticket.target_removed' if remove else 'ticket.target_added',incident,{'machine_id':machine})
        store.timeline(c,incident,'ticket_target','Affected host '+('removed.' if remove else 'added for read-only troubleshooting context; no additional command permissions.'),actor='user')


def compatible_root(c,incident,now):
    from .applications import upstream_incident
    root=upstream_incident(c,incident,now)
    if root:return active_primary(c,root) or root,'Explicit application dependency with current failures; shared cause remains unconfirmed.'
    row=c.execute('SELECT i.*,ch.kind,m.parent_id FROM incidents i JOIN checks ch ON ch.id=i.check_id JOIN machines m ON m.id=i.machine_id WHERE i.id=?',(incident,)).fetchone()
    if not row:return None,None
    # Parent reachability is compatible with service/guest failures, never arbitrary CPU alerts.
    allowed={'agent','http','tcp','proxmox','truenas','plex'}
    if row['kind'] not in allowed:return None,None
    parents=[]
    if row['parent_id']:parents.append(row['parent_id'])
    for obj in c.execute("SELECT cluster_id,node FROM proxmox_objects WHERE machine_id=? AND kind IN ('qemu','lxc') AND present=1",(row['machine_id'],)):
        parents.extend(r[0] for r in c.execute("SELECT machine_id FROM proxmox_objects WHERE cluster_id=? AND node=? AND kind='node' AND present=1 AND machine_id IS NOT NULL",(obj['cluster_id'],obj['node'])))
    for parent in parents:
        upstream=c.execute("SELECT i.id,ch.interval,o.at FROM incidents i JOIN checks ch ON ch.id=i.check_id JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE i.machine_id=? AND i.closed IS NULL AND i.status!='Resolved' AND ch.enabled=1 AND ch.health='down' AND o.health='down' AND i.condition_key IN ('agent-communication','guest-down') ORDER BY i.first_seen LIMIT 1",(parent,)).fetchone()
        if upstream and 0<=now-upstream['at']<=max(180,upstream['interval']*3):return active_primary(c,upstream['id']) or upstream['id'],'Explicit parent/Proxmox hosting relationship with current reachability failures; shared cause remains unconfirmed.'
    return None,None


def tick(store,now=None):
    now=time.time() if now is None else now
    candidates=store.rows("SELECT i.id FROM incidents i JOIN checks ch ON ch.id=i.check_id JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE i.closed IS NULL AND i.status!='Resolved' AND i.merged_into IS NULL AND ch.enabled=1 AND ch.health='down' AND o.health='down' AND o.at<=? AND o.at>=?-max(180,ch.interval*3) AND NOT EXISTS (SELECT 1 FROM ticket_groups WHERE member_id=i.id) ORDER BY i.first_seen LIMIT 100",(now,now))
    for row in candidates:
        with store.connect() as c:root,reason=compatible_root(c,row['id'],now)
        if root and root!=row['id']:
            try:attach(store,root,row['id'],reason,automatic=True,now=now)
            except ValueError:continue


def coordinating_primary(c,incident,now=None):
    """A group never lets an ineligible/maintained primary starve another target."""
    now=time.time() if now is None else now;root=active_primary(c,incident)
    if not root:return None
    row=c.execute('SELECT * FROM incidents WHERE id=?',(root,)).fetchone()
    from .maintenance_ai import state
    if state(c,row['machine_id'],now,root)['active']:return None
    if c.execute("SELECT 1 FROM ai_jobs WHERE incident_id=? AND state IN ('pending','dispatching','running','unknown')",(root,)).fetchone():return root
    control=c.execute('SELECT owner,handling_mode FROM incident_control WHERE incident_id=?',(root,)).fetchone()
    if control and (control['owner']=='user' or control['handling_mode']!='automatic'):return None
    cfg=c.execute("SELECT value FROM settings WHERE key='hermes_config'").fetchone()
    cfg=json.loads(cfg[0]) if cfg else {}
    from .engine import SEVERITIES
    if SEVERITIES.index(row['severity'])<SEVERITIES.index(cfg.get('minimum','high')):return None
    # Completed/failed primary work cannot indefinitely hold unresolved members.
    if c.execute('SELECT 1 FROM ai_jobs WHERE incident_id=?',(root,)).fetchone():return None
    return root
