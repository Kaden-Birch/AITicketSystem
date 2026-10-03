"""Readable, filtered audit presentation; stored history is unchanged."""
import json
import time

IMPORTANT="action NOT IN ('proxmox.discovered','unifi.telemetry_read') AND (actor IN ('user','security') OR action LIKE '%failed%' OR action LIKE '%denied%' OR action LIKE '%unknown%' OR action LIKE '%expired%' OR action LIKE '%revoked%')"
FILTERS={'highlights':IMPORTANT,'all':'1=1','security':"action LIKE 'security.%' OR action LIKE 'agent.enroll%' OR action LIKE 'agent.reenroll%' OR action LIKE 'agent.revoked%' OR action LIKE '%credential%' OR action LIKE 'fleet.key%' OR action LIKE 'fleet.private%'",'changes':"actor='user' AND action NOT LIKE 'security.%' AND action NOT IN ('proxmox.discovered','unifi.telemetry_read')",'operations':"actor NOT IN ('user','security') OR action IN ('proxmox.discovered','unifi.telemetry_read')"}
RANGES={'day':86400,'week':604800,'month':2592000,'all':None}


def listing(store,view,period,query,page):
    if view not in FILTERS or period not in RANGES or not 1<=page<=100000 or len(query)>100:raise ValueError('Invalid audit filter.')
    clauses=[FILTERS[view]];args=[]
    if RANGES[period]:clauses.append('at>=?');args.append(time.time()-RANGES[period])
    if query:
        clauses.append("(action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\')")
        pattern='%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%';args.extend([pattern]*3)
    where=' AND '.join('('+c+')' for c in clauses)
    total=store.rows('SELECT count(*) count FROM audit WHERE '+where,args)[0]['count']
    rows=store.rows('SELECT * FROM audit WHERE '+where+' ORDER BY at DESC,id LIMIT 26 OFFSET ?',[*args,(page-1)*25])
    # Resolve common inventory references in one batch, without dumping identifiers into the list.
    names={r['id']:r['name'] for r in store.rows('SELECT id,name FROM machines')}
    names.update({r['id']:r['name'] for r in store.rows('SELECT id,name FROM checks')})
    names.update({r['id']:r['name'] for r in store.rows('SELECT a.id,m.name FROM agents a JOIN machines m ON m.id=a.machine_id')})
    names.update({r['id']:r['name'] for r in store.rows('SELECT id,name FROM notification_groups')})
    names.update({r['id']:r['name'] for r in store.rows('SELECT id,name FROM maintenance_windows')})
    for table,column in (('proxmox_connections','name'),('unifi_connections','name'),('fleet_groups','name'),('fleet_jobs','label'),('fleet_keys','label')):
        names.update({r['id']:r['name'] for r in store.rows('SELECT id,'+column+' name FROM '+table)})
    for row in rows:
        domain,_,event=row['action'].partition('.')
        label={'unifi':'UniFi','ai':'AI','proxmox':'Proxmox','security':'Security','health_rule':'Health alert','commands':'Command access','command':'Host command','network':'Network','notification':'Notification','handoff':'Ticket control'}.get(domain,domain.replace('_',' ').capitalize())
        row['label']=label+' · '+(event.replace('_',' ').replace('.',' ').capitalize() or 'Updated')
        row['target_name']=names.get(row['target']) or {'administrator':'Administrator','settings':'Application settings','inventory':'Inventory','agents':'All agents','global':'All hosts'}.get(row['target'],'Application activity')
        row['actor_name']={'user':'Administrator','agent':'Host agent','monitor':'Monitoring service','security':'Security','hermes':'Hermes'}.get(row['actor'],'Application')
        row['attention']=any(word in row['action'] for word in ('failed','denied','unknown','expired','revoked'))
        try:row['facts']=json.loads(row['details'])
        except (TypeError,ValueError):row['facts']={}
        if not isinstance(row['facts'],dict):row['facts']={'Recorded details':row['facts']}
    return rows[:25],len(rows)>25,total
