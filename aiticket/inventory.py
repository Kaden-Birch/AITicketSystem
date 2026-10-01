"""Atomic, additive configuration transfer. Credentials and runtime authority never transfer."""
import json
import math
import sqlite3
import time
from .security import validate_url,digest
from .diagnostics import METRICS
from .engine import SEVERITIES

FIELDS={
 'machines':('id','name','parent_id'),
 'proxmox_clusters':('id','name'),
 'proxmox_connections':('id','cluster_id','name','url','token_id'),
 'agents':('id','machine_id'),
 'checks':('id','machine_id','name','kind','config','interval','fail_after','recover_after','severity'),
 'proxmox_objects':('id','cluster_id','kind','object_key','generation','name','node','status','template','present','machine_id','check_id'),
 'discovery_schedules':('connection_id','interval'),
 'maintenance_windows':('id','name','machine_id','kind','timezone','start','end','weekday','start_minute','end_minute','enabled'),
 'notification_groups':('id','name'),
 'machine_groups':('machine_id','group_id'),
 'notification_overrides':('scope_kind','scope_id','policy'),
}
CONFIG={
 'http':{'url','status'},'tcp':{'host','port'},
 'proxmox':{'url','token_id','resource','expected'},
 'proxmox_linked':{'object_id','cluster_id','resource','expected'},
 'agent':{'agent_id','max_age'},
 'agent_metric':{'agent_id','metric','fail_above','recover_below','sustain_seconds'},
}


def export_inventory(store):
    with store.connect() as c:
        c.execute('BEGIN')
        tables={name:[dict(r) for r in c.execute('SELECT '+','.join(fields)+' FROM '+name)] for name,fields in FIELDS.items()}
    for row in tables['checks']:
        cfg=json.loads(row['config'])
        row['config']={key:cfg[key] for key in CONFIG[row['kind']] if key in cfg}
    for row in tables['notification_overrides']:
        row['policy']=json.loads(row['policy'])
    return {'format':'aiticket-inventory','version':1,'tables':tables}


def integer(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:
        raise ValueError('Invalid inventory integer or interval.')


def text(value,maximum=2048):
    if not isinstance(value,str) or not 1<=len(value)<=maximum or '\x00' in value:
        raise ValueError('Invalid inventory text.')


def config(kind,cfg):
    if kind not in CONFIG or not isinstance(cfg,dict) or set(cfg)-CONFIG[kind]:
        raise ValueError('Unsupported check configuration or credential field.')
    if kind=='http':
        validate_url(cfg.get('url',''))
        integer(cfg.get('status',200),100,599)
    elif kind=='tcp':
        text(cfg.get('host'),253)
        integer(cfg.get('port'),1,65535)
    elif kind=='proxmox':
        validate_url(cfg.get('url',''),('https',))
        text(cfg.get('token_id'),200)
    elif kind in ('agent','agent_metric'):
        text(cfg.get('agent_id'),100)
        if kind=='agent':
            integer(cfg.get('max_age',180),30,86400)
        else:
            if cfg.get('metric') not in METRICS:
                raise ValueError('Unsupported agent metric.')
            low,high=cfg.get('recover_below'),cfg.get('fail_above')
            if any(type(v) not in (int,float) or not math.isfinite(v) for v in (low,high)) or not 0<=low<high<=100:
                raise ValueError('Invalid resource thresholds.')
            integer(cfg.get('sustain_seconds'),30,86400)
    else:
        for key in ('object_id','cluster_id','resource'):
            text(cfg.get(key),256)
    if kind.startswith('proxmox') and cfg.get('expected','running') not in ('running','stopped','online','offline','available','unavailable'):
        raise ValueError('Unsupported expected Proxmox state.')
    return cfg


def validate_document(document):
    if not isinstance(document,dict) or set(document)!={'format','version','tables'} or document['format']!='aiticket-inventory' or type(document['version']) is not int or document['version']!=1 or not isinstance(document['tables'],dict) or set(document['tables'])!=set(FIELDS):
        raise ValueError('Unsupported inventory file.')
    tables=document['tables']
    if len(json.dumps(document,allow_nan=False))>2_000_000:
        raise ValueError('Inventory file exceeds 2 MB.')
    for name,fields in FIELDS.items():
        rows=tables[name]
        if not isinstance(rows,list) or len(rows)>10000:
            raise ValueError('Invalid or oversized inventory table.')
        identities=set()
        for row in rows:
            if not isinstance(row,dict) or set(row)!=set(fields):
                raise ValueError('Unexpected inventory fields; secrets and runtime state are prohibited.')
            key=tuple(row[f] for f in fields[:2]) if name=='notification_overrides' else row[fields[0]]
            if key in identities:
                raise ValueError('Duplicate inventory identity.')
            identities.add(key)
            for field in fields:
                if field in ('id','connection_id','scope_kind','scope_id','group_id','name','kind','url','token_id','object_key','timezone','severity') or (field=='machine_id' and name!='maintenance_windows' and name!='proxmox_objects'):
                    text(row[field],2048 if field=='url' else 256)
            for field,value in row.items():
                if field in ('config','policy'):
                    continue
                if isinstance(value,str):
                    if value or field not in ('node','status'):
                        text(value,2048 if field=='url' else 256)
                elif value is not None and (type(value) not in (int,float) or not math.isfinite(value)):
                    raise ValueError('Invalid inventory scalar.')
            if name=='checks':
                config(row['kind'],row['config'])
                integer(row['interval'],10,86400)
                integer(row['fail_after'],1,100)
                integer(row['recover_after'],1,100)
                if row['severity'] not in SEVERITIES:
                    raise ValueError('Unknown severity.')
            if name=='proxmox_connections':
                validate_url(row['url'],('https',))
            if name=='proxmox_objects':
                if row['kind'] not in ('node','qemu','lxc','storage'):
                    raise ValueError('Unknown resource kind.')
                integer(row['generation'],1,10**9)
                for field in ('template','present'):
                    integer(row[field],0,1)
            if name=='discovery_schedules':
                integer(row['interval'],0,86400)
                if row['interval'] and row['interval']<60:
                    raise ValueError('Discovery interval must be at least 60 seconds.')
            if name=='notification_overrides':
                from .policies import validate_override
                validate_override(row['policy'])
                if row['scope_kind'] not in ('machine','group'):
                    raise ValueError('Unknown notification scope.')
            if name=='maintenance_windows':
                from zoneinfo import ZoneInfo
                try:
                    ZoneInfo(row['timezone'])
                except Exception:
                    raise ValueError('Unknown maintenance timezone.') from None
                integer(row['enabled'],0,1)
                if row['kind']=='once':
                    if any(type(row[k]) not in (int,float) for k in ('start','end')) or not 0<row['end']-row['start']<=31*86400:
                        raise ValueError('Invalid one-time maintenance window.')
                elif row['kind']=='weekly':
                    integer(row['weekday'],0,6)
                    integer(row['start_minute'],0,1439)
                    integer(row['end_minute'],1,1440)
                    if row['end_minute']<=row['start_minute']:
                        raise ValueError('Invalid weekly maintenance window.')
                else:
                    raise ValueError('Unknown maintenance type.')
    return tables


def import_inventory(store,vault,document):
    try:
        tables=validate_document(document)
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('PRAGMA defer_foreign_keys=ON')
            affected={m['id'] for m in tables['machines']}|{r['machine_id'] for r in tables['checks']}
            if affected:
                placeholders=','.join('?' for _ in affected)
                if c.execute("SELECT 1 FROM incidents i JOIN ai_jobs j ON j.incident_id=i.id WHERE i.machine_id IN ("+placeholders+") AND j.state IN ('pending','dispatching','running','unknown')",tuple(affected)).fetchone() or c.execute("SELECT 1 FROM agents a JOIN action_proposals p ON p.agent_id=a.id WHERE a.machine_id IN ("+placeholders+") AND p.state IN ('dispatched','authorized','verifying','unknown')",tuple(affected)).fetchone():
                    raise ValueError('Finish active AI/recovery work before importing affected machines.')
            for name,rows in tables.items():
                for original in rows:
                    row=dict(original)
                    if name=='machines':
                        row.update(created=time.time(),recovery_role='protected')
                    if name=='proxmox_connections':
                        row.update(token_secret=vault.encrypt(''),ca=None)
                    if name=='agents':
                        row.update(credential_digest=digest('unavailable:'+row['id']),revoked=1)
                    if name=='checks':
                        row['config']=dict(row['config'])
                        if row['kind']=='proxmox':
                            row['config']['token_secret']=vault.encrypt('')
                        row['config']=json.dumps(row['config'])
                        row.update(enabled=0,health='unknown',failures=0,successes=0,first_failure_at=None,lease_token=None,lease_until=None,next_run=0)
                    if name=='proxmox_objects':
                        row.update(last_seen=0,review_required=1,missing_since=time.time())
                    if name=='discovery_schedules':
                        row.update(interval=0,next_run=0,lease_token=None,lease_until=None)
                    if name=='maintenance_windows':
                        row['enabled']=0
                    if name=='notification_overrides':
                        row['policy']=json.dumps(row['policy'])
                    keys=('scope_kind','scope_id') if name=='notification_overrides' else (FIELDS[name][0],)
                    where=' AND '.join(k+'=?' for k in keys)
                    old=c.execute('SELECT * FROM '+name+' WHERE '+where,tuple(row[k] for k in keys)).fetchone()
                    if old:
                        immutable={'agents':('machine_id',),'checks':('machine_id','kind'),'proxmox_connections':('cluster_id','url','token_id'),'proxmox_objects':('cluster_id','kind','object_key','generation','machine_id','check_id')}.get(name,())
                        if any(old[k]!=row[k] for k in immutable):
                            raise ValueError('Existing inventory identity has a different binding; import cannot relink it.')
                        if name=='agents':
                            continue # Existing credentials and enrollment remain local.
                        if name=='proxmox_connections':
                            for key in ('token_secret','ca'):
                                row[key]=old[key]
                        if name=='checks':
                            before=json.loads(old['config'])
                            old_definition={k:before[k] for k in CONFIG[row['kind']] if k in before}
                            if old_definition!=original['config'] and c.execute('SELECT 1 FROM incident_sources s JOIN incidents i ON i.id=s.incident_id WHERE s.check_id=? AND i.closed IS NULL',(row['id'],)).fetchone():
                                raise ValueError('An active incident source cannot change its check definition; use a new check identity.')
                        if name=='checks' and row['kind']=='proxmox':
                            before=json.loads(old['config']); after=json.loads(row['config'])
                            if before.get('url')!=after.get('url') or before.get('token_id')!=after.get('token_id'):
                                raise ValueError('Use a new identity for a changed credential endpoint.')
                            after['token_secret']=before.get('token_secret','')
                            row['config']=json.dumps(after)
                        updates=[k for k in row if k not in keys and not (name=='machines' and k=='created')]
                        c.execute('UPDATE '+name+' SET '+','.join(k+'=?' for k in updates)+' WHERE '+where,tuple(row[k] for k in updates)+tuple(row[k] for k in keys))
                    else:
                        c.execute('INSERT INTO '+name+'('+','.join(row)+') VALUES('+','.join('?' for _ in row)+')',tuple(row.values()))
            # Validate complete graph, including retained records, before committing.
            parents={r['id']:r['parent_id'] for r in c.execute('SELECT id,parent_id FROM machines')}
            for machine in parents:
                visited=set(); current=machine
                while current:
                    if current in visited or current not in parents:
                        raise ValueError('Dependency graph contains a cycle or missing parent.')
                    visited.add(current); current=parents[current]
            for check in tables['checks']:
                cfg=check['config']
                if check['kind'] in ('agent','agent_metric'):
                    agent=c.execute('SELECT machine_id FROM agents WHERE id=?',(cfg['agent_id'],)).fetchone()
                    if not agent or agent[0]!=check['machine_id']:
                        raise ValueError('Agent check identity does not match its machine.')
                if check['kind']=='proxmox_linked':
                    obj=c.execute('SELECT * FROM proxmox_objects WHERE id=?',(cfg['object_id'],)).fetchone()
                    if not obj or obj['cluster_id']!=cfg['cluster_id'] or obj['object_key']!=cfg['resource'] or obj['machine_id']!=check['machine_id'] or obj['check_id']!=check['id']:
                        raise ValueError('Linked source binding is inconsistent.')
            for row in tables['notification_overrides']:
                target='machines' if row['scope_kind']=='machine' else 'notification_groups'
                if not c.execute('SELECT 1 FROM '+target+' WHERE id=?',(row['scope_id'],)).fetchone():
                    raise ValueError('Notification scope does not exist.')
            # Never import approval authority; invalidate pending approval on affected machines.
            for machine in affected:
                c.execute("UPDATE action_proposals SET state='cancelled' WHERE incident_id IN (SELECT id FROM incidents WHERE machine_id=?) AND state IN ('awaiting','approved')",(machine,))
            store.audit(c,'inventory.imported','inventory',{'counts':{k:len(v) for k,v in tables.items()}})
    except (sqlite3.IntegrityError,TypeError,KeyError) as exc:
        raise ValueError('Invalid or conflicting inventory; no changes were imported.') from exc
