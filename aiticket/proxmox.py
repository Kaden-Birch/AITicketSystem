"""Read-only Proxmox inventory, with explicit administrator cluster namespaces."""
import json
import time
import math
import requests
from .db import uid


class Client:
    def __init__(self, connection, vault):
        self.connection = connection
        self.headers = {'Authorization': 'PVEAPIToken=' + connection['token_id'] + '=' + vault.decrypt(connection['token_secret'])}

    def get(self, path):
        with requests.get(self.connection['url'].rstrip('/') + '/api2/json' + path,
                          headers=self.headers, timeout=(3, 8), verify=self.connection['ca'] or True,
                          allow_redirects=False, stream=True) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError('Unexpected API response')
            body = bytearray()
            deadline = time.monotonic() + 15
            for block in response.iter_content(65536):
                if time.monotonic() > deadline:
                    raise ValueError('API response exceeded time limit')
                body.extend(block)
                if len(body) > 2_000_000:
                    raise ValueError('API response exceeds size limit')
            return json.loads(body)['data']

    def test(self):
        results = {'reachability': 'unknown', 'authentication': 'unknown', 'capabilities': {}}
        try:
            self.get('/version')
            results['reachability'] = 'reachable'
        except requests.HTTPError as exc:
            results['reachability'] = 'reachable'
            if exc.response.status_code == 401:
                results['authentication'] = 'rejected'
                return results
        except Exception as exc:
            results['reachability'] = 'failed: ' + type(exc).__name__
            return results
        try:
            resources = self.get('/cluster/resources')
            normalize(resources)
            results['authentication'] = 'accepted'
            results['capabilities']['inventory'] = 'readable; visibility is limited by token permissions'
        except requests.HTTPError as exc:
            results['authentication'] = 'rejected' if exc.response.status_code == 401 else 'not established'
            results['capabilities']['inventory'] = 'denied or unavailable'
        except Exception as exc:
            results['capabilities']['inventory'] = 'failed: ' + type(exc).__name__
        try:
            permissions = self.get('/access/permissions')
            results['capabilities']['effective_permissions'] = permissions if isinstance(permissions, dict) else 'unavailable'
        except Exception:
            results['capabilities']['effective_permissions'] = 'unavailable; permissions were not broadened'
        return results


def normalize(resources):
    if not isinstance(resources, list) or len(resources) > 10000:
        raise ValueError('Invalid or oversized inventory')
    result, seen = [], set()
    for item in resources:
        kind = item.get('type')
        if kind not in ('node', 'qemu', 'lxc', 'storage'):
            continue
        key = item.get('id')
        if not isinstance(key, str) or not key or len(key) > 256 or (kind, key) in seen:
            raise ValueError('Invalid or duplicate resource identity')
        seen.add((kind, key))
        result.append({'kind':kind, 'key':key, 'name':str(item.get('name') or item.get('storage') or item.get('node') or key)[:200],
                       'node':str(item.get('node',''))[:200], 'status':str(item.get('status','unknown'))[:32], 'template':bool(item.get('template',False)), 'metrics':{k:v for k,v in item.items() if k in ('cpu','maxcpu','mem','maxmem','disk','maxdisk','uptime') and type(v) in (int,float) and math.isfinite(v) and 0<=v<=1e18 and (k!='cpu' or v<=1)}})
    return result


def discover(store, vault, connection_id, lease_token=None):
    rows = store.rows('SELECT * FROM proxmox_connections WHERE id=?',(connection_id,))
    if not rows:
        raise ValueError('Unknown connection')
    connection = rows[0]
    objects = normalize(Client(connection,vault).get('/cluster/resources'))
    now = time.time()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if lease_token and not c.execute('SELECT 1 FROM discovery_schedules WHERE connection_id=? AND lease_token=? AND interval>0',(connection_id,lease_token)).fetchone():
            return 0
        # A missing object is a visibility warning, never automatic retirement.
        c.execute('UPDATE proxmox_objects SET missing_since=coalesce(missing_since,?) WHERE cluster_id=? AND present=1',(now,connection['cluster_id']))
        for item in objects:
            existing = c.execute('SELECT * FROM proxmox_objects WHERE cluster_id=? AND kind=? AND object_key=? AND present=1',
                                 (connection['cluster_id'],item['kind'],item['key'])).fetchone()
            if existing:
                c.execute('UPDATE proxmox_objects SET name=?,node=?,status=?,template=?,last_seen=?,missing_since=NULL WHERE id=?',
                          (item['name'],item['node'],item['status'],item['template'],now,existing['id']))
            else:
                generation = c.execute('SELECT coalesce(max(generation),0)+1 FROM proxmox_objects WHERE cluster_id=? AND kind=? AND object_key=?',
                                       (connection['cluster_id'],item['kind'],item['key'])).fetchone()[0]
                c.execute('INSERT INTO proxmox_objects(id,cluster_id,kind,object_key,generation,name,node,status,template,present,last_seen,machine_id,check_id) VALUES(?,?,?,?,?,?,?,?,?,1,?,NULL,NULL)',
                          (uid(),connection['cluster_id'],item['kind'],item['key'],generation,item['name'],item['node'],item['status'],item['template'],now))
            c.execute('UPDATE proxmox_objects SET metrics=? WHERE cluster_id=? AND kind=? AND object_key=? AND present=1',(json.dumps(item['metrics']),connection['cluster_id'],item['kind'],item['key']))
        # Absence in a permission-filtered response is not proof of deletion. An
        # administrator explicitly retires old objects before reusing their IDs.
        c.execute('UPDATE proxmox_connections SET last_discovery=? WHERE id=?',(now,connection_id))
        refresh_parents(c,store,connection['cluster_id'])
        store.audit(c,'proxmox.discovered',connection_id,{'visible_resources':len(objects)})
    return len(objects)


def refresh_parents(c,store,cluster_id):
    for guest in c.execute("SELECT * FROM proxmox_objects WHERE cluster_id=? AND present=1 AND machine_id IS NOT NULL AND kind IN ('qemu','lxc')",(cluster_id,)).fetchall():
        node = c.execute("SELECT machine_id FROM proxmox_objects WHERE cluster_id=? AND kind='node' AND object_key=? AND present=1",(cluster_id,'node/'+guest['node'])).fetchone()
        if not node or not node['machine_id']:
            old = c.execute('SELECT parent_id FROM machines WHERE id=?',(guest['machine_id'],)).fetchone()[0]
            managed = c.execute("SELECT 1 FROM proxmox_objects WHERE cluster_id=? AND kind='node' AND machine_id=?",(cluster_id,old)).fetchone()
            if managed:
                c.execute('UPDATE machines SET parent_id=NULL WHERE id=?',(guest['machine_id'],))
                store.audit(c,'machine.parent_unlinked',guest['machine_id'],actor='monitor')
        if node and node['machine_id'] and node['machine_id'] != guest['machine_id']:
            old = c.execute('SELECT parent_id FROM machines WHERE id=?',(guest['machine_id'],)).fetchone()[0]
            if old != node['machine_id']:
                # Guard against a cycle introduced by manual inventory choices.
                current, visited = node['machine_id'], {guest['machine_id']}
                while current:
                    if current in visited:
                        raise ValueError('Link would create a dependency cycle')
                    visited.add(current)
                    row = c.execute('SELECT parent_id FROM machines WHERE id=?',(current,)).fetchone()
                    current = row[0] if row else None
                c.execute('UPDATE machines SET parent_id=? WHERE id=?',(node['machine_id'],guest['machine_id']))
                store.audit(c,'machine.parent_updated',guest['machine_id'],{'parent_id':node['machine_id']},actor='monitor')


def link(store, object_id, machine_id, expected, create_name=None):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        obj = c.execute('SELECT * FROM proxmox_objects WHERE id=? AND present=1',(object_id,)).fetchone()
        if not obj or obj['machine_id']:
            raise ValueError('Object is unavailable or already linked')
        if obj['template']:
            raise ValueError('Templates are excluded from monitoring')
        states = {'node':('online','offline'),'qemu':('running','stopped'),'lxc':('running','stopped'),'storage':('available','unavailable')}
        if expected not in states[obj['kind']]:
            raise ValueError('Invalid expected state for this resource type')
        if create_name:
            machine_id = uid()
            c.execute('INSERT INTO machines(id,name,parent_id,created) VALUES(?,?,NULL,?)',(machine_id,create_name,time.time()))
        if not c.execute('SELECT 1 FROM machines WHERE id=?',(machine_id,)).fetchone():
            raise ValueError('Select an existing machine or create one')
        other = c.execute("SELECT 1 FROM proxmox_objects WHERE machine_id=? AND present=1 AND machine_id IS NOT NULL AND kind IN ('node','qemu','lxc')",(machine_id,)).fetchone()
        if obj['kind'] in ('node','qemu','lxc') and other:
            raise ValueError('This machine already has a node or guest identity; keep nodes and guests separate')
        check_id = uid()
        cfg = json.dumps({'object_id':object_id,'cluster_id':obj['cluster_id'],'resource':obj['object_key'],'expected':expected})
        c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES(?,?,?,?,?,60)',(check_id,machine_id,'Proxmox '+obj['object_key'],'proxmox_linked',cfg))
        c.execute('UPDATE proxmox_objects SET machine_id=?,check_id=?,review_required=0 WHERE id=?',(machine_id,check_id,object_id))
        refresh_parents(c,store,obj['cluster_id'])
        store.audit(c,'proxmox.linked',object_id,{'machine_id':machine_id,'expected':expected})


def unlink(store,object_id,retire=False):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        obj=c.execute('SELECT * FROM proxmox_objects WHERE id=?',(object_id,)).fetchone()
        if not obj:
            raise ValueError('Unknown resource')
        if obj['machine_id'] and c.execute("SELECT 1 FROM power_jobs WHERE machine_id=? AND state IN ('dispatched','authorized','verifying','unknown')",(obj['machine_id'],)).fetchone():
            raise ValueError('Reconcile the existing power execution before unlinking this resource.')
        if obj['machine_id']:
            c.execute("UPDATE power_jobs SET state='cancelled' WHERE machine_id=? AND state IN ('awaiting','approved')",(obj['machine_id'],))
        if obj['kind']=='node' and obj['machine_id']:
            guests=c.execute("SELECT machine_id FROM proxmox_objects WHERE cluster_id=? AND kind IN ('qemu','lxc') AND node=? AND machine_id IS NOT NULL",(obj['cluster_id'],obj['node'])).fetchall()
            for guest in guests:
                changed=c.execute('UPDATE machines SET parent_id=NULL WHERE id=? AND parent_id=?',(guest['machine_id'],obj['machine_id']))
                if changed.rowcount:
                    store.audit(c,'machine.parent_unlinked',guest['machine_id'],actor='monitor')
        if obj['check_id']:
            c.execute('UPDATE checks SET enabled=0,lease_token=NULL,lease_until=NULL WHERE id=?',(obj['check_id'],))
        c.execute('UPDATE proxmox_objects SET machine_id=NULL,check_id=NULL,present=? WHERE id=?',(0 if retire else obj['present'],object_id))
        store.audit(c,'proxmox.retired' if retire else 'proxmox.unlinked',object_id,{'previous_machine_id':obj['machine_id']})


def linked_probe(store,vault,config):
    obj=store.rows('SELECT * FROM proxmox_objects WHERE id=? AND present=1',(config['object_id'],))
    if not obj:
        return False,{'reason':'Source retired; identity must be reviewed'}
    connections=store.rows('SELECT * FROM proxmox_connections WHERE cluster_id=? ORDER BY id',(config['cluster_id'],))
    for connection in connections:
        try:
            resources=normalize(Client(connection,vault).get('/cluster/resources'))
            item=next((r for r in resources if r['key']==config['resource']),None)
            if item:
                return item['status']==config['expected'],{'resource':config['resource'],'generation':obj[0]['generation'],'status':item['status'],'expected':config['expected'],'node':item['node']}
        except Exception:
            continue
    return False,{'reason':'Resource unavailable or not visible through configured endpoints; deletion is unconfirmed'}


def schedule(store, connection_id, interval, now=None):
    if type(interval) is not int or (interval!=0 and not 60<=interval<=86400):
        raise ValueError('Refresh interval must be zero (disabled) or 60–86400 seconds.')
    now=time.time() if now is None else now
    with store.connect() as c:
        if not c.execute('SELECT 1 FROM proxmox_connections WHERE id=?',(connection_id,)).fetchone():
            raise ValueError('Unknown connection.')
        c.execute('INSERT INTO discovery_schedules(connection_id,interval,next_run) VALUES(?,?,?) ON CONFLICT(connection_id) DO UPDATE SET interval=excluded.interval,next_run=excluded.next_run,lease_token=NULL,lease_until=NULL',(connection_id,interval,now))
        store.audit(c,'proxmox.schedule_changed',connection_id,{'interval':interval})


def scheduled_refresh(store,vault,now=None):
    now=time.time() if now is None else now
    token=uid()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM discovery_schedules WHERE interval>0 AND next_run<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_run LIMIT 1',(now,now)).fetchone()
        if not row:
            return False
        connection_id=row['connection_id']
        c.execute('UPDATE discovery_schedules SET lease_token=?,lease_until=? WHERE connection_id=?',(token,now+60,connection_id))
    error=None
    try:
        discover(store,vault,connection_id,lease_token=token)
    except Exception as exc:
        error=type(exc).__name__ # Never retain upstream bodies, URLs or tokens.
    with store.connect() as c:
        changed=c.execute('UPDATE discovery_schedules SET next_run=?,lease_token=NULL,lease_until=NULL,last_error=? WHERE connection_id=? AND lease_token=?',(now+row['interval'],error,connection_id,token))
        if changed.rowcount and error:
            store.audit(c,'proxmox.discovery_failed',connection_id,{'error_type':error},actor='monitor')
    return True
