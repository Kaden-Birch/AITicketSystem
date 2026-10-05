"""Updater telemetry is separate from monitoring heartbeats and host command policy."""
import json
import math
import re
import time
from .db import uid

HEARTBEAT_OPERATIONS={'process_summary','service_status','service_logs','container_logs'}

STATES={'current','available','scheduled','waiting','installing','updated','rolled_back','failed','blocked'}


def report(store,agent,payload):
    if not isinstance(payload,dict) or set(payload)-{'state','installed','available','checked','detail','automatic','handled_request'}: raise ValueError('Invalid updater status')
    if payload.get('state') not in STATES: raise ValueError('Invalid updater state')
    for key in ('installed','available'):
        value=payload.get(key)
        if value is not None and (not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9.+_-]{1,64}',value)): raise ValueError('Invalid agent version')
    if type(payload.get('checked')) not in (float,int) or not math.isfinite(payload['checked']) or not 0<=payload['checked']<=time.time()+300: raise ValueError('Invalid update timestamp')
    if type(payload.get('automatic')) is not bool or not isinstance(payload.get('detail',''),str) or len(payload.get('detail',''))>240: raise ValueError('Invalid updater details')
    handled=payload.get('handled_request')
    if handled is not None and (not isinstance(handled,str) or not re.fullmatch('[a-f0-9-]{36}',handled)): raise ValueError('Invalid update request')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute("INSERT OR IGNORE INTO agent_updates(agent_id) VALUES(?)",(agent,))
        c.execute('UPDATE agent_updates SET at=?,status=? WHERE agent_id=?',(time.time(),json.dumps(payload),agent))
        row=c.execute('SELECT request FROM agent_updates WHERE agent_id=?',(agent,)).fetchone()
        if row['request'] and row['request']==handled:
            c.execute('UPDATE agent_updates SET request=NULL WHERE agent_id=?',(agent,));return {'request':None}
        return {'request':row['request']}


def request_update(store,machine):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        agent=c.execute('SELECT id FROM agents WHERE machine_id=? AND revoked=0',(machine,)).fetchone()
        if not agent: raise ValueError('No enrolled agent is linked to this host.')
        row=c.execute('SELECT * FROM agent_updates WHERE agent_id=?',(agent['id'],)).fetchone()
        if not row or row['at']<time.time()-900: raise ValueError('Independent updater unavailable. Run the current installer on this host first.')
        status=json.loads(row['status'])
        if status.get('state')=='rolled_back': raise ValueError('This release failed verification. The updater will wait for a newer corrective release.')
        if not status.get('available') or status.get('installed')==status['available']: raise ValueError('No newer release is reported.')
        if not row['request']:
            identifier=uid();c.execute('UPDATE agent_updates SET request=? WHERE agent_id=?',(identifier,agent['id']))
            store.audit(c,'agent.update_requested',agent['id'],{'request':identifier})


def view(store,agent):
    if not agent: return None
    windows=json.loads(agent.get('host_info') or '{}').get('os','').lower().startswith('windows')
    rows=store.rows('SELECT * FROM agent_updates WHERE agent_id=?',(agent['id'],))
    if not rows: return {'installed':agent.get('version') or 'Not reported','needs_install':True,'windows':windows}
    row=rows[0];status=json.loads(row['status'])
    return {**status,'windows':windows,'at':row['at'],'stale':row['at']<time.time()-900,'pending':bool(row['request']),
            'outdated':bool(status.get('available') and status.get('installed')!=status['available'])}


def compatibility(payload):
    if not isinstance(payload,dict) or set(payload)!={'version','protocol','operations'}:
        raise ValueError('Invalid compatibility request.')
    version=payload['version'];operations=payload['operations']
    if not isinstance(version,str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:\+[a-f0-9]{12})?',version):
        raise ValueError('Invalid release version.')
    if type(payload['protocol']) is not int or not isinstance(operations,list) or len(operations)>16 or any(not isinstance(op,str) or len(op)>80 for op in operations):
        raise ValueError('Invalid release requirements.')
    return {'version':version,'compatible':payload['protocol']==1 and set(operations)<=HEARTBEAT_OPERATIONS}
