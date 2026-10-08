"""Observed changes provide correlation, never proof of causation."""
import json,time
from .db import uid
from .diagnostics import redact


def event(c,machine,entity,kind,before,after,at=None):
    if before==after:return
    at=time.time() if at is None else at
    summary=redact(entity+' · '+kind.replace('_',' ')+' changed')[:200]
    c.execute('INSERT INTO change_events VALUES(?,?,?,?,?,?,?)',(uid(),machine,entity,kind,summary,json.dumps({'before':redact(before,1000) if isinstance(before,str) else before,'after':redact(after,1000) if isinstance(after,str) else after,'note':'Observed change; not proof of cause.'}),at))
    c.execute('DELETE FROM change_events WHERE at<?',(at-30*86400,))


def agent(c,machine,version,discovery,at):
    previous=c.execute('SELECT version FROM agents WHERE machine_id=?',(machine,)).fetchone()
    if previous and previous[0]:event(c,machine,'Monitoring agent','agent_update',previous[0],version,at)
    old=c.execute('SELECT data FROM agent_discovery WHERE machine_id=?',(machine,)).fetchone()
    if old and discovery:
        prior={x['target']:x for x in json.loads(old[0]).get('containers',[])}
        for item in discovery.get('containers',[]):
            prev=prior.get(item['target'])
            if not prev:continue
            for key in ('image_id','image','restart_count','started_at','health'):
                if key in prev and key in item:event(c,machine,item['name'],key,prev[key],item[key],at)


def reboot(c,machine,previous,previous_at,current,at,received):
    """A changed boot estimate is observed on a later heartbeat, not at dispatch."""
    old=previous.get('uptime_seconds');new=current.get('uptime_seconds')
    if type(old) not in (int,float) or type(new) not in (int,float) or not previous_at or at<=previous_at:return
    # Both clocks must be plausible. A shifted wall clock alone cannot prove a reboot.
    if abs(at-received)>300 or new>=old or old-new<5:return
    before=previous_at-old;after=at-new
    if after>previous_at and after-before>30:
        event(c,machine,'Host','reboot',{'estimated_boot':before},{'estimated_boot':after,'observed_at':at,'timing':'Estimated from uptime; first observed at this heartbeat.'},at)


def network(c,machine,current,at):
    old=c.execute('SELECT data FROM network_inventory WHERE machine_id=?',(machine,)).fetchone()
    if not old:return
    previous={item['name']:item for item in json.loads(old[0]).get('interfaces',[])}
    for item in current.get('interfaces',[]):
        prior=previous.get(item['name'])
        if not prior:continue
        for key in ('state','carrier','speed_mbps'):
            if prior.get(key) is not None and item.get(key) is not None:
                event(c,machine,item['name'],'interface_'+key,prior[key],item[key],at)


def integration(c,row,snapshot,at):
    old=json.loads(row['snapshot'] or '{}')
    if not old or old.get('error'):return
    for key in ('version',):
        if key in old and key in snapshot:event(c,row['machine_id'],row['name'],key,old[key],snapshot[key],at)
    if row['kind']=='plex':
        before=old.get('playback',{});after=snapshot.get('playback',{})
        if before.get('error_reporting_available') and after.get('error_reporting_available'):event(c,row['machine_id'],row['name'],'transcode_errors',before.get('transcode_errors'),after.get('transcode_errors'),at)
        previous={x['id']:x for x in old.get('media_locations',[])}
        for item in snapshot.get('media_locations',[]):
            prior_location=previous.get(item['id'])
            if prior_location and prior_location.get('readable') is not None and item.get('readable') is not None:event(c,row['machine_id'],row['name']+' · '+item['library'],'media_access',prior_location['readable'],item['readable'],at)
    prior={x['name']:x for x in old.get('apps',[])}
    for item in snapshot.get('apps',[]):
        prev=prior.get(item['name'])
        if prev:
            for key in ('state','version'):
                if key in item and key in prev:event(c,row['machine_id'],item['name'],key,prev[key],item[key],at)


def context(c,machines,offset=0):
    if type(offset) is not int or not 0<=offset<=10000:raise ValueError('Invalid change-history offset.')
    if not machines:return []
    return [dict(r)|{'details':json.loads(r['details'])} for r in c.execute('SELECT * FROM change_events WHERE machine_id IN ('+','.join('?' for _ in machines)+') AND at>=? ORDER BY at DESC,id LIMIT 30 OFFSET ?',(*sorted(machines),time.time()-30*86400,offset))]
