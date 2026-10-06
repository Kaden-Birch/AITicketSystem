"""Bounded log-pattern evidence and policy-governed tickets. Never infers repair authority."""
import hashlib
import json
import re
import sqlite3
import time
from . import network_logs as logs
from .db import uid
from .engine import observe
from .policies import maintained,active

KINDS={'disconnect':'Repeated disconnects','flap':'Port flapping','restart':'Device restarts','wan':'WAN failovers','auth':'Authentication failures'}
NAMES={
 'disconnect':('client disconnected','wifi client disconnected','wi-fi client disconnected','wired client disconnected'),
 'flap':('port link down','port link up','port disconnected','port connected','port down','port up'),
 'restart':('device restarted','device rebooted','device restart','device reboot'),
 'wan':('wan failover','wan failed over','internet failover','wan switched','internet switched'),
 'auth':('wifi authentication failed','wi-fi authentication failed','client authentication failed','authentication failed','authentication failure','login failed','failed login')}


def classify(event):
    if event.get('format')!='CEF': return None
    name=' '.join(re.sub(r'[^a-z0-9 ]',' ',event['name'].lower()).split())
    return next((kind for kind,names in NAMES.items() if name in names),None)


def rules(store):
    return [dict(row)|{'config':json.loads(row['config'])} for row in store.rows('SELECT * FROM log_problem_rules ORDER BY name')]


def save_rule(store,values):
    kind=values.get('kind');name=values.get('name','').strip();identifier=values.get('id') or uid()
    try: count=int(values.get('count',3));window=int(values.get('minutes',15))*60
    except (TypeError,ValueError): raise ValueError('Enter whole numbers for the count and window.')
    severity=values.get('severity','medium');source=values.get('source_id') or None
    aliases=[line.strip() for line in values.get('event_names','').splitlines() if line.strip()]
    if kind not in KINDS or not 1<=len(name)<=100 or not 2<=count<=1000 or not 60<=window<=86400 or severity not in ('low','medium','high','critical') or len(aliases)>20 or any(len(n)>200 for n in aliases):
        raise ValueError('Choose a supported pattern, 2–1,000 events, 1–1,440 minutes and a valid severity/name. Up to 20 exact event names are supported.')
    cfg={'count':count,'window':window,'severity':severity,'tickets':values.get('tickets')=='yes','event_names':aliases}
    with store.connect() as c:
        if source and not c.execute('SELECT 1 FROM log_sources WHERE id=?',(source,)).fetchone():raise ValueError('Choose an existing log source.')
        if not values.get('id') and c.execute('SELECT count(*) FROM log_problem_rules').fetchone()[0]>=30:raise ValueError('Up to 30 pattern rules are supported.')
        if values.get('id') and not c.execute('SELECT 1 FROM log_problem_rules WHERE id=?',(identifier,)).fetchone():raise ValueError('Unknown rule.')
        now=time.time()
        c.execute('INSERT INTO log_problem_rules VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,source_id=excluded.source_id,config=excluded.config,enabled=excluded.enabled,updated=excluded.updated',
                  (identifier,name,kind,source,json.dumps(cfg),int(values.get('enabled')=='yes'),now,now))
        # A changed definition cannot silently inherit old counts or evidence.
        c.execute("UPDATE log_problems SET state='paused' WHERE rule_id=?",(identifier,))
        c.execute('UPDATE checks SET enabled=0 WHERE id IN (SELECT check_id FROM log_problems WHERE rule_id=?)',(identifier,))
        store.audit(c,'network_logs.rule_saved',identifier,{'kind':kind,'enabled':values.get('enabled')=='yes'})
    return identifier


def snapshot(store,now):
    try:
        with logs.reader(store) as c:
            deadline=time.monotonic()+0.35;c.set_progress_handler(lambda:int(time.monotonic()>deadline),2000)
            rows=c.execute('SELECT * FROM events WHERE at>=? AND at<=? ORDER BY at DESC,id DESC LIMIT 5001',(now-86400,now+30)).fetchall()
        with store.connect() as c:return logs.decorate(c,rows[:5000]),len(rows)>5000,True
    except (sqlite3.Error,OSError):return [],False,False


def key(event,kind):
    device=event.get('device_mac');client=event.get('client_mac');port=event.get('port')
    if kind=='flap':return (device,str(port)) if device and str(port or '').isascii() and str(port or '').isdigit() else None
    if kind in ('disconnect','auth'):return (device or '',client) if client else None
    return (device,) if device else None


def anchor(event,kind):
    roles=('client','infrastructure','console') if kind in ('disconnect','auth') else ('infrastructure','client','console')
    return next((a['machine_id'] for role in roles for a in event['associations'] if a['role']==role),None)


def tick(store,now=None,force=False):
    now=time.time() if now is None else now
    if not force and now-store.setting('network_problem_last_tick',0)<30:return
    store.save('network_problem_last_tick',now)
    definitions=[r for r in rules(store) if r['enabled']]
    if not definitions:
        if store.setting('network_log_correlation',False):correlate(store,now)
        return
    records,capped,available=snapshot(store,now)
    store.save('network_problem_scan',{'at':now,'capped':capped,'available':available,'scanned':len(records)})
    if not available:return  # Missing history is never a recovery signal.
    with store.connect() as c:
        sources={r['id']:dict(r) for r in c.execute('SELECT * FROM log_sources WHERE enabled=1')}
        parents={r['id']:r['parent_id'] for r in c.execute('SELECT id,parent_id FROM machines')}
        windows=[dict(r) for r in c.execute('SELECT * FROM maintenance_windows WHERE enabled=1')]
    def in_maintenance(machine,at):
        targets=set();current=machine
        while current and current not in targets:targets.add(current);current=parents.get(current)
        return any((w['machine_id'] is None or w['machine_id'] in targets) and active(w,at) for w in windows)
    limited=False
    # Keep completed, inactive problem bookkeeping bounded; incident history remains intact.
    with store.connect() as c:
        expired=c.execute("SELECT p.id,p.check_id FROM log_problems p LEFT JOIN incidents i ON i.id=p.incident_id WHERE p.last_seen<? AND (p.incident_id IS NULL OR i.closed IS NOT NULL OR i.status='Resolved')",(now-30*86400,)).fetchall()
        for row in expired:
            if row['check_id']:c.execute('UPDATE checks SET enabled=0 WHERE id=?',(row['check_id'],))
            c.execute('DELETE FROM log_problems WHERE id=?',(row['id'],))
    for rule in definitions:
        cfg=rule['config'];groups={};suppressed=0
        for event in records:
            if event['source_id'] not in sources or rule['source_id'] and event['source_id']!=rule['source_id'] or not now-cfg['window']<=event['at']<=now+30:continue
            if cfg['event_names']:
                if event['format']!='CEF' or event['name'].casefold() not in {n.casefold() for n in cfg['event_names']}:continue
            elif classify(event)!=rule['kind']:continue
            identity=key(event,rule['kind'])
            if not identity:continue
            hosts={a['machine_id'] for a in event['associations'] if a['role'] in ('client','infrastructure','console')}
            # Exclude expected events in their event-time window and currently maintained targets.
            if any(in_maintenance(m,event['at']) or in_maintenance(m,now) for m in hosts):suppressed+=1;continue
            if not hosts and (in_maintenance(None,event['at']) or in_maintenance(None,now)):suppressed+=1;continue
            fingerprint=hashlib.sha256(json.dumps([rule['updated'],event['source_id'],identity,anchor(event,rule['kind'])]).encode()).hexdigest()
            groups.setdefault(fingerprint,[]).append(event)
        limited=limited or len(groups)>200
        seen=set()
        for fingerprint,events in list(groups.items())[:200]:
            # Exact repeated timestamp/name/identity messages are one observation; receipt-only messages cannot be deduplicated safely.
            unique={json.dumps([e['at'],e['name'],e['source_id'],key(e,rule['kind'])]):e for e in events};events=sorted(unique.values(),key=lambda e:(e['at'],e['id']))
            count=len(events)
            if rule['kind']=='flap':
                states=[bool(re.search(r'\b(up|connected)\b',e['name'].lower())) for e in events]
                count=sum(a!=b for a,b in zip(states,states[1:]))
            latest=events[-1];hosts=sorted({a['machine_id'] for e in events for a in e['associations']})[:50]
            enough=count>=cfg['count'];fresh=-30<=now-latest['at']<=180 and abs(latest['received']-latest['at'])<=180
            state='active' if enough else 'below threshold'
            with store.connect() as c:
                previous=c.execute('SELECT * FROM log_problems WHERE rule_id=? AND fingerprint=?',(rule['id'],fingerprint)).fetchone()
                if not previous and not enough:continue
                if not previous and c.execute('SELECT count(*) FROM log_problems').fetchone()[0]>=1000:
                    limited=True;continue
                identifier=previous['id'] if previous else uid();seen.add(identifier)
                old=json.loads(previous['data']) if previous else {};seen_keys=set(old.get('seen_keys',[]))
                new_keys={e['event_key'] for e in events}-seen_keys
                room=max(0,5000-len(seen_keys));tracked=sorted(new_keys)[:room]
                seen_keys.update(tracked)
                target=anchor(latest,rule['kind'])
                data={'name':rule['name'],'kind':rule['kind'],'device_mac':latest['device_mac'],'port':latest['port'],'client_mac':latest['client_mac'],'hosts':hosts,
                      'events':[{'id':e['id'],'event_key':e['event_key'],'at':e['at'],'name':e['name'],'url':'/network-events/'+str(e['id'])+'?event_key='+e['event_key']} for e in events[-20:]],
                      'window':cfg['window'],'window_first':events[0]['at'],'window_last':latest['at'],'capped':capped,'suppressed':suppressed,
                      'seen_keys':sorted(seen_keys),'total_observations':old.get('total_observations',0)+len(tracked),'count_tracking_limited':old.get('count_tracking_limited',False) or len(new_keys)>room,
                      'fact':f'{count} '+('observed link transitions' if rule['kind']=='flap' else 'matching observations')+' in the rule window.',
                      'suspected_cause':'Unknown. Repetition and shared timing do not establish cause.'}
                check_id=previous['check_id'] if previous else None
                if cfg['tickets'] and enough and fresh and target and not check_id:
                    check_id='log-problem-'+identifier
                    c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity) VALUES(?,?,?,?,?,30,1,2,?)',
                              (check_id,target,rule['name'],'network_problem','{}',cfg['severity']))
                c.execute('INSERT INTO log_problems VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,state=excluded.state,last_seen=excluded.last_seen,event_count=excluded.event_count,check_id=excluded.check_id,updated=excluded.updated',
                          (identifier,rule['id'],fingerprint,latest['source_id'],json.dumps(data),state,events[0]['at'],latest['at'],count,check_id,previous['incident_id'] if previous else None,now))
            if check_id:
                with store.connect() as c:c.execute('UPDATE checks SET severity=? WHERE id=?',(cfg['severity'],check_id))
                evidence={**{k:v for k,v in data.items() if k!='seen_keys'},'reason':rule['name']+': '+data['fact'],'problem_id':identifier,'requires_manual_verification':True}
                # Quiet/expired patterns are unknown, not verified healthy networking.
                observe(store,check_id,False if enough and fresh else None,evidence,now)
                with store.connect() as c:
                    incident=c.execute('SELECT id FROM incidents WHERE check_id=? AND closed IS NULL',(check_id,)).fetchone()
                    if incident:c.execute('UPDATE log_problems SET incident_id=? WHERE id=?',(incident[0],identifier))
        with store.connect() as c:
            stale=c.execute("SELECT id,check_id,data FROM log_problems WHERE rule_id=? AND state NOT IN ('paused','acknowledged')",(rule['id'],)).fetchall()
            for row in stale:
                if row['id'] in seen:continue
                c.execute("UPDATE log_problems SET state='no recent observations',updated=? WHERE id=? AND state!='no recent observations'",(now,row['id']))
        for row in stale:
            if row['id'] not in seen and row['check_id']:observe(store,row['check_id'],None,{'reason':'No recent matching observations; quiet logs do not verify recovery.'},now)
    store.save('network_problem_scan',{'at':now,'capped':capped,'available':available,'scanned':len(records),'groups_limited':limited})
    if store.setting('network_log_correlation',False):correlate(store,now)


def correlate(store,now):
    """Current compatible reachability failures with an explicit shared network path."""
    from .topology import context
    from .ticket_groups import attach,active_primary
    clusters={}
    with store.connect() as c:
        rows=c.execute("SELECT i.id,i.machine_id,ch.kind,ch.interval,o.at FROM incidents i JOIN checks ch ON ch.id=i.check_id JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=ch.id ORDER BY at DESC LIMIT 1) WHERE i.closed IS NULL AND i.status!='Resolved' AND i.merged_into IS NULL AND ch.enabled=1 AND ch.health='down' AND o.health='down' AND ch.kind IN ('agent','http','tcp','proxmox','proxmox_linked','unifi_device','network_problem') ORDER BY i.first_seen LIMIT 100").fetchall()
        for row in rows:
            if not 0<=now-row['at']<=max(180,row['interval']*3) or maintained(c,row['machine_id'],now):continue
            facts=context(c,row['machine_id'],now)
            for link in facts.get('links',[])+facts.get('physical_host',{}).get('links',[]):
                if link['confidence'] not in ('confirmed','corroborated') or not link.get('fresh'):continue
                clusters.setdefault((link['connection_id'],link['device_id']),[]).append(dict(row))
            for d in c.execute('SELECT connection_id,device_id FROM unifi_devices WHERE machine_id=? AND deleted IS NULL',(row['machine_id'],)):
                clusters.setdefault((d[0],d[1]),[]).append(dict(row))
        for key,items in clusters.items():
            # Preserve current groups and human exclusions; no correlation from a lone host.
            items=list({i['id']:i for i in items}.values())
            if len({i['machine_id'] for i in items})<2:continue
            primary=active_primary(c,items[0]['id']) or items[0]['id']
            clusters[key]=(primary,[i['id'] for i in items])
    for value in clusters.values():
        if not isinstance(value,tuple):continue
        primary,members=value
        for member in members:
            if member==primary:continue
            try:attach(store,primary,member,'Current reachability failures share a confirmed/corroborated switch path. Shared impact is observed; cause remains unconfirmed.',automatic=True,now=now)
            except ValueError:pass


def problems(store):
    return [dict(r)|{'data':json.loads(r['data'])} for r in store.rows('SELECT p.*,r.name AS rule_name FROM log_problems p JOIN log_problem_rules r ON r.id=p.rule_id ORDER BY p.updated DESC LIMIT 100')]
