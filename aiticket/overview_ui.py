"""Read-only fleet summaries and ticket list projections."""
import json,time,math
from datetime import datetime,timedelta
from zoneinfo import ZoneInfo

NAV=[('Dashboard','/'),('Hosts','/hosts'),('Tickets','/tickets'),('Network Devices','/network-devices'),('Proxmox','/proxmox'),('Fleet','/fleet'),('Agent health','/resources'),('Delivery queue','/queue'),('Audit','/audit'),('Policies','/policies'),('Hermes & usage','/hermes'),('Recovery policy','/recovery-policy'),('Settings','/settings'),('Administration','/administration')]


def ticket_rows(store,now=None):
    now=time.time() if now is None else now
    rows=store.rows('''SELECT i.*,m.name machine,ic.owner,ic.handling_mode,
    EXISTS(SELECT 1 FROM ticket_blockers b WHERE b.incident_id=i.id AND b.cleared IS NULL) blocked,
    EXISTS(SELECT 1 FROM ai_jobs j WHERE j.incident_id=i.id) has_ai,
    EXISTS(SELECT 1 FROM ai_jobs j WHERE j.incident_id=i.id AND j.state IN ('dispatching','running')) running,
    EXISTS(SELECT 1 FROM ticket_blockers b WHERE b.incident_id=i.id) OR EXISTS(SELECT 1 FROM work_sessions w WHERE w.incident_id=i.id AND w.actor='user') OR EXISTS(SELECT 1 FROM timeline t WHERE t.incident_id=i.id AND t.actor='user' AND t.kind='handoff_user') intervened,
    COALESCE((SELECT sum(max(0,COALESCE(w.ended,?)-w.started)) FROM work_sessions w WHERE w.incident_id=i.id),0) seconds,
    (SELECT count(*) FROM work_sessions w WHERE w.incident_id=i.id AND w.ended IS NULL) active_timers
    FROM incidents i JOIN machines m ON m.id=i.machine_id LEFT JOIN incident_control ic ON ic.incident_id=i.id ORDER BY i.first_seen DESC,i.id''',(now,))
    for r in rows:
        r['resolved']=r['closed'] is not None or r['status']=='Resolved'
        r['category']='resolved' if r['resolved'] else 'manual' if r['blocked'] or r['owner']=='user' or r['status'] in ('Needs user intervention','Awaiting approval') else 'ai' if r['running'] else 'new'
        r['label']={'resolved':'Resolved','manual':'Needs attention','ai':'AI working','new':'New / queued'}[r['category']]
        r['title']=json.loads(r['report']).get('check','Ticket')
        r['agent']='Hermes' if r['has_ai'] else '—'
        r['server_now']=now
    return rows


def host_list(store,now=None):
    from .hostview import overview
    now=time.time() if now is None else now
    hosts=overview(store,now)
    checks={};last={r['machine_id']:r['at'] for r in store.rows('SELECT machine_id,max(first_seen) at FROM incidents GROUP BY machine_id')}
    for r in store.rows("SELECT * FROM checks WHERE enabled=1 AND kind<>'manual'"):checks.setdefault(r['machine_id'],[]).append(r)
    for h in hosts:
        cs=checks.get(h['id'],[]);h['check_count']=len(cs);h['last_ticket']=last.get(h['id']);h['frequency']=str(store.setting('agent_interval',30))+'s' if h['agent'] else (str(min(c['interval'] for c in cs))+'s' if cs else '—')
        obj=h['object'];agent=h['agent']
        stopped=bool(obj and obj['kind'] in ('qemu','lxc') and obj['status']=='stopped' and obj['present'] and not obj['missing_since'] and 0<=now-obj['last_seen']<=180)
        if h.get('offline_expected') or stopped:h['state']='offline';h['state_label']='Offline (intentional)' if h.get('offline_expected') else 'Powered down'
        elif agent and not agent['revoked'] and (not agent['last_seen'] or now-agent['last_seen']>180):h['state']='unreachable';h['state_label']='Unreachable'
        elif any(c['health']=='down' and c['severity']=='critical' for c in cs):h['state']='unreachable';h['state_label']='Critical check failure'
        elif any(c['health']!='healthy' or c['failures'] for c in cs) or not h['sample']['fresh']:h['state']='warning';h['state_label']='Needs attention / awaiting data'
        else:h['state']='healthy';h['state_label']='Healthy'
    return hosts


def plot(label,values,unit='',ceiling=None):
    known=[v for v in values if v is not None];ceiling=ceiling or max([1]+known)*1.1
    segments=[];points=[]
    for i,value in enumerate(values):
        if value is None:
            if points:segments.append(' '.join(points));points=[]
        else:points.append(f'{35+(i+.5)/len(values)*530:.1f},{140-min(ceiling,max(0,value))/ceiling*115:.1f}')
    if points:segments.append(' '.join(points))
    return {'label':label,'unit':unit,'segments':segments,'ceiling':round(ceiling,1),'latest':round(known[-1],1) if known else None}


def dashboard_data(store,now=None):
    now=time.time() if now is None else now
    rows=ticket_rows(store,now);hosts=host_list(store,now)
    tz=ZoneInfo(store.setting('display_timezone','America/Edmonton'));today=datetime.fromtimestamp(now,tz).date();days=[today-timedelta(days=29-i) for i in range(30)]
    counts=[0]*30;resolutions=[[] for _ in days];manual=[0]*30
    for row in rows:
        date=datetime.fromtimestamp(row['first_seen'],tz).date()
        if date in days:
            i=days.index(date);counts[i]+=1;manual[i]+=bool(row['intervened'])
        if row['closed'] is not None:
            date=datetime.fromtimestamp(row['closed'],tz).date()
            if date in days:resolutions[days.index(date)].append(max(0,row['closed']-row['first_seen'])/3600)
    samples=store.rows('SELECT * FROM metric_samples WHERE at>=? AND at<=? ORDER BY at',(now-86400,now))
    entities={(h['id'],'agent') if h['agent'] else (h['object']['id'],'proxmox') for h in hosts if h['agent'] or h['object']}
    buckets=[{} for _ in range(96)]
    for sample in samples:
        identity=(sample['entity_id'],sample['source'])
        if identity in entities:buckets[min(95,int((sample['at']-(now-86400))/900))][identity]=json.loads(sample['metrics'])
    charts=[]
    for key,label in [('cpu_percent','Average CPU'),('ram_percent','Average RAM'),('disk_percent','Average storage')]:
        means=[]
        for bucket in buckets:
            values=[v[key] for v in bucket.values() if type(v.get(key)) in (int,float) and math.isfinite(v[key])]
            means.append(sum(values)/len(values) if values else None)
        charts.append(plot(label,means,'%',100))
    mean_resolution=[sum(v)/len(v) if v else None for v in resolutions]
    interventions=[100*m/n if n else None for m,n in zip(manual,counts)]
    closed=[r for r in rows if r['closed'] is not None and r['closed']>=datetime.combine(days[0],datetime.min.time(),tz).timestamp()]
    return {'hosts':len(hosts),'agents':sum(bool(h['agent'] and not h['agent']['revoked']) for h in hosts),'open':sum(not r['resolved'] for r in rows),'total':len(rows),'recent':sum(counts),'average_hours':round(sum(max(0,r['closed']-r['first_seen']) for r in closed)/len(closed)/3600,1) if closed else None,'manual_percent':round(100*sum(manual)/sum(counts),1) if sum(counts) else None,'charts':charts,'ticket_charts':[plot('Tickets created',counts),plot('Average time to resolution',mean_resolution,'h'),plot('Manual intervention',interventions,'%',100)],'start':now-86400,'end':now,'date_start':str(days[0]),'date_end':str(days[-1])}
