"""Read-only fleet summaries and ticket list projections."""
import json,time
from datetime import datetime,timedelta
from zoneinfo import ZoneInfo

NAV=[('Dashboard','/'),('Needs attention','/attention'),('Hosts','/hosts'),('Tickets','/tickets'),('Network Devices','/network-devices'),('Proxmox','/proxmox'),('Fleet','/fleet'),('Applications','/applications'),('Knowledge Base','/knowledge'),('Monitoring health','/monitoring-health'),('Delivery queue','/queue'),('Audit','/audit'),('Settings','/settings')]


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
        if date in days and row['first_seen']<=now:
            i=days.index(date);counts[i]+=1;manual[i]+=bool(row['intervened'])
        if row['closed'] is not None:
            date=datetime.fromtimestamp(row['closed'],tz).date()
            if date in days and row['closed']<=now:resolutions[days.index(date)].append(max(0,row['closed']-row['first_seen'])/3600)
    resolved_counts=[len(v) for v in resolutions]
    mean_resolution=[sum(v)/len(v) if v else None for v in resolutions]
    start=datetime.combine(days[0],datetime.min.time(),tz).timestamp()
    closed=[r for r in rows if r['closed'] is not None and start<=r['closed']<=now]
    opened_today=counts[-1];resolved_today=resolved_counts[-1]
    backlog=[]
    for day in days:
        cutoff=min(now,datetime.combine(day+timedelta(days=1),datetime.min.time(),tz).timestamp()-0.000001)
        backlog.append(sum(r['first_seen']<=cutoff and (r['closed'] is None or r['closed']>cutoff) for r in rows))
    states={'healthy':0,'warning':0,'unreachable':0,'offline':0}
    for h in hosts:
        state='warning' if h['state']=='unreachable' and h['state_label']!='Unreachable' else h['state']
        states[state]+=1
    from .policies import maintained
    checks={'healthy':0,'retrying':0,'down':0,'unknown':0,'paused':0}
    with store.connect() as c:
        for check in c.execute("SELECT k.*,(SELECT max(at) FROM observations o WHERE o.check_id=k.id) last_checked FROM checks k WHERE enabled=1 AND kind<>'manual'"):
            if check['maintenance_until']>now or maintained(c,check['machine_id'],now):state='paused'
            elif not check['last_checked'] or now-check['last_checked']>max(180,check['interval']*3):state='unknown'
            elif check['health']=='down':state='down'
            elif check['failures']:state='retrying'
            elif check['health']=='healthy':state='healthy'
            else:state='unknown'
            checks[state]+=1
    notifications=store.rows("SELECT count(*) count FROM deliveries WHERE state IN ('failed','expired')")[0]['count']
    flow=plot('Tickets opened vs resolved',counts)
    flow['latest']=None
    flow['series']=[{**plot('Opened',counts,ceiling=max([1]+counts+resolved_counts)*1.1),'color':'opened'},
                    {**plot('Resolved',resolved_counts,ceiling=max([1]+counts+resolved_counts)*1.1),'color':'resolved'}]
    flow['ceiling']=flow['series'][0]['ceiling']
    return {'open':sum(not r['resolved'] for r in rows),'recent':sum(counts),
            'average_hours':round(sum(max(0,r['closed']-r['first_seen']) for r in closed)/len(closed)/3600,1) if closed else None,
            'average_resolution':duration(sum(max(0,r['closed']-r['first_seen']) for r in closed)/len(closed)) if closed else '—',
            'manual_percent':round(100*sum(manual)/sum(counts),1) if sum(counts) else None,
            'resolved_count':len(closed),'opened_today':opened_today,'resolved_today':resolved_today,
            'needs_help':sum(r['category']=='manual' for r in rows),'ai_working':sum(r['category']=='ai' for r in rows),
            'queued':sum(r['category']=='new' for r in rows),'host_health':states,'check_health':checks,
            'hosts_attention':states['warning']+states['unreachable'],'notification_review':notifications,
            'ai_enabled':bool(store.setting('hermes_config',{}).get('enabled')),
            'daily':[{'date':str(day),'opened':counts[i],'resolved':resolved_counts[i],'resolution':mean_resolution[i]*60 if mean_resolution[i] is not None else None,'backlog':backlog[i],'manual':manual[i]} for i,day in enumerate(days)],
            'charts':[],'ticket_charts':[flow,plot('Open ticket backlog',backlog),plot('Average time to resolution',mean_resolution,'h')],
            'date_start':str(days[0]),'date_end':str(days[-1])}


def duration(seconds):
    if seconds<60:return str(round(seconds))+'s'
    if seconds<3600:return str(round(seconds/60))+'m'
    if seconds<86400:return str(round(seconds/3600,1))+'h'
    return str(round(seconds/86400,1))+'d'
