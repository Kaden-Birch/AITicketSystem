"""Read-only, self-clearing operational attention across existing subsystems."""
import json
import time
from .policies import maintained

CATEGORIES={'all':'Everything','agents':'Agents','updates':'Updates','connections':'Connections','ai':'Investigations','notifications':'Notifications','monitoring':'Monitoring'}


def collect(store,now=None):
    now=time.time() if now is None else now
    items=[]
    def add(key,category,title,subject,detail,url,action,at=None,priority=1):
        items.append(dict(key=key,category=category,title=title,subject=subject,detail=detail,url=url,action=action,at=at,priority=priority))
    with store.connect() as c:
        paused={r['id'] for r in c.execute('SELECT id FROM machines WHERE offline_expected=1')}
        paused.update(r['id'] for r in c.execute('SELECT id FROM machines') if maintained(c,r['id'],now))
    for row in store.rows('SELECT a.id,a.machine_id,a.last_seen,m.name,u.status,u.at FROM agents a JOIN machines m ON m.id=a.machine_id LEFT JOIN agent_updates u ON u.agent_id=a.id WHERE a.revoked=0'):
        mid=row['machine_id'];settings='/hosts/'+mid+'/settings#agent-updates'
        if mid not in paused and (not row['last_seen'] or now-row['last_seen']>180):
            add('agent:'+row['id'],'agents','Agent is disconnected',row['name'],'No recent heartbeat. Check the agent service and its connection to the application.','/hosts/'+mid,'Open host',row['last_seen'],0)
        if row['status']:
            status=json.loads(row['status']);state=status.get('state')
            if state in ('failed','rolled_back','blocked'):
                title={'failed':'Update could not complete','rolled_back':'Previous agent restored','blocked':'Update needs the application ready'}[state]
                add('update:'+row['id'],'updates',title,row['name'],'Review the update status and local recovery commands before trying again.',settings,'Review update',row['at'],0)
            elif mid not in paused and (not row['at'] or now-row['at']>900):
                add('update:'+row['id'],'updates','Updater is not checking in',row['name'],'The independent updater has not reported recently. Check its timer or scheduled task.',settings,'Review updater',row['at'])
            elif status.get('available') and status.get('available')!=status.get('installed'):
                add('update:'+row['id'],'updates','Agent update available',row['name'],'A newer release is available. Automatic updates may be scheduled or waiting for active work.',settings,'Review update',row['at'],2)
        elif mid not in paused:
            add('update:'+row['id'],'updates','Automatic updater setup needed',row['name'],'Run the current installer once to add independent updates. Existing enrollment is preserved.',settings,'Set up updater',None,2)
    from .integrations import views
    for row in views(store):
        if row['machine_id'] in paused:continue
        if row['data'].get('error') or row['data'].get('warnings') or not row['fresh']:
            url='/hosts/'+row['machine_id']+'/settings' if row['kind']=='truenas' else '/services/'+row['id']
            error=str(row['data'].get('error','')).lower()
            credentials=any(word in error for word in ('key','token','permission','authentication','rejected'))
            detail='The API key or its permissions need review. Check the key owner, expiry and read access.' if credentials else 'Some readings are unavailable. Test the connection and check its credentials, permissions and address.'
            add('integration:'+row['id'],'connections',row['kind'].capitalize()+' connection needs attention',row['name'],detail,url,'Review connection',row['at'])
    for row in store.rows('SELECT id,name,machine_id,snapshot FROM unifi_connections WHERE deleted IS NULL'):
        if row['machine_id'] in paused:continue
        snapshot=json.loads(row['snapshot'] or '{}')
        if not snapshot or snapshot.get('errors') or snapshot.get('error'):
            add('unifi:'+row['id'],'connections','UniFi connection needs attention',row['name'],'Some API readings are unavailable. Check the connection and read permissions.','/network-devices/'+row['id']+'/settings','Review connection')
    # Cluster endpoints are redundant; an endpoint error is not proof that the cluster is down.
    for row in store.rows("SELECT cl.id,cl.name,max(pc.last_discovery) at FROM proxmox_clusters cl JOIN proxmox_connections pc ON pc.cluster_id=cl.id JOIN discovery_schedules ds ON ds.connection_id=pc.id WHERE ds.last_error IS NOT NULL AND ds.last_error!='' GROUP BY cl.id"):
        add('proxmox:'+row['id'],'connections','Proxmox refresh needs attention',row['name'],'A refresh reported a connection error. Review cluster endpoints and credentials; this does not establish a cluster outage.','/proxmox','Review Proxmox',row['at'])
    connection=store.setting('hermes_connection',{})
    if connection.get('state')=='Needs attention':
        add('hermes','connections','Hermes connection needs attention','AI service','Reconnect Hermes in Settings, then run a read-only test investigation.','/settings/ai','Open AI settings',connection.get('at'),0)
    sql="""SELECT j.id,j.incident_id,j.state,j.created,j.expires,j.maintenance_paused_at,m.name
    FROM ai_jobs j JOIN incidents i ON i.id=j.incident_id JOIN machines m ON m.id=i.machine_id
    WHERE i.closed IS NULL AND i.status!='Resolved' AND j.id=(SELECT id FROM ai_jobs WHERE incident_id=i.id ORDER BY created DESC,id DESC LIMIT 1)"""
    for row in store.rows(sql):
        if row['maintenance_paused_at']:continue
        state=row['state']
        if state in ('failed','unknown','expired') or state in ('pending','dispatching','running') and row['expires']<=now:
            title={'unknown':'Investigation outcome is uncertain','failed':'Investigation could not finish','expired':'Investigation timed out'}.get(state,'Investigation is overdue')
            add('ai:'+row['id'],'ai',title,row['name'],'Review the latest ticket update and outstanding operations before continuing.','/incidents/'+row['incident_id'],'Open ticket',row['created'],0)
    for row in store.rows("SELECT b.incident_id,m.name,min(b.created) at FROM ticket_blockers b JOIN incidents i ON i.id=b.incident_id JOIN machines m ON m.id=i.machine_id WHERE b.cleared IS NULL AND i.closed IS NULL AND i.status!='Resolved' GROUP BY b.incident_id"):
        if not any(item['url']=='/incidents/'+row['incident_id'] and item['category']=='ai' for item in items):
            add('blocker:'+row['incident_id'],'ai','Ticket needs your input',row['name'],'Review the ticket for the decision or information needed to continue.','/incidents/'+row['incident_id'],'Open ticket',row['at'],0)
    for row in store.rows("SELECT state,count(*) count,min(created) at FROM deliveries WHERE state IN ('failed','expired') GROUP BY state"):
        add('discord:'+row['state'],'notifications',str(row['count'])+' Discord notifications need review','Discord','Review failed or expired messages. Retry only after checking the recorded delivery outcome.','/queue?view=attention','Open delivery queue',row['at'])
    for row in store.rows("SELECT state,count(*) count,min(created) at FROM telegram_outbox WHERE state IN ('failed','unknown') GROUP BY state"):
        add('telegram:'+row['state'],'notifications',str(row['count'])+' Telegram messages need review','Telegram','Delivery is unconfirmed. Review Telegram status; retrying an uncertain message can send a duplicate.','/settings/telegram','Review Telegram',row['at'])
    from .reliability import issues
    linked={item['subject'] for item in items if item['category']=='connections'}
    for index,row in enumerate(issues(store,now)):
        if row['machine_id'] in paused or row['host'] in linked:continue
        add('monitoring:'+str(index),'monitoring',row['title'],row['host'],'Current monitoring evidence is incomplete. Review data collection and permissions.','/monitoring-health','Review monitoring')
    return sorted(items,key=lambda item:(item['priority'],-(item['at'] or 0),item['key']))


def listing(store,category='all',query='',page=1):
    if category not in CATEGORIES or not 1<=page<=100000:raise ValueError('Choose a valid attention category and page.')
    items=collect(store);counts={key:0 for key in CATEGORIES};counts['all']=len(items)
    for item in items:counts[item['category']]+=1
    filtered=[i for i in items if (category=='all' or i['category']==category) and query.casefold() in (i['title']+' '+i['subject']+' '+i['detail']).casefold()]
    start=(page-1)*20
    return {'items':filtered[start:start+20],'total':len(filtered),'counts':counts,'categories':CATEGORIES,'more':len(filtered)>start+20}
