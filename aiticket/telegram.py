"""Allowlisted Telegram polling with durable inbound IDs and outbound outcomes."""
import json,re,time,secrets,hashlib
import requests
from .db import uid
from .diagnostics import redact

DEFAULTS={'enabled':False,'chats':[],'users':[],'notifications':True,'queries':True,'next_poll':0,'offset':0}


def api(vault,encrypted,method,fields):
    token=vault.decrypt(encrypted)
    if not re.fullmatch(r'\d{5,20}:[A-Za-z0-9_-]{20,100}',token):raise ValueError('Enter a valid bot token from BotFather.')
    # Fixed Telegram endpoint, no redirects, bounded response, no token in error text.
    try:
        with requests.post('https://api.telegram.org/bot'+token+'/'+method,json=fields,timeout=(3,10),allow_redirects=False,stream=True) as r:
            raw=r.raw.read(256001)
            if len(raw)>256000 or r.status_code!=200:raise ValueError('Telegram request failed.')
            reply=json.loads(raw)
            if reply.get('ok') is not True:raise ValueError('Telegram request failed.')
            return reply.get('result')
    except Exception:raise ValueError('Telegram could not respond. Check the bot token and network connection.') from None


def configure(store,vault,form):
    cfg={**DEFAULTS,**store.setting('telegram_config',{})}
    def ids(key):
        values=re.split(r'[\s,]+',form.get(key,'').strip())
        if any(not re.fullmatch(r'-?\d{1,20}',v) for v in values if v):raise ValueError('Use numeric chat and user IDs separated by commas.')
        return list(dict.fromkeys(v for v in values if v))[:20]
    if form.get('enabled')=='yes' and not cfg['enabled']:cfg['enabled_at']=time.time()
    cfg.update(enabled=form.get('enabled')=='yes',chats=ids('chats'),users=ids('users'),notifications=form.get('notifications')=='yes',queries=form.get('queries')=='yes')
    cfg['generation']=secrets.token_hex(8)
    secret=form.get('token','').strip();updates={'telegram_config':cfg}
    if secret:
        if not re.fullmatch(r'\d{5,20}:[A-Za-z0-9_-]{20,100}',secret):raise ValueError('Enter the bot token provided by BotFather.')
        updates['telegram_secret']=vault.encrypt(secret)
        cfg.update(offset=0,next_poll=0,bot_namespace=hashlib.sha256(secret.encode()).hexdigest()[:24])
    if cfg['enabled'] and (not cfg['chats'] or not cfg['users'] or not (secret or store.setting('telegram_secret'))):raise ValueError('Add a bot token, permitted chat IDs and permitted user IDs before enabling.')
    store.save_many(updates,actor='user')


def enqueue(c,event,chat,message):
    c.execute('INSERT OR IGNORE INTO telegram_outbox(id,event_key,chat_id,text,state,created,error) VALUES(?,?,?,?,?,?,NULL)',(uid(),event,str(chat),redact(message)[:4000],'pending',time.time()))


def receive(store,cfg,updates):
    for update in updates[:50]:
        message=update.get('message',{});chat=str(message.get('chat',{}).get('id',''));user=str(message.get('from',{}).get('id',''));identifier=update.get('update_id')
        if type(identifier) is not int:continue
        if chat not in cfg['chats'] or user not in cfg['users'] or message.get('from',{}).get('is_bot') or not isinstance(message.get('text'),str):continue
        # Namespace durable identities across different bots and token rotations.
        if cfg.get('bot_namespace'):identifier=int.from_bytes(hashlib.sha256((cfg['bot_namespace']+':'+str(identifier)).encode()).digest()[:8],'big') & ((1<<63)-1)
        with store.connect() as c:c.execute('INSERT OR IGNORE INTO telegram_updates(update_id,chat_id,user_id,text,created) VALUES(?,?,?,?,?)',(identifier,chat,user,redact(message['text'])[:2000],time.time()))


def handle(store,vault,cfg,row):
    with store.connect() as c:
        if not c.execute("UPDATE telegram_updates SET state='processing' WHERE update_id=? AND state='pending'",(row['update_id'],)).rowcount:return
    message=row['text'].strip();chat=row['chat_id'];reply='Use /status [host name], /ticket TICKET-ID, /reply TICKET-ID note, or /ask TICKET-ID question.'
    try:
        if not cfg['queries']:reply='Chat queries are disabled in Settings.'
        elif message.startswith(('/status','/ticket')):
            from .status_queries import answer,text
            command,_,arg=message.partition(' ')
            reply=text(answer(store,arg.strip() if command.startswith('/status') else '',incident=arg.strip() if command.startswith('/ticket') else None))
        elif message.startswith(('/reply ','/ask ')):
            parts=message.split(' ',2)
            if len(parts)!=3 or not parts[2].strip():raise ValueError('Include a ticket ID and message.')
            identifier=parts[1];body=parts[2].strip()
            with store.connect() as c:
                incident=c.execute('SELECT * FROM incidents WHERE id=?',(identifier,)).fetchone()
                if not incident or incident['closed'] is not None:raise ValueError('Choose an open ticket.')
                if message.startswith('/reply '):store.timeline(c,identifier,'note',body,actor='user')
            if message.startswith('/ask '):
                from .ai import request_job
                job=request_job(store,vault,identifier,mode='advice',question=body,request_id=__import__('uuid').uuid5(__import__('uuid').NAMESPACE_URL,'telegram:'+str(row['update_id'])).__str__(),read_only=True)
                with store.connect() as c:
                    c.execute("UPDATE telegram_updates SET state='waiting',job_id=? WHERE update_id=?",(job,row['update_id']))
                reply='AI investigation requested. I’ll send its findings here. Maintenance and host permissions still apply.'
            else:reply='Note added to the ticket.'
        elif message=='/start':reply='Connected. '+reply
    except ValueError as e:reply=redact(str(e))[:500]
    with store.connect() as c:
        enqueue(c,'reply:'+str(row['update_id']),chat,reply)
        c.execute("UPDATE telegram_updates SET state=CASE WHEN state='waiting' THEN state ELSE 'completed' END WHERE update_id=?",(row['update_id'],))


def notification_allowed(c,row,event,now):
    from .policies import effective,maintained
    from .engine import SEVERITIES
    from .health_rules import incident_paused
    from .ticket_groups import active_primary
    policy=effective(c,row['machine_id'])
    if not policy['enabled'] or SEVERITIES.index(row['severity'])<SEVERITIES.index(policy['minimum']) or event=='recovery' and not policy['recovery']:return 'cancelled'
    if event!='recovery' and (row['closed'] is not None or incident_paused(c,row['id'])):return 'cancelled'
    if row['silence_until']>now or maintained(c,row['machine_id'],now) or c.execute('SELECT 1 FROM incident_sources s JOIN checks ch ON ch.id=s.check_id WHERE s.incident_id=? AND ch.maintenance_until>?',(row['id'],now)).fetchone():return 'paused'
    if event=='opened':
        primary=active_primary(c,row['id'])
        root=c.execute('SELECT machine_id,severity FROM incidents WHERE id=?',(primary,)).fetchone() if primary else None
        pp=effective(c,root['machine_id']) if root else None
        if root and pp['enabled'] and SEVERITIES.index(root['severity'])>=SEVERITIES.index(pp['minimum']):return 'cancelled'
    return 'allowed'


def notification(c,store,incident_id,event,cfg=None):
    cfg=cfg or {**DEFAULTS,**store.setting('telegram_config',{})}
    if not cfg['enabled'] or not cfg['notifications'] or event not in ('opened','recovery') and not event.startswith('blocker:'):return
    row=c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
    report=json.loads(row['report'])
    message=report.get('target','Host')+' · '+report.get('check','Ticket')+'\n'+row['status']+' · '+row['severity'].capitalize()+' priority'
    if event.startswith('blocker:'):
        blocker=c.execute('SELECT reason FROM ticket_blockers WHERE id=? AND cleared IS NULL',(event.split(':')[1],)).fetchone()
        if not blocker:return
        message=report.get('target','Host')+' needs your help.\n'+blocker['reason'][:1000]
    from .worklog import ticket_url
    message+='\n'+(ticket_url(store,row['id']) or ('Ticket '+row['id']))
    for chat in cfg['chats']:enqueue(c,'incident:'+row['id']+':'+event+':'+chat,chat,message)


def notifications(store,cfg):
    # Fill missing channel receipts from durable notification events, not every
    # manual ticket. This preserves the administrator's Notify choice.
    with store.connect() as c:
        for chat in cfg['chats']:
            for delivery in c.execute("SELECT d.* FROM deliveries d WHERE d.created>? AND NOT EXISTS(SELECT 1 FROM telegram_outbox o WHERE o.event_key='incident:'||d.event_key||':'||?) ORDER BY d.created LIMIT 100",(cfg.get('enabled_at',time.time()),chat)).fetchall():
                event=delivery['event_key'].split(':',1)[1]
                notification(c,store,delivery['incident_id'],event,{**cfg,'chats':[chat]})


def tick(store,vault):
    secret=store.setting('telegram_secret');cfg={**DEFAULTS,**store.setting('telegram_config',{})};now=time.time()
    if not secret or not cfg['enabled']:return False
    # One durable polling lease across worker processes.
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE');cfg={**DEFAULTS,**json.loads(c.execute("SELECT value FROM settings WHERE key='telegram_config'").fetchone()[0])}
        if not cfg['enabled'] or cfg['next_poll']>now:return False
        c.execute("UPDATE telegram_outbox SET state='unknown',error='Worker stopped before delivery could be confirmed.' WHERE state='sending' AND next_attempt<?",(now-30,))
        cfg['next_poll']=now+30;cfg.setdefault('enabled_at',now)
        c.execute("UPDATE settings SET value=? WHERE key='telegram_config'",(json.dumps(cfg),))
    try:
        updates=api(vault,secret,'getUpdates',{'offset':cfg['offset'],'limit':50,'timeout':0,'allowed_updates':['message']})
        if not isinstance(updates,list):raise ValueError('Invalid Telegram response.')
        with store.connect() as c:
            current=json.loads(c.execute("SELECT value FROM settings WHERE key='telegram_config'").fetchone()[0])
            if store.setting('telegram_secret')!=secret or any(current.get(k)!=cfg.get(k) for k in ('enabled','chats','users','queries','notifications','generation')):return False
            current['offset']=max([cfg['offset']]+[u['update_id']+1 for u in updates if type(u.get('update_id')) is int]);current['next_poll']=now+5;c.execute("UPDATE settings SET value=? WHERE key='telegram_config'",(json.dumps(current),))
        receive(store,current,updates)
        cfg=current
        for row in store.rows("SELECT * FROM telegram_updates WHERE state='pending' ORDER BY created,update_id LIMIT 10"):
            if row['chat_id'] in cfg['chats'] and row['user_id'] in cfg['users']:handle(store,vault,cfg,row)
            else:
                with store.connect() as c:c.execute("UPDATE telegram_updates SET state='cancelled' WHERE update_id=?",(row['update_id'],))
        for row in store.rows("SELECT u.*,j.state job_state,j.summary FROM telegram_updates u JOIN ai_jobs j ON j.id=u.job_id WHERE u.state='waiting' AND j.state IN ('completed','failed','cancelled','expired','unknown') LIMIT 10"):
            if row['chat_id'] not in cfg['chats'] or row['user_id'] not in cfg['users']:
                with store.connect() as c:c.execute("UPDATE telegram_updates SET state='cancelled' WHERE update_id=?",(row['update_id'],))
                continue
            with store.connect() as c:
                enqueue(c,'answer:'+str(row['update_id']),row['chat_id'],row['summary'][:3500] or 'Investigation '+row['job_state']+'. Open the ticket for details.');c.execute("UPDATE telegram_updates SET state='completed' WHERE update_id=?",(row['update_id'],))
        if cfg['notifications']:notifications(store,cfg)
        row=next(iter(store.rows("SELECT * FROM telegram_outbox WHERE state='pending' AND next_attempt<=? ORDER BY created LIMIT 1",(time.time(),))),None)
        if row:
            current={**DEFAULTS,**store.setting('telegram_config',{})}
            if not current['enabled'] or store.setting('telegram_secret')!=secret:return False
            cfg=current
            with store.connect() as c:
                if row['event_key'].startswith('incident:'):
                    parts=row['event_key'].split(':');incident=c.execute('SELECT * FROM incidents WHERE id=?',(parts[1],)).fetchone()
                    if parts[2]=='blocker' and not c.execute('SELECT 1 FROM ticket_blockers WHERE id=? AND cleared IS NULL',(parts[3],)).fetchone():
                        c.execute("UPDATE telegram_outbox SET state='cancelled' WHERE id=?",(row['id'],));return True
                    disposition=notification_allowed(c,incident,parts[2],time.time()) if incident and cfg['notifications'] else 'cancelled'
                    if disposition=='paused':
                        c.execute('UPDATE telegram_outbox SET next_attempt=? WHERE id=?',(time.time()+30,row['id']));return True
                    if disposition=='cancelled':
                        c.execute("UPDATE telegram_outbox SET state='cancelled' WHERE id=?",(row['id'],));return True
                if not c.execute("UPDATE telegram_outbox SET state='sending',next_attempt=? WHERE id=? AND state='pending'",(time.time(),row['id'])).rowcount:return True
            if row['chat_id'] not in cfg['chats']:state='cancelled'
            else:
                try:api(vault,secret,'sendMessage',{'chat_id':row['chat_id'],'text':row['text'],'link_preview_options':{'is_disabled':True}});state='completed'
                except ValueError:state='unknown' # Acceptance may have occurred; never replay silently.
            with store.connect() as c:c.execute('UPDATE telegram_outbox SET state=? WHERE id=?',(state,row['id']))
        store.save('telegram_health',{'at':time.time(),'status':'Connected'})
    except ValueError:store.save('telegram_health',{'at':time.time(),'status':'Connection needs attention'})
    return True
