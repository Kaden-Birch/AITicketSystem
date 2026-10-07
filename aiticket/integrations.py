"""Agentless sources share durable polling, encrypted credentials and host identity."""
import json,time
from urllib.parse import urlsplit
from pathlib import Path
from .db import uid
from .security import validate_url


def config(form,kind):
    url=validate_url(form.get('url','').strip().rstrip('/'),('https',) if kind=='truenas' else ('https','http'))
    p=urlsplit(url)
    if p.query or p.path not in ('','/') or (kind=='truenas' and p.scheme!='https'):raise ValueError('Enter the server address only, such as https://nas.example.com. TrueNAS requires HTTPS.')
    verify_tls=not (kind=='truenas' and form.get('skip_certificate_verification')=='yes')
    ca=form.get('ca','').strip()
    if verify_tls and ca and (not Path(ca).is_file() or not __import__('os').access(ca,__import__('os').R_OK)):raise ValueError('The certificate file is not readable by the application. Use its path inside the application container.')
    try:interval=int(form.get('interval',60))
    except (TypeError,ValueError):raise ValueError('Enter a refresh interval in seconds.')
    if not 30<=interval<=3600:raise ValueError('Choose a refresh interval between 30 and 3600 seconds.')
    result={'url':url,'ca':ca or True,'interval':interval}
    if kind=='truenas':
        username=form.get('username','').strip()
        if not username or len(username)>100:raise ValueError('Enter the TrueNAS user that owns the API key.')
        result['username']=username
        result['verify_tls']=verify_tls
    else:
        library=form.get('library_id','').strip()
        if library and not library.isdigit():raise ValueError('Choose a valid Plex library.')
        result['library_id']=library
        libraries=form.getlist('library_ids') if hasattr(form,'getlist') else form.get('library_ids',[])
        if not isinstance(libraries,list) or len(libraries)>10 or any(not isinstance(x,str) or not x.isdigit() for x in libraries):raise ValueError('Choose up to ten Plex libraries.')
        result['library_ids']=list(dict.fromkeys(([library] if library else [])+libraries))
        if len(result['library_ids'])>10:raise ValueError('Choose up to ten Plex libraries.')
        result['deep_monitoring']=True
    return result


def save(store,vault,machine,kind,name,cfg,secret,identifier=None,snapshot=None,parent=None):
    if not isinstance(secret,str) or len(secret)>8192:raise ValueError('Enter a valid API key or Plex token.')
    if kind not in ('truenas','plex') or not 1<=len(name.strip())<=100:raise ValueError('Enter a service name.')
    with store.connect() as c:
        old=c.execute('SELECT * FROM integrations WHERE id=?',(identifier,)).fetchone() if identifier else None
        if machine is None and kind=='truenas':
            if parent and not c.execute('SELECT 1 FROM machines WHERE id=?',(parent,)).fetchone():raise ValueError('Choose an existing parent host.')
            machine=uid();c.execute('INSERT INTO machines(id,name,parent_id,created) VALUES(?,?,?,?)',(machine,name.strip(),parent,time.time()))
            store.audit(c,'machine.created',machine,{'source':'truenas'})
        if not c.execute('SELECT 1 FROM machines WHERE id=?',(machine,)).fetchone():raise ValueError('Select an existing host.')
        if old and (old['kind']!=kind or old['machine_id']!=machine):raise ValueError('A saved connection cannot move to another host or service type.')
        if kind=='truenas' and c.execute('SELECT 1 FROM integrations WHERE machine_id=? AND kind=? AND id!=?',(machine,kind,identifier or '')).fetchone():raise ValueError('This host already has a TrueNAS connection.')
        if not secret and not old:raise ValueError('Enter an API key or Plex token.')
        identifier=identifier or uid()
        c.execute('INSERT INTO integrations(id,machine_id,kind,name,config,secret,snapshot,at,next_run) VALUES(?,?,?,?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET name=excluded.name,config=excluded.config,secret=excluded.secret,snapshot=excluded.snapshot,at=excluded.at,next_run=0,lease_until=NULL',
          (identifier,machine,kind,name.strip(),json.dumps(cfg),vault.encrypt(secret) if secret else old['secret'],json.dumps(snapshot or {}),time.time() if snapshot else None))
        if not old:
            check=uid();c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,severity) VALUES(?,?,?,?,?,?,'medium')",(check,machine,'TrueNAS health' if kind=='truenas' else name.strip(),kind,json.dumps({'connection_id':identifier,'scope':'host' if kind=='truenas' else 'service'}),cfg['interval']))
        else:c.execute("UPDATE checks SET next_run=0 WHERE json_extract(config,'$.connection_id')=?",(identifier,))
        if kind=='plex':
            from .service_dependencies import sync
            sync(c,store,identifier,machine,name.strip(),cfg)
        store.audit(c,'integration.saved',identifier,{'kind':kind,'machine_id':machine})
    return identifier


def read(kind,cfg,secret):
    if kind=='truenas':
        from .truenas import collect
    else:
        from .plex import collect
    return collect(cfg,secret)


def refresh(store,vault,row):
    cfg=json.loads(row['config']);reading_cfg={**cfg,'_previous':json.loads(row['snapshot'])} if row['kind']=='plex' else cfg
    snapshot=read(row['kind'],reading_cfg,vault.decrypt(row['secret']));now=time.time()
    with store.connect() as c:
        # Never apply an old credential/configuration result after editing/deletion.
        changed=c.execute('UPDATE integrations SET snapshot=?,at=?,next_run=?,lease_until=NULL WHERE id=? AND config=? AND secret=?',(json.dumps(snapshot),now,now+cfg['interval'],row['id'],row['config'],row['secret'])).rowcount
        if changed:
            from .changes import integration as record_changes
            record_changes(c,row,snapshot,now)
            from .metric_history import record
            if row['kind']=='truenas':
                from .capacity_forecasts import pools
                pools(c,'truenas',{**row,'config':cfg},snapshot,now)
                record(c,row['machine_id'],'truenas',now,snapshot.get('metrics',{}))
                for pool in snapshot.get('pools',[]):metric(c,row['id']+':pool:'+str(pool['id']),'storage',now,{'used_percent':pool.get('used_percent')})
                for app in snapshot.get('apps',[]):metric(c,row['id']+':app:'+app['name'],'application',now,app.get('metrics',{}))
            else:metric(c,row['id'],'plex',now,snapshot.get('metrics',{}))
    return snapshot


def metric(c,entity,source,at,values):
    import math
    values={k:v for k,v in values.items() if type(v) in (int,float) and math.isfinite(v)}
    if values:c.execute('INSERT OR IGNORE INTO metric_samples VALUES(?,?,?,?)',(entity,source,at,json.dumps(values)))


def tick(store,vault):
    now=time.time()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM integrations WHERE next_run<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_run LIMIT 1',(now,now)).fetchone()
        if not row:return False
        row=dict(row);c.execute('UPDATE integrations SET lease_until=?,next_run=? WHERE id=?',(now+90,now+60,row['id']))
    try:refresh(store,vault,row)
    except Exception as exc:
        with store.connect() as c:c.execute('UPDATE integrations SET snapshot=?,at=?,lease_until=NULL WHERE id=? AND config=? AND secret=?',(json.dumps({'error':connection_error(exc),'monitoring_issue':True}),now,row['id'],row['config'],row['secret']))
    return True


def views(store,machine=None):
    rows=store.rows('SELECT i.id,i.kind,i.name,i.machine_id,i.config,i.snapshot,i.at,m.name AS host FROM integrations i JOIN machines m ON m.id=i.machine_id'+(' WHERE i.machine_id=?' if machine else '')+' ORDER BY i.name',(machine,) if machine else ())
    for row in rows:
        row['config']=json.loads(row['config']);row['data']=json.loads(row.pop('snapshot'));row['fresh']=bool(row['at'] and 0<=time.time()-row['at']<=max(180,row['config']['interval']*3))
    return rows


def context(c,machine):
    return [{'kind':r['kind'],'name':r['name'],'sampled_at':r['at'],'fresh':bool(r['at'] and 0<=time.time()-r['at']<=max(180,json.loads(r['config'])['interval']*3)),'data':json.loads(r['snapshot'])} for r in c.execute('SELECT kind,name,at,config,snapshot FROM integrations WHERE machine_id=? LIMIT 10',(machine,))]


def probe(store,kind,cfg):
    rows=store.rows('SELECT snapshot,at,config FROM integrations WHERE id=? AND kind=?',(cfg['connection_id'],kind))
    if not rows:return None,{'reason':'Monitoring connection was removed.','monitoring_issue':True}
    row=rows[0];data=json.loads(row['snapshot']);interval=json.loads(row['config'])['interval']
    if not row['at'] or not 0<=time.time()-row['at']<=max(180,interval*3):return None,{'reason':'Waiting for a current API reading.','monitoring_issue':True}
    if data.get('error'):return None,{'reason':data['error'],'monitoring_issue':True}
    if kind=='plex':
        if cfg.get('scope')=='location':
            item=next((x for x in data.get('media_locations',[]) if x['id']==cfg.get('target')),None)
            if item is None:return None,{'reason':'The selected media location is not in the current reading. Review library settings.','monitoring_issue':True}
            return item['readable'],{'reason':item['reason'],'location':item['path'],'library':item['library'],'sampled_at':row['at'],'coverage':'One sampled file in this location.'}
        if cfg.get('scope')=='transcode':
            playback=data.get('playback',{})
            if not playback.get('error_reporting_available'):return None,{'reason':'No current transcode session exposes an error flag. This does not establish playback health.','monitoring_issue':True}
            return playback.get('transcode_errors',0)==0,{'reason':'Plex reports a transcode error.' if playback.get('transcode_errors') else 'Current transcode sessions report no errors.','details':playback,'sampled_at':row['at']}
        healthy=data.get('media_access') if cfg.get('scope')=='media' else data.get('responsive')
        return healthy,{'reason':data.get('media_reason','Plex can read the sample media file.') if healthy and cfg.get('scope')=='media' else 'Plex responds.' if healthy else data.get('media_reason','Plex is not responding.'),'sampled_at':row['at'],'metrics':data.get('metrics',{})}
    scope=cfg.get('scope','host')
    if scope=='host':
        severe=[a for a in data.get('alerts',[]) if a.get('level') in ('CRITICAL','ERROR','ALERT','EMERGENCY')]
        if severe:return False,{'reason':'TrueNAS reports a serious alert.','alerts':severe,'sampled_at':row['at']}
        pools=data.get('pools')
        if pools is None:return None,{'reason':'Pool health is unavailable; check read permissions.','monitoring_issue':True}
        if any(p.get('healthy') is None for p in pools) and not any(p.get('healthy') is False for p in pools):return None,{'reason':'Pool health is unavailable; check read permissions.','monitoring_issue':True}
        return all(p.get('healthy') is True for p in pools),{'reason':'Storage pools are healthy.' if all(p.get('healthy') is True for p in pools) else 'A storage pool needs attention.','pools':pools,'sampled_at':row['at']}
    key='pools' if scope=='pool' else 'apps'
    if key not in data:return None,{'reason':'This API reading is unavailable.','monitoring_issue':True}
    item=next((a for a in data[key] if str(a['id'] if scope=='pool' else a['name'])==cfg['target']),None)
    if item is None:return False,{'reason':'The monitored '+scope+' is no longer present.'}
    if scope=='pool':healthy=item.get('healthy')
    else:
        state=item.get('state','UNKNOWN');healthy=True if state=='RUNNING' else None if state in ('DEPLOYING','INITIALIZING','UNKNOWN') else False
        if healthy and any(str(x.get('state','')).lower() in ('exited','dead','restarting') for x in item.get('containers',[])):healthy=False
    return healthy,{'reason':scope.capitalize()+' is healthy.' if healthy else scope.capitalize()+' needs attention.' if healthy is False else 'Waiting for application startup.','sampled_at':row['at'],'details':item}


def add_check(store,connection,scope,target=None):
    row=next((r for r in views(store) if r['id']==connection),None)
    if not row:raise ValueError('Unknown monitoring connection.')
    if not row['fresh'] or row['data'].get('error'):raise ValueError('Wait for a current API reading before adding a check.')
    if row['kind']=='plex':
        if scope=='location':
            item=next((x for x in row['data'].get('media_locations',[]) if x['id']==target),None)
            if not item:raise ValueError('Choose a discovered media location.')
            title=row['name']+' · '+item['library']+' · '+item['path']
        elif scope=='transcode':title=row['name']+' transcode errors'
        elif scope=='media' and (row['config'].get('library_id') or row['config'].get('library_ids')):title=row['name']+' media access'
        else:raise ValueError('Choose a Plex library in service settings first.')
    else:
        if scope not in ('pool','app'):raise ValueError('Select an application or storage pool.')
        item=next((x for x in row['data'].get('pools' if scope=='pool' else 'apps',[]) if str(x['id'] if scope=='pool' else x['name'])==target),None)
        if not item:raise ValueError('Refresh discovery and select an existing item.')
        title=item['name']+' '+('storage' if scope=='pool' else 'application')
    cfg={'connection_id':connection,'scope':scope}
    if target:cfg['target']=target
    with store.connect() as c:
        old=c.execute('SELECT id FROM checks WHERE machine_id=? AND kind=? AND config=?',(row['machine_id'],row['kind'],json.dumps(cfg))).fetchone()
        if old:return old['id']
        identifier=uid();c.execute("INSERT INTO checks(id,machine_id,name,kind,config,interval,severity) VALUES(?,?,?,?,?,?,'medium')",(identifier,row['machine_id'],title,row['kind'],json.dumps(cfg),row['config']['interval']))
        if row['kind']=='plex':
            from .service_dependencies import sync
            sync(c,store,connection,row['machine_id'],row['name'],row['config'])
        store.audit(c,'check.created',identifier,{'kind':row['kind']})
    return identifier


def connection_error(exc):
    import ssl,requests
    if isinstance(exc,(ssl.SSLError,requests.exceptions.SSLError)):return 'The server certificate could not be verified. Check the trusted certificate file and server name.'
    if isinstance(exc,ValueError):return str(exc) if isinstance(exc,(__import__('aiticket.plex',fromlist=['PlexError']).PlexError,__import__('aiticket.truenas',fromlist=['RPCError']).RPCError)) else 'Check the API key owner, permissions and server response.'
    return 'The monitoring connection could not complete. Check the address, certificate and server availability.'


def remove(store,identifier):
    with store.connect() as c:
        c.execute("UPDATE checks SET enabled=0 WHERE json_extract(config,'$.connection_id')=?",(identifier,))
        group='service:'+identifier
        c.execute('DELETE FROM application_dependencies WHERE application_id=?',(group,))
        c.execute('DELETE FROM application_checks WHERE application_id=?',(group,))
        c.execute('DELETE FROM applications WHERE id=?',(group,))
        # Keep service knowledge after removing its live monitoring connection.
        c.execute('UPDATE kb_folders SET service_id=NULL WHERE service_id=?',(identifier,))
        c.execute('DELETE FROM integrations WHERE id=?',(identifier,));store.audit(c,'integration.deleted',identifier)
