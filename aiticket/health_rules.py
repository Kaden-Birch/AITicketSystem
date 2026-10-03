"""Fleet health defaults, explicit host overrides and stable monitoring checks."""
import json, math, re
from .db import uid

METRICS = {
    'cpu_percent': ('CPU usage', 'above', 90, 80, False, ''),
    'memory_used_percent': ('Available memory', 'below', 10, 20, True, 'Memory available to applications, including reclaimable cache.'),
    'memory_pressure_percent': ('Memory pressure', 'above', 10, 5, False, 'Time applications spend waiting for memory. Sustained pressure can slow services.'),
    'disk_used_percent': ('Free storage', 'below', 15, 20, True, 'Free space on the host’s root filesystem.'),
    'inode_used_percent': ('Available file entries', 'below', 10, 15, False, 'Space for new files and folders. A disk can run out of file entries even when storage remains free.'),
}


def defaults(metric):
    _,direction,threshold,recovery,_,_=METRICS[metric]
    return dict(metric=metric,direction=direction,unit='percent',threshold=threshold,recovery=recovery,sustain_seconds=120,severity='medium')


def normalize(metric,cfg):
    result=defaults(metric)
    if 'threshold' in cfg:
        result.update({k:cfg[k] for k in result if k in cfg})
    elif 'fail_above' in cfg:
        free=result['direction']=='below'
        result.update(threshold=100-cfg['fail_above'] if free else cfg['fail_above'],recovery=100-cfg['recover_below'] if free else cfg['recover_below'],sustain_seconds=cfg.get('sustain_seconds',120))
    return result


def amount(value,unit):
    text=str(value).strip()
    if unit=='bytes':
        match=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*(GB|MB|TB)?',text,re.I)
        if not match:raise ValueError('Enter free space in GB, MB or TB, for example 50 GB or 0.5 TB.')
        number=float(match[1])*{'GB':1e9,'MB':1e6,'TB':1e12}[str(match[2] or 'GB').upper()]
    else:
        try:number=float(text.rstrip('%').strip())
        except ValueError:raise ValueError('Enter a percentage between 0 and 100.')
    if not math.isfinite(number) or number<0 or number>(1e18 if unit=='bytes' else 100):raise ValueError('Enter a valid threshold within the displayed range.')
    return number


def validate(metric,cfg):
    if metric not in METRICS:raise ValueError('Choose a supported health metric.')
    if cfg.get('unit') not in ('percent','bytes') or cfg.get('direction')!=METRICS[metric][1] or (cfg['unit']=='bytes' and not METRICS[metric][4]):raise ValueError('Invalid metric units.')
    values=[cfg.get('threshold'),cfg.get('recovery')]
    if any(type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=(1e18 if cfg['unit']=='bytes' else 100) for v in values):raise ValueError('Invalid resource thresholds.')
    if not (values[0]<values[1] if cfg['direction']=='below' else values[1]<values[0]):raise ValueError('Recovery must be above the alert threshold for free space, or below it for usage/pressure.')
    if type(cfg.get('sustain_seconds')) is not int or not 30<=cfg['sustain_seconds']<=86400:raise ValueError('Sustained duration must be 30–86400 seconds.')
    if cfg.get('severity','medium') not in ('low','medium','high','critical'):raise ValueError('Choose a valid ticket priority.')


def save(store,scope,values):
    metric=values.get('metric');action=values.get('action','save')
    if metric not in METRICS:raise ValueError('Choose a supported health metric.')
    if scope!='*' and not store.rows("SELECT id FROM machines WHERE id=? AND id NOT LIKE 'unifi:%' AND id NOT LIKE 'unifi-device:%'",(scope,)):raise ValueError('Choose a monitored host.')
    if action not in ('save','reset','disable','pause','resume'):raise ValueError('Unknown health action.')
    if scope=='*' and action in ('reset','disable'):raise ValueError('Use the default monitoring switch.')
    if scope!='*' and action in ('pause','resume'):raise ValueError('Fleet pause is a global setting.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        old=c.execute('SELECT * FROM health_rules WHERE scope=? AND metric=?',(scope,metric)).fetchone()
        if action=='reset':c.execute('DELETE FROM health_rules WHERE scope=? AND metric=?',(scope,metric))
        else:
            cfg=normalize(metric,json.loads(old['config'])) if old else defaults(metric)
            enabled=old['enabled'] if old else 0;paused=old['paused'] if old else 0
            if action=='save':
                unit=values.get('unit','percent')
                if unit not in ('percent','bytes'):raise ValueError('Choose Percentage or Free space.')
                cfg.update(unit=unit,threshold=amount(values.get('threshold',''),unit),recovery=amount(values.get('recovery',''),unit),sustain_seconds=int(values.get('sustain_seconds',120)),severity=values.get('severity','medium'))
                validate(metric,cfg);enabled=int(values.get('enabled')=='yes')
            elif action=='disable':enabled=0
            else:paused=int(action=='pause')
            c.execute('INSERT OR REPLACE INTO health_rules VALUES(?,?,?,?,?)',(scope,metric,json.dumps(cfg),enabled,paused))
        store.audit(c,'health_rule.'+action,scope,{'metric':metric})
    sync(store)


def cards(store,scope='*'):
    rules={(r['scope'],r['metric']):r for r in store.rows('SELECT * FROM health_rules')};result=[]
    for metric,(label,direction,_,_,size,description) in METRICS.items():
        global_rule=rules.get(('*',metric));local=rules.get((scope,metric)) if scope!='*' else global_rule
        chosen=local or global_rule;cfg=normalize(metric,json.loads(chosen['config'])) if chosen else defaults(metric)
        enabled=bool(chosen and chosen['enabled']);paused=bool(global_rule and global_rule['paused'])
        factor=1e9 if cfg['unit']=='bytes' else 1
        result.append(dict(cfg,metric=metric,label=label,description=description,size=size,enabled=enabled,paused=paused,inherited=scope!='*' and local is None,override=scope!='*' and local is not None,scope=scope,display_threshold=round(cfg['threshold']/factor,9),display_recovery=round(cfg['recovery']/factor,9)))
    return result


def sync(store):
    """Reuse check IDs so edits and inheritance retain ticket/source history."""
    interval=store.setting('agent_interval',30)
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        rules={(r['scope'],r['metric']):r for r in c.execute('SELECT * FROM health_rules')}
        by_metric={}
        for row in c.execute("SELECT * FROM checks WHERE kind='agent_metric' ORDER BY id"):
            by_metric.setdefault((row['machine_id'],json.loads(row['config']).get('metric')),[]).append(row)
        for agent in c.execute('SELECT * FROM agents').fetchall():
            for metric in METRICS:
                global_rule=rules.get(('*',metric));rule=rules.get((agent['machine_id'],metric)) or global_rule
                existing=by_metric.get((agent['machine_id'],metric),[])
                # Older/manual imported definitions become host overrides once.
                if (agent['machine_id'],metric) not in rules and existing and not json.loads(existing[0]['config']).get('health_rule'):
                    row=existing[0];cfg=normalize(metric,json.loads(row['config']))
                    c.execute('INSERT OR IGNORE INTO health_rules VALUES(?,?,?,?,0)',(agent['machine_id'],metric,json.dumps(cfg),row['enabled']))
                    rule={'config':json.dumps(cfg),'enabled':row['enabled']}
                cfg=normalize(metric,json.loads(rule['config'])) if rule else defaults(metric)
                cfg.update(agent_id=agent['id'],health_rule=True)
                enabled=int(bool(rule and rule['enabled'] and not agent['revoked'] and not (global_rule and global_rule['paused'])))
                if not existing and not enabled:continue
                check=existing[0] if existing else None;encoded=json.dumps(cfg,sort_keys=True)
                if not check:
                    c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity,enabled) VALUES(?,?,?,?,?,?,1,2,?,?)',(uid(),agent['machine_id'],METRICS[metric][0],'agent_metric',encoded,interval,cfg['severity'],enabled))
                elif json.loads(check['config'])!=cfg or check['enabled']!=enabled or check['interval']!=interval or check['severity']!=cfg['severity']:
                    c.execute("UPDATE checks SET config=?,name=?,enabled=?,interval=?,severity=?,health='unknown',failures=0,successes=0,first_failure_at=NULL,next_run=0,lease_token=NULL,lease_until=NULL WHERE id=?",(encoded,METRICS[metric][0],enabled,interval,cfg['severity'],check['id']))
                for duplicate in existing[1:]:
                    if duplicate['enabled'] or duplicate['lease_token']:
                        c.execute('UPDATE checks SET enabled=0,lease_token=NULL,lease_until=NULL WHERE id=?',(duplicate['id'],))
                        store.audit(c,'health_rule.duplicate_retired',duplicate['id'],{'metric':metric},actor='monitor')


def incident_paused(c,incident_id):
    sources=c.execute('SELECT c.kind,c.enabled,c.config FROM incident_sources s JOIN checks c ON c.id=s.check_id WHERE s.incident_id=?',(incident_id,)).fetchall()
    if not sources:
        sources=c.execute('SELECT c.kind,c.enabled,c.config FROM incidents i JOIN checks c ON c.id=i.check_id WHERE i.id=?',(incident_id,)).fetchall()
    return bool(sources) and all(r['kind']=='agent_metric' and not r['enabled'] and json.loads(r['config']).get('health_rule') for r in sources)
