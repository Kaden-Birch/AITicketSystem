"""Read-only capacity trends. Forecasts never alter checks or authorize remediation."""
import hashlib
import json
import math
import statistics
import time

DAY=86400


def valid(value):
    return type(value) in (int,float) and math.isfinite(value)


def pool_entity(kind,connection,pool):
    identity=pool.get('id',pool.get('number'))
    if identity is None:return None
    url=connection.get('url') or connection.get('config',{}).get('url','')
    return kind+':'+connection['id']+':'+hashlib.sha256(url.encode()).hexdigest()[:12]+':'+str(identity)


def record(c,entity,machine,kind,label,at,used,total,headroom=None):
    if not entity or not all(valid(v) for v in (at,used,total)) or used<0 or total<=0:return False
    if headroom is not None and (not valid(headroom) or not 0<=headroom<=total):return False
    if not time.time()-90*DAY<=at<=time.time()+60:return False
    c.execute('''INSERT INTO capacity_samples VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(entity,bucket) DO UPDATE SET
        at=excluded.at,used=excluded.used,total=excluded.total,headroom=excluded.headroom,label=excluded.label,machine_id=excluded.machine_id
        WHERE excluded.at>capacity_samples.at''',(entity,int(at//3600),machine,kind,str(label)[:160],at,used,total,headroom))
    c.execute('DELETE FROM capacity_samples WHERE at<?',(time.time()-90*DAY,))
    return True


def pools(c,kind,connection,snapshot,at):
    if not isinstance(snapshot,dict):return
    if kind=='truenas':values=snapshot.get('pools',[])
    else:
        readings=snapshot.get('readings',{})
        storage=readings.get('storage',{}) if isinstance(readings,dict) else None
        values=storage.get('pools',[]) if isinstance(storage,dict) else None
    if not isinstance(values,list):return
    for pool in values[:256]:
        if not isinstance(pool,dict):continue
        if kind=='truenas':
            used=pool.get('used_bytes');free=pool.get('available_bytes')
            total=used+free if valid(used) and valid(free) else None
        else:used=pool.get('usage');total=pool.get('capacity')
        if not valid(used) or not valid(total) or not 0<=used<=total:continue
        record(c,pool_entity(kind,connection,pool),connection['machine_id'],kind,str(pool.get('name') or 'Pool '+str(pool.get('number','?'))),at,used,total)


def estimate(samples,now=None,max_age=900,fresh=True):
    now=time.time() if now is None else now
    result={'state':'insufficient','title':'Learning the capacity trend','reason':'Needs at least seven days of consistent readings spanning six days.','points':[]}
    rows=sorted([r for r in samples if all(valid(r.get(k)) for k in ('at','used','total')) and r['total']>0 and r['used']>=0 and now-30*DAY<=r['at']<=now],key=lambda r:r['at'])
    if not rows:return result
    latest=rows[-1];result.update(observed_at=latest['at'],used=latest['used'],total=latest['total'])
    if not fresh or now-latest['at']>max_age:return result|{'state':'stale','title':'Forecast unavailable','reason':'Current capacity reading is stale or unavailable.'}
    # A resized volume, changed budget, or a major cleanup starts a new trend.
    reset=False
    for i in range(len(rows)-1,0,-1):
        if abs(rows[i]['total']-rows[i-1]['total'])>max(1,rows[i]['total']*.01) or rows[i-1]['used']-rows[i]['used']>rows[i]['total']*.05:
            rows=rows[i:];reset=True;break
    daily={}
    for r in rows:daily.setdefault(int(r['at']//DAY),[]).append(r)
    points=[{'at':statistics.median(r['at'] for r in group),'used':statistics.median(r['used'] for r in group),'total':statistics.median(r['total'] for r in group)} for group in daily.values()]
    result.update(points=points,days=len(points),span_days=(rows[-1]['at']-rows[0]['at'])/DAY)
    if len(points)<7 or result['span_days']<6:
        if reset:result['reason']='Capacity changed or a major cleanup occurred. Learning a new trend with at least seven days of readings.'
        return result
    if any(b['at']-a['at']>2*DAY for a,b in zip(points,points[1:])):return result|{'state':'inconsistent','title':'Forecast unavailable','reason':'History has gaps longer than two days. More consistent readings are needed.'}
    xs=[(p['at']-points[0]['at'])/DAY for p in points];ys=[p['used'] for p in points]
    slopes=sorted((ys[j]-ys[i])/(xs[j]-xs[i]) for i in range(len(xs)) for j in range(i+1,len(xs)) if xs[j]>xs[i])
    rate=statistics.median(slopes);low=slopes[int((len(slopes)-1)*.1)];high=slopes[int((len(slopes)-1)*.9)]
    result.update(rate=rate,rate_low=low,rate_high=high)
    floor=max(1,latest['total']*1e-9) # Ignore negligible byte-level rounding noise.
    if abs(rate)<=floor:return result|{'state':'stable','title':'No sustained growth','reason':'Usage is approximately stable. No time-to-capacity estimate is shown.'}
    if rate<0:return result|{'state':'shrinking','title':'Usage is decreasing','reason':'The recent trend is shrinking. No time-to-capacity estimate is shown.'}
    intercept=statistics.median(y-rate*x for x,y in zip(xs,ys))
    residual=sum((y-(intercept+rate*x))**2 for x,y in zip(xs,ys));variance=sum((y-statistics.mean(ys))**2 for y in ys)
    fit=1-residual/variance if variance else 0
    if low<=floor or fit<.7:return result|{'state':'inconsistent','title':'Growth is too variable','reason':'The readings do not support a consistent increasing trend. No reliable capacity date is shown.'}
    remaining=latest.get('headroom')
    if remaining is None:remaining=max(0,latest['total']-latest['used'])
    if not valid(remaining) or remaining<0:return result|{'state':'unavailable','title':'Forecast unavailable','reason':'Remaining space is unavailable.'}
    days=remaining/rate
    result.update(state='growing',title='Capacity approaching' if days<=30 else 'Capacity forecast',eta_days=days,earliest_days=remaining/high,latest_days=remaining/low,capacity_at=now+days*DAY,reason='Estimate assumes the recent growth pattern continues. The range reflects observed growth variation, not a guarantee.')
    return result


def forecast(store,entity,now=None,max_age=900,fresh=True,expected_total=None):
    now=time.time() if now is None else now
    rows=store.rows('SELECT at,used,total,headroom FROM capacity_samples WHERE entity=? AND at>=? AND at<=? ORDER BY at',(entity,now-30*DAY,now)) if entity else []
    if rows and expected_total is not None and rows[-1]['total']!=expected_total:rows=[]
    result=estimate(rows,now,max_age,fresh)
    from .archive_storage import human
    if 'rate' in result:result['rate_text']=('−' if result['rate']<0 else '+')+human(abs(result['rate']))+'/day'
    if result['state']=='growing':
        result['eta_text']=duration(result['eta_days'])
        early=duration(result['earliest_days']);late=duration(result['latest_days'])
        result['range_text']=early if early==late else early.removesuffix(' days')+'–'+late
    points=result['points']
    percentages=[p['used']/p['total']*100 for p in points]
    bottom=min(percentages,default=0);top=max(percentages,default=0)
    result['trend_scale']=f'{bottom:.1f}%–{top:.1f}%'
    result['points']=[{**p,'size':human(p['used']),'percent':round(p['used']/p['total']*100,2),'x':i/max(1,len(points)-1)*240,'y':40-(p['used']/p['total']*100-bottom)/max(top-bottom,1e-9)*36} for i,p in enumerate(points)]
    result['sparkline']=' '.join(f'{p["x"]:.1f},{p["y"]:.1f}' for p in result['points'])
    return result


def duration(days):
    if days<1:return 'less than 1 day'
    if days>365:return 'over 1 year'
    return str(max(1,round(days)))+' days'


def backfill(store):
    """Only archived snapshots with actual capacity values can seed older trends."""
    cursor=store.setting('capacity_backfill',0);now=time.time()
    rows=store.rows("SELECT rowid sequence,entity_id,kind,at,payload FROM telemetry_records WHERE rowid>? AND kind IN ('integration','unifi') AND at>=? ORDER BY rowid LIMIT 100",(cursor,now-30*DAY))
    with store.connect() as c:
        for row in rows:
            try:
                payload=json.loads(row['payload']);snapshot=payload.get('readings',{})
                if isinstance(snapshot,str):snapshot=json.loads(snapshot)
            except (ValueError,TypeError,AttributeError):continue
            action='integration.saved' if row['kind']=='integration' else 'unifi.connection_saved'
            saved=c.execute('SELECT max(at) FROM audit WHERE action=? AND target=?',(action,row['entity_id'])).fetchone()[0]
            if saved is not None and row['at']<saved:continue
            if not isinstance(snapshot,dict):continue
            if row['kind']=='integration':
                conn=c.execute("SELECT id,machine_id,config FROM integrations WHERE id=? AND kind='truenas'",(row['entity_id'],)).fetchone()
                if conn:connection=dict(conn);connection['config']=json.loads(connection['config']);pools(c,'truenas',connection,snapshot,row['at'])
            else:
                conn=c.execute("SELECT id,machine_id,url FROM unifi_connections WHERE id=? AND kind='drive' AND deleted IS NULL",(row['entity_id'],)).fetchone()
                if conn:pools(c,'unifi',dict(conn),snapshot,row['at'])
    if rows:store.save('capacity_backfill',rows[-1]['sequence'])


def sample_local(store):
    from .archive_storage import local
    from .network_logs import DEFAULTS
    data=local(store);budget={**DEFAULTS,**store.setting('network_log_retention',{})}['megabytes']*1_000_000
    with store.connect() as c:
        record(c,'logs:local',None,'local_logs','Local evidence budget',time.time(),data['record_bytes'],budget)
