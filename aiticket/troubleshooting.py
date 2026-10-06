"""Read-only chronology of independently observed evidence; never infers causation."""
import json
import math
import time
from urllib.parse import quote
from . import network_logs as logs

KINDS = {'all':'All evidence', 'network':'Network events', 'checks':'Monitoring results',
         'resources':'Resource changes', 'changes':'Observed changes', 'tickets':'Ticket activity'}


def clean(value, depth=0):
    if depth > 5: return 'Further details omitted'
    if isinstance(value, str): return logs.safe(value, 1000)
    if isinstance(value, dict):
        import re
        return {logs.safe(k,100):clean(v,depth+1) for k,v in list(value.items())[:30]
                if not re.search(r'(?i)(password|secret|token|credential|authorization|cookie|private.?key)',str(k))}
    if isinstance(value, list): return [clean(v,depth+1) for v in value[:30]]
    if type(value) in (int,float): return value if math.isfinite(value) else None
    return value if value is None or type(value) is bool else logs.safe(value,200)


def scope(c, machine=None, incident=None):
    """Explicitly associated targets and confirmed/corroborated network dependencies only."""
    targets = [machine] if machine else []
    if incident:
        from .ticket_groups import machines
        row=c.execute('SELECT machine_id FROM incidents WHERE id=?',(incident,)).fetchone()
        if not row: raise ValueError('Unknown ticket.')
        targets=[row[0]]+sorted(machines(c,incident)-{row[0]})
    targets=list(dict.fromkeys(t for t in targets if t))[:16]
    from .topology import context
    for target in list(targets):
        facts=context(c,target)
        parent=c.execute('SELECT parent_id FROM machines WHERE id=?',(target,)).fetchone()
        if parent and parent[0] and parent[0] not in targets and len(targets)<16: targets.append(parent[0])
        for link in facts.get('links',[])+facts.get('physical_host',{}).get('links',[]):
            if link['confidence'] not in ('confirmed','corroborated'): continue
            row=c.execute('SELECT machine_id FROM unifi_devices WHERE connection_id=? AND device_id=? AND deleted IS NULL',
                          (link['connection_id'],link['device_id'])).fetchone()
            if row and row[0] not in targets and len(targets)<16: targets.append(row[0])
    return targets


def build(c, machines, start, end, kind='all', limit=80):
    targets=list(dict.fromkeys(machines))[:16]
    if kind not in KINDS or not 0 <= start < end or end-start > 31*86400+60:
        raise ValueError('Choose a supported evidence type and a time range of up to 31 days.')
    names={r['id']:r['name'] for r in c.execute('SELECT id,name FROM machines WHERE id IN ('+','.join('?' for _ in targets)+')',targets)} if targets else {}
    targets=list(names); entries=[]; partial=[]; network_available=True
    def add(identifier,category,at,machine,title,summary='',details=None,url=None,state='unknown'):
        entries.append({'id':identifier,'kind':category,'at':at,'machine_id':machine,'host':names.get(machine,'Host'),
                        'title':logs.safe(title,200),'summary':logs.safe(summary,500),'details':clean(details or {}),
                        'url':url or '/hosts/'+quote(machine,safe=''),'state':state})
    for machine in targets:
        if kind in ('all','network'):
            result=logs.query(c,machine=machine,start=start,end=end,limit=50)
            network_available=network_available and result['available']
            if result['next_offset'] is not None or result.get('truncated'): partial.append('Network events')
            for event in result['items']:
                add('network:'+str(event.get('event_key') or event['id']),'network',event['at'],machine,event['name'],event['message'],
                    {'event_id':event['id'],'reported_time':event['timestamp_kind'],'received_at':event['received'],
                     'source_id':event['source_id'],'device':event['device_name'],'port':event['port'],
                     'client_ip':event['client_ip'],'client_mac':event['client_mac'],'maintenance':event['maintenance']},
                    '/network-events/'+str(event['id']))
        if kind in ('all','checks'):
            prior={r['id']:r['previous'] for r in c.execute('SELECT ch.id,(SELECT health FROM observations WHERE check_id=ch.id AND at<? ORDER BY at DESC,id DESC LIMIT 1) previous FROM checks ch WHERE machine_id=?',(start,machine))}
            rows=c.execute('SELECT o.*,ch.name FROM observations o JOIN checks ch ON ch.id=o.check_id WHERE ch.machine_id=? AND o.at>=? AND o.at<=? ORDER BY o.at DESC,o.id DESC LIMIT 1001',(machine,start,end)).fetchall()
            if len(rows)>1000: partial.append('Monitoring results'); prior={}
            for row in reversed(rows[:1000]):
                previous=prior.get(row['check_id'])
                if row['health']==previous: continue
                label={'healthy':'Healthy reading' if previous is None else 'Monitoring recovered' if previous=='down' else 'Monitoring became healthy',
                       'down':'Monitoring failed','unknown':'Monitoring result unknown'}.get(row['health'],'Monitoring changed')
                evidence=json.loads(row['evidence'])
                add('check:'+row['id'],'checks',row['at'],machine,row['name']+' · '+label,
                    evidence.get('reason',''),{'observation_id':row['id'],'check_id':row['check_id'],'previous_result':previous,
                    'result':row['health'],'evidence':evidence},'/hosts/'+quote(machine,safe='')+'#check-'+quote(row['check_id'],safe=''),row['health'])
                prior[row['check_id']]=row['health']
        if kind in ('all','changes'):
            rows=c.execute('SELECT * FROM change_events WHERE machine_id=? AND at>=? AND at<=? ORDER BY at DESC,id LIMIT 101',(machine,start,end)).fetchall()
            if len(rows)>100: partial.append('Observed changes')
            for row in rows[:100]:
                add('change:'+row['id'],'changes',row['at'],machine,row['summary'],'Observed change; cause is unconfirmed.',json.loads(row['details'])|{'change_id':row['id']})
        if kind in ('all','resources'):
            entities=[machine]+[r[0] for r in c.execute('SELECT id FROM proxmox_objects WHERE machine_id=?',(machine,))]+[r[0] for r in c.execute('SELECT id FROM integrations WHERE machine_id=?',(machine,))]
            placeholders=','.join('?' for _ in entities)
            rows=c.execute('SELECT * FROM metric_samples WHERE entity_id IN ('+placeholders+') AND at>=? AND at<=? ORDER BY at DESC,entity_id,source LIMIT 1001',(*entities,start,end)).fetchall()
            if len(rows)>1000: partial.append('Resource samples')
            anchors={}; times={}
            for row in reversed(rows[:1000]):
                metrics=json.loads(row['metrics'])
                # Source streams stay separate. These display deltas do not change alert thresholds.
                readings=[]
                for label,keys in [('CPU',('cpu_percent','statistics.cpuUtilizationPct','device.cpuUtilizationPct','CPU usage')),
                                   ('RAM',('ram_percent','statistics.memoryUtilizationPct','device.memoryUtilizationPct','Memory usage')),
                                   ('Storage',('disk_percent',))]:
                    for key in keys:
                        value=metrics.get(key)
                        if type(value) in (int,float) and math.isfinite(value) and 0<=value<=100:
                            readings.append((key,label,value)); break
                for key,value in metrics.items():
                    if key.startswith('Pool ') and key.endswith(' usage') and type(value) in (int,float) and math.isfinite(value) and 0<=value<=100:
                        readings.append((key,key,value))
                for key,label,value in readings:
                    stream=(row['entity_id'],row['source'],key); before=anchors.get(stream)
                    if before is None or abs(value-before)>=10 or row['at']-times[stream]>180:
                        gap=before is not None and row['at']-times[stream]>180
                        title=label+(' reading' if before is None or gap else ' changed')
                        summary=f'{value:g}%' if before is None or gap else f'{before:g}% → {value:g}%'
                        add('resource:'+':'.join(stream)+':'+str(row['at']),'resources',row['at'],machine,title,summary,
                            {'source':row['source'],'entity_id':row['entity_id'],'metric':key,'previous_displayed_value':None if gap else before,'value':value,'gap_before':gap})
                        anchors[stream]=value
                    times[stream]=row['at']
        if kind in ('all','tickets'):
            rows=c.execute('SELECT id,first_seen,closed,report FROM incidents WHERE machine_id=? AND first_seen<=? AND (closed IS NULL OR closed>=?) ORDER BY first_seen DESC LIMIT 101',(machine,end,start)).fetchall()
            if len(rows)>100: partial.append('Ticket activity')
            for row in rows[:100]:
                title=json.loads(row['report']).get('check','Ticket'); url='/incidents/'+quote(row['id'],safe='')
                if start<=row['first_seen']<=end: add('opened:'+row['id'],'tickets',row['first_seen'],machine,'Ticket opened · '+title,url=url)
                if row['closed'] is not None and start<=row['closed']<=end: add('closed:'+row['id'],'tickets',row['closed'],machine,'Ticket resolved · '+title,url=url)
                activity=c.execute('SELECT * FROM timeline WHERE incident_id=? AND at>=? AND at<=? ORDER BY at DESC,id LIMIT 101',(row['id'],start,end)).fetchall()
                if len(activity)>100: partial.append('Ticket updates')
                for item in activity[:100]:
                    add('ticket:'+item['id'],'tickets',item['at'],machine,item['kind'].replace('_',' ').capitalize(),item['text'],
                        {'ticket_id':row['id'],'actor':item['actor'],'timeline_id':item['id']},url)
    unique={}
    for item in entries:
        if item['id'] in unique:
            unique[item['id']]['related_hosts'].append({'id':item['machine_id'],'name':item['host']})
        else: unique[item['id']]=item|{'related_hosts':[{'id':item['machine_id'],'name':item['host']}]}
    ordered=sorted(unique.values(),key=lambda item:(item['at'],item['id']),reverse=True)
    counts={category:sum(item['kind']==category for item in ordered) for category in KINDS if category!='all'}
    return {'items':ordered[:limit],'counts':counts,'truncated':len(ordered)>limit,'partial':sorted(set(partial)),
            'network_available':network_available,'hosts':[{'id':k,'name':v} for k,v in names.items()],
            'start':start,'end':end,'kind':kind,'limit':limit}
