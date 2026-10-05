"""Shared read-only answers for normal Hermes, Telegram and the web UI."""
import json,time
from .diagnostics import redact


def answer(store,query='',machine=None,incident=None):
    if not isinstance(query,str) or len(query)>300:raise ValueError('Use a short status question.')
    with store.connect() as c:
        if incident:
            row=c.execute('SELECT machine_id FROM incidents WHERE id=?',(incident,)).fetchone()
            if not row:raise ValueError('Ticket not found.')
            machine=row[0]
        if not machine and query.strip():
            rows=c.execute('SELECT id,name FROM machines WHERE instr(lower(name),lower(?))>0 ORDER BY name LIMIT 11',(query.strip(),)).fetchall()
            if len(rows)==1:machine=rows[0]['id']
            elif len(rows)>1:return {'state':'choose_host','hosts':[dict(x) for x in rows[:10]],'note':'Choose an exact host.'}
            elif query.strip().lower() not in ('status','report','summary','all'):return {'state':'not_found','note':'No matching host. Use its name or ask for status.'}
        from .hostview import overview
        hosts=overview(store)
        if machine:
            hosts=[h for h in hosts if h['id']==machine]
            if not hosts:raise ValueError('Host not found.')
        tickets=[]
        for h in hosts[:50]:
            tickets.extend(dict(r)|{'title':json.loads(r['report']).get('check','Ticket'),'host':h['name']} for r in c.execute("SELECT id,status,severity,first_seen,report FROM incidents WHERE machine_id=? AND closed IS NULL AND status!='Resolved' ORDER BY first_seen LIMIT 10",(h['id'],)))
        result={'at':time.time(),'hosts':[{'id':h['id'],'name':h['name'],'health':h.get('health'),'open_tickets':h['active_incidents'],'telemetry_fresh':h['sample']['fresh'],'sampled_at':h['sample']['at']} for h in hosts[:50]],'tickets':[{k:v for k,v in t.items() if k!='report'} for t in tickets[:50]],'truncated':len(hosts)>50 or len(tickets)>50,'note':'Read-only monitoring evidence; stale telemetry is not proof of health.'}
        if machine:
            from .machine_context import context
            from .knowledge import context as knowledge
            result['host_evidence']=context(c,machine);result['knowledge']=knowledge(c,{machine})
        if incident:
            from .ticket_groups import context as group
            result['related']=group(c,incident)
        from .ai import evidence_snapshot
        return evidence_snapshot(result)


def text(result):
    if result.get('state'):return result.get('note','Choose a host.')
    lines=[h['name']+': '+str(h['health'] or 'Awaiting results')+' · '+str(h['open_tickets'])+' open tickets'+(' · readings need attention' if not h['telemetry_fresh'] else '') for h in result.get('hosts',[])[:15]]
    lines.extend(t['host']+' · '+t['title']+' · '+t['status']+' · Ticket '+t['id'] for t in result.get('tickets',[])[:8])
    return redact('\n'.join(lines) or 'No monitored hosts yet.')[:3500]
