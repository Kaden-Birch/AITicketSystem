"""Bounded event markers for the host's selected metric window."""
from .troubleshooting import build as chronology,scope


def build(store,machine,history):
    start,end=history['start'],history['end']
    items={};partial=set();network_available=True
    with store.connect() as c:
        dependencies=scope(c,machine=machine);related=dependencies[:4]
        configured=c.execute('SELECT 1 FROM log_sources WHERE enabled=1 LIMIT 1').fetchone()
        for kind in ('changes','checks','network','tickets','actions'):
            if kind=='network' and not configured:continue
            if kind=='network' and len(dependencies)>4:partial.add('Network dependency scope')
            result=chronology(c,related if kind=='network' else [machine],start,end,kind,limit=101)
            partial.update(result['partial'])
            if result['truncated']:partial.add(kind)
            network_available=network_available and result['network_available']
            for item in result['items']:items.setdefault(item['id'],item)
    # Quiet healthy samples are not an event. Retain actual failure/recovery transitions.
    ordered=sorted((item for item in items.values() if not (item['kind']=='checks' and item['state']=='healthy' and item['details'].get('previous_result') is None)),key=lambda row:(row['at'],row['id']),reverse=True)
    truncated=len(ordered)>200 or bool(partial)
    ordered=ordered[:200];groups={}
    for item in ordered:
        bucket=min(119,max(0,int((item['at']-start)/(end-start)*120)))
        group=groups.setdefault(bucket,{'bucket':bucket,'x':round(38+(bucket+.5)/120*554,2),'items':[]})
        group['items'].append(item)
    for group in groups.values():
        group['label']=f"{len(group['items'])} event(s): "+', '.join(item['title'] for item in group['items'][:3])
        group['state']='bad' if any(item['state']=='down' for item in group['items']) else 'warn' if any(item['kind']=='network' for item in group['items']) else 'info'
    return {'items':ordered,'groups':sorted(groups.values(),key=lambda row:row['bucket']),'truncated':truncated,'partial':sorted(partial),'network_available':network_available,'start':start,'end':end}
