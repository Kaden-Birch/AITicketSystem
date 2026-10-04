"""Readable ticket updates; immutable original evidence stays in technical history."""
import re

LABELS = {
    'ai_queued': ('Queued', 'neutral', 'Investigation queued.'),
    'ai_running': ('In progress', 'info', None),
    'resolution_requested': ('Checking recovery', 'info', 'Work finished. Checking that everything is healthy.'),
    'recovery': ('Resolved', 'healthy', None),
    'ai_blocker': ('Needs you', 'down', None),
    'ai_auto_blocked': ('Needs attention', 'down', None),
    'ai_failed': ('Needs attention', 'down', None),
    'ai_unknown': ('Interrupted', 'warning', None),
    'ai_cancelled': ('Stopped', 'neutral', 'AI investigation stopped.'),
    'ai_expired': ('Needs attention', 'warning', 'The investigation timed out.'),
    'command_queued': ('In progress', 'info', 'A host operation was queued.'),
    'command_result': ('Update', 'neutral', 'A host operation returned a result. Details are available in the machine workspace.'),
    'handoff_ai': ('In progress', 'info', 'AI investigation resumed.'),
    'handoff_user': ('Your turn', 'warning', 'You took over this investigation.'),
    'opened': ('New', 'neutral', 'Monitoring detected a problem.'),
}
UUID = r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b'


def readable(value):
    text=str(value or '')
    text=re.sub(r'\*?\*?Closure is pending independent monitoring verification\.[\s\S]*?(?:notification\.|$)', '', text)
    text=re.sub(r'^AI inference \(unverified\):\s*', '', text)
    text=re.sub(r'\s*·\s*Execution\s+'+UUID, '', text)
    text=re.sub(UUID, '[reference in technical history]', text)
    text=re.sub(r'(?i)Request ticket closure and recovery notification[^.]*\.', '', text)
    text=re.sub(r'(?i)Ticket resolution requested\.\s*', '', text)
    text=text.replace('**','')
    text=re.sub(r'^#{1,6}\s*', '', text, flags=re.M)
    return text.strip() or 'Update recorded. Details are available in technical history.'


def conversation(timeline, jobs):
    # A completed model response is a session result, never verified resolution.
    requested=False
    result=[]
    for entry in timeline:
        if entry['kind']=='manual_opened':continue
        if entry['kind']=='ai_queued':requested=False
        if entry['kind']=='resolution_requested':requested=True
        label,tone,fixed=LABELS.get(entry['kind'],('Update','neutral',None))
        if entry['kind']=='ai_completed':
            label,tone='Checking recovery' if requested else 'Session complete','info'
        actor={'user':'You','hermes':'Hermes','monitor':'Monitoring','agent':'Host agent'}.get(entry['actor'],'System')
        result.append({**entry,'author':actor,'label':label,'tone':tone,'body':fixed or readable(entry['text'])})
    return result
