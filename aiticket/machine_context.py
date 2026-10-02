"""Small, credential-free machine facts with explicit freshness and access scope."""
import json
import time


def context(c,machine,now=None,external=False):
    now=time.time() if now is None else now
    m=c.execute('SELECT id,name FROM machines WHERE id=?',(machine,)).fetchone()
    if not m: return None
    a=c.execute('SELECT address,last_seen,host_info,capabilities,revoked FROM agents WHERE machine_id=?',(machine,)).fetchone()
    p=c.execute('SELECT enabled,hermes,external,approval FROM command_policies WHERE machine_id=?',(machine,)).fetchone()
    fresh=bool(a and not a['revoked'] and a['last_seen'] is not None and 0<=now-a['last_seen']<=180)
    allowed=bool(p and p['enabled'] and p['external' if external else 'hermes'])
    shell=bool(allowed and fresh and json.loads(a['capabilities']).get('shell_commands') is True)
    reason='Available' if shell else 'Host command permission is disabled for this caller.' if not allowed else 'No monitoring agent is enrolled.' if not a else 'The monitoring agent is revoked.' if a['revoked'] else 'The agent heartbeat is stale or absent.' if not fresh else 'The agent has not advertised shell command capability; check its installation and local command policy.'
    return {'id':m['id'],'name':m['name'],'agent_connection':{'address':a['address'] if a else None,'observed_at':a['last_seen'] if a else None,'fresh':fresh,'source':'Monitoring agent HTTP connection peer; may be a NAT/proxy address and does not list guest network interfaces.'},'system':json.loads(a['host_info']) if a else {},'shell':{'available':shell,'reason':reason,'approval':p['approval'] if p else None,'mode':{'immediate':'full','readonly':'read_only','guarded':'ask_dangerous','required':'legacy_approve_all'}.get(p['approval']) if p else None}}
