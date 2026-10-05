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
    windows=bool(a and json.loads(a['host_info']).get('os','').lower().startswith('windows'))
    result={'id':m['id'],'name':m['name'],'agent_connection':{'address':a['address'] if a else None,'observed_at':a['last_seen'] if a else None,'fresh':fresh,'source':'Monitoring agent HTTP connection peer; may be a NAT/proxy address and does not list guest network interfaces.'},'system':json.loads(a['host_info']) if a else {},'shell':{'interpreter':'powershell' if windows else '/bin/sh','run_as':'LocalSystem' if windows else 'Agent OS account','available':shell,'reason':reason,'approval':p['approval'] if p else None,'mode':{'immediate':'full','readonly':'read_only','guarded':'ask_dangerous','required':'legacy_approve_all'}.get(p['approval']) if p else None}}

    sample=c.execute('SELECT sampled_at,telemetry,last_seen FROM agents WHERE machine_id=? AND revoked=0',(machine,)).fetchone()
    sample_fresh=bool(sample and sample['sampled_at'] is not None and -30<=now-sample['sampled_at']<=180 and fresh)
    from .ai import evidence_snapshot
    metrics=json.loads(sample['telemetry'] or '{}') if sample else {}
    result['telemetry']={'sampled_at':sample['sampled_at'] if sample else None,'received_at':sample['last_seen'] if sample else None,'fresh':sample_fresh,'metrics':evidence_snapshot(metrics),'clock_offset_seconds':round(sample['sampled_at']-sample['last_seen'],1) if sample and sample['sampled_at'] is not None and sample['last_seen'] is not None else None}
    checks=[]
    rows=c.execute('SELECT c.id,c.name,c.kind,c.enabled,c.health,c.interval,c.failures,c.successes,o.at,o.health AS latest_health,o.evidence FROM checks c LEFT JOIN observations o ON o.id=(SELECT id FROM observations WHERE check_id=c.id ORDER BY at DESC LIMIT 1) WHERE c.machine_id=? AND c.kind!=\'manual\' ORDER BY c.enabled DESC,c.name LIMIT 31',(machine,)).fetchall()
    for row in rows[:30]:
        evidence=evidence_snapshot(json.loads(row['evidence'] or '{}'))
        if len(json.dumps(evidence))>600:evidence={'coverage':'Large result; inspect the check evidence for details','reason':evidence.get('reason'),'status':evidence.get('status')}
        checks.append({'id':row['id'],'name':row['name'],'kind':row['kind'],'enabled':bool(row['enabled']),'health':row['health'],'last_result':row['latest_health'],'observed_at':row['at'],'fresh':bool(row['at'] is not None and 0<=now-row['at']<=max(180,row['interval']*3)),'interval_seconds':row['interval'],'failures':row['failures'],'recovery_successes':row['successes'],'evidence':evidence})
    result['checks']=checks
    from .integrations import context as integration_context
    result['services']=integration_context(c,machine)
    discovery=c.execute('SELECT * FROM agent_discovery WHERE machine_id=?',(machine,)).fetchone()
    if discovery:
        inventory=json.loads(discovery['data']);result['discovery']={'sampled_at':discovery['at'],'fresh':fresh and 0<=now-discovery['at']<=180,'containers':inventory.get('containers',[]),'processes':inventory.get('processes',[])[:40],'processes_truncated':len(inventory.get('processes',[]))>40 or inventory.get('processes_truncated',False),'containers_truncated':inventory.get('containers_truncated',False),'warnings':inventory.get('warnings',[])}
    from .evidence import summary as coverage_summary
    result['evidence_available']=coverage_summary(c,machine,now)
    result['coverage']={'checks_truncated':len(rows)>30,'telemetry':'All reported metric values; unavailable values are not healthy results.'}
    from .applications import context as applications_context
    result['applications']=applications_context(c,machine,now)
    from .proxmox_operations import context as proxmox_context
    result['proxmox']=proxmox_context(c,machine)
    result['proxmox_metrics']=[{'kind':r['kind'],'sampled_at':r['last_seen'],'fresh':bool(r['present'] and 0<=now-r['last_seen']<=180),'metrics':evidence_snapshot(json.loads(r['metrics'] or '{}')),'note':'Proxmox disk allocation is not guest filesystem free space.'} for r in c.execute('SELECT kind,last_seen,present,metrics FROM proxmox_objects WHERE machine_id=? AND present=1 ORDER BY last_seen DESC LIMIT 4',(machine,))]
    return evidence_snapshot(result)
