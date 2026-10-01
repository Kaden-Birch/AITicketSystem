"""Locally enforced, bounded read-only operations. No shell, arguments or paths from jobs."""
import json
import os
import re
import selectors
import subprocess
import time
from pathlib import Path


def redact(text):
    return re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+',r'\1=[REDACTED]',str(text)[:16000])


def load_policy(path):
    if not Path(path).exists():
        return {'services':{},'logs':False}
    policy=json.loads(Path(path).read_text())
    services=policy.get('services',{})
    if not isinstance(services,dict) or len(services)>20 or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',str(k)) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}\.service',str(v)) or str(v).startswith('-') for k,v in services.items()):
        raise ValueError('Invalid local service allowlist')
    recovery=policy.get('recovery',{})
    if not isinstance(recovery,dict) or not isinstance(recovery.get('services',[]),list) or any(s not in services for s in recovery.get('services',[])):
        raise ValueError('Invalid recovery service allowlist')
    return {'services':services,'logs':policy.get('logs') is True,'recovery':{'enabled':recovery.get('enabled') is True,'validated':recovery.get('validated') is True,'services':recovery.get('services',[])}}


def capabilities(policy):
    result={'operations':['process_summary','service_status']+(['service_logs'] if policy['logs'] else []),'services':list(policy['services'])}
    cfg=policy.get('recovery',{})
    if cfg.get('enabled') and cfg.get('validated'):
        result.update(actions=['service_restart'],action_services={s:policy['services'][s] for s in cfg['services']})
    return result


def command(argv):
    """Fixed argv only; enforce wall time and output limit, including noisy providers."""
    process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,
                             env={'PATH':'/usr/bin:/bin','LANG':'C','SYSTEMD_PAGER':''},shell=False,start_new_session=True)
    output=bytearray()
    deadline=time.monotonic()+5
    selector=selectors.DefaultSelector()
    selector.register(process.stdout,selectors.EVENT_READ)
    limited=False
    try:
        while time.monotonic()<deadline and len(output)<16000:
            events=selector.select(timeout=min(.2,max(0,deadline-time.monotonic())))
            if events:
                block=os.read(process.stdout.fileno(),min(4096,16000-len(output)))
                if not block:
                    break
                output.extend(block)
            elif process.poll() is not None:
                break
        if process.poll() is None:
            limited=True
            process.kill()
        process.wait(timeout=2)
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return {'status':'completed' if process.returncode==0 and not limited else 'failed',
            'output':(redact(output.decode(errors='replace'))+ ('\n[output/time limit reached]' if limited else ''))[:16000]}


def execute(job,policy,proc_root='/proc'):
    if not isinstance(job,dict) or job.get('expires',0)<=time.time():
        raise ValueError('Expired diagnostic')
    operation=job.get('operation')
    parameters=job.get('parameters',{})
    if operation not in capabilities(policy)['operations'] or not isinstance(parameters,dict):
        raise ValueError('Diagnostic denied by local allowlist')
    if operation=='process_summary':
        if parameters:
            raise ValueError('Process summary accepts no parameters')
        rows=[]
        for scanned,entry in enumerate(Path(proc_root).iterdir()):
            if scanned>=1000:
                break
            if entry.name.isdigit():
                try:
                    rows.append({'pid':int(entry.name),'name':entry.joinpath('comm').read_text()[:80].strip()})
                except OSError:
                    pass
            if len(rows)>=100:
                break
        return {'status':'completed','output':redact(json.dumps({'processes':rows,'limit':100,'command_arguments':'excluded'}))}
    if set(parameters)!={'service_id'} or parameters['service_id'] not in policy['services']:
        raise ValueError('Service denied by local allowlist')
    unit=policy['services'][parameters['service_id']]
    if operation=='service_status':
        return command(['/usr/bin/systemctl','show','--no-pager','--property=Id,LoadState,ActiveState,SubState',unit])
    return command(['/usr/bin/journalctl','--no-pager','--quiet','--lines=50','--output=short-iso','--unit',unit])
