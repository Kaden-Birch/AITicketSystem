#!/usr/bin/env python3
"""Outbound Linux monitoring agent with centrally authorized command execution."""
import argparse
import getpass
import json
import os
import signal
import ssl
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

VERSION = '0.8.0'


def endpoint(value,allow_http=False):
    p = urlsplit(value)
    if p.scheme not in (('https','http') if allow_http else ('https',)) or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError('Use HTTPS, or explicitly enable HTTP with --allow-http; embedded credentials, query strings and fragments are prohibited.')
    return value.rstrip('/')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post(base, route, payload, ca=None, credential=None, allow_http=False):
    base=endpoint(base,allow_http=allow_http)
    handlers=[NoRedirect]
    if urlsplit(base).scheme=='https':
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    opener = urllib.request.build_opener(*handlers)
    headers = {'Content-Type': 'application/json'}
    if credential:
        headers['Authorization'] = 'Bearer ' + credential
    req = urllib.request.Request(base + route, data=json.dumps(payload).encode(), headers=headers, method='POST')
    with opener.open(req, timeout=10) as response:
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError('Server response exceeds size limit')
        return json.loads(body)


def write_state(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def telemetry(state=None):
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable','SwapTotal','SwapFree'):
            memory[key] = int(value.strip().split()[0]) * 1024
    disk = os.statvfs('/')
    result = {'inode_free':disk.f_favail,'inode_total':disk.f_files,'uptime_seconds': float(Path('/proc/uptime').read_text().split()[0]),
            'load_1': os.getloadavg()[0], 'load_5':os.getloadavg()[1],'load_15':os.getloadavg()[2], 'cpu_cores':os.cpu_count() or 1, 'swap_total_bytes':memory.get('SwapTotal',0),'swap_free_bytes':memory.get('SwapFree',0), 'memory_total_bytes': memory['MemTotal'],
            'memory_available_bytes': memory['MemAvailable'],
            'disk_free_bytes': disk.f_bavail * disk.f_frsize, 'disk_total_bytes': disk.f_blocks * disk.f_frsize}
    if state is not None:
        counters=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        total,idle=sum(counters),counters[3]+counters[4]
        previous=state.get('cpu_counters')
        if previous and total>previous[0] and idle>=previous[1]:
            result['cpu_percent']=max(0,min(100,100*(1-(idle-previous[1])/(total-previous[0]))))
        state['cpu_counters']=[total,idle]
    pressure=Path('/proc/pressure/memory')
    if pressure.exists():
        for line in pressure.read_text().splitlines():
            if line.startswith('full '):
                result['memory_pressure_percent']=float(dict(field.split('=') for field in line.split()[1:])['avg10'])
    return result


def host_info():
    import platform
    os_name='Linux'
    path=Path('/etc/os-release')
    if path.exists():
        values=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
        os_name=values.get('PRETTY_NAME','Linux').strip('"')
    return {'hostname':platform.node()[:200],'os':os_name[:200],'kernel':platform.release()[:200],'architecture':platform.machine()[:80]}


def network_info():
    try:
        from network import inventory
        return inventory()
    except Exception:
        return {"interfaces":[],"neighbors":[],"machine_type":"unknown"}


def process_jobs(state,path,jobs,policy):
    from diagnostics import execute
    ledger=state.setdefault('diagnostic_ledger',{})
    for job in jobs[:1]:
        job_id=job['id']
        record=ledger.get(job_id)
        if not record:
            ledger[job_id]={'status':'running','output':''}
            write_state(path,state)
            try:
                record=execute(job,policy)
            except Exception as exc:
                record={'status':'failed','output':'Diagnostic failed: '+type(exc).__name__}
        elif record['status']=='running':
            record={'status':'failed','output':'Agent restarted during diagnostic; not blindly replayed.'}
        ledger[job_id]=record
        state['diagnostic_result']={'job_id':job_id,'lease_token':job['lease_token'],**record}
        # Retain bounded completed identity ledger; old jobs expire in ten minutes.
        while len(ledger)>100:
            ledger.pop(next(iter(ledger)))
        write_state(path,state)



def process_actions(state,path,jobs,policy,authorize,policy_loader=None):
    from actions import execute
    ledger=state.setdefault('action_ledger',{})
    for job in jobs[:1]:
        identifier=job['id']
        record=ledger.get(identifier)
        if not record:
            # Persist before authorization/execution. Any crash in this window is unknown, never replayed.
            ledger[identifier]={'status':'running','output':''}
            write_state(path,state)
            try:
                authorization=authorize({'id':identifier,'dispatch_token':job['dispatch_token'],'proposal_hash':job['proposal_hash']})
                if authorization.get('status')!='authorized' or authorization.get('proposal_hash')!=job['proposal_hash'] or authorization.get('operation')!=job['operation'] or authorization.get('parameters')!=job['parameters']:
                    raise ValueError('Action authorization failed')
                record=execute(job,policy_loader() if policy_loader else policy)
            except Exception:
                record={'status':'unknown','output':'Authorization/execution outcome unknown; no automatic replay.'}
        elif record['status']=='running':
            record={'status':'unknown','output':'Agent restarted during action; no automatic replay.'}
        ledger[identifier]=record
        state['action_result']={'id':identifier,'dispatch_token':job['dispatch_token'],**record}
        # Action identities are never evicted; reenrollment requires a new broker delivery.
        write_state(path,state)


def monitor_checks(send,base,state,path):
    """Optional checks must never prevent the primary heartbeat."""
    try:
        from monitoring import evaluate
        reply=send(base,'/api/agent/checks',{'results':state.get('monitor_results',[])},state.get('ca'),state['credential'])
        state['monitor_results']=[evaluate(check) for check in reply.get('checks',[])[:2]]
        write_state(path,state)
        if state['monitor_results']:
            send(base,'/api/agent/checks',{'results':state['monitor_results']},state.get('ca'),state['credential'])
            state['monitor_results']=[];write_state(path,state)
    except Exception as exc:
        status=getattr(exc,'code',None)
        print('Optional host checks unavailable: '+type(exc).__name__+(' (HTTP '+str(status)+')' if status else '')+'; heartbeat continues.',flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['enroll', 'run', 'recovery-credential'])
    parser.add_argument('--state', default='/var/lib/aiticket-agent/identity.json')
    parser.add_argument('--server')
    parser.add_argument('--allow-http',action='store_true',help='Explicitly allow unencrypted HTTP; enrollment saves this choice.')
    parser.add_argument('--ca')
    parser.add_argument('--policy',default='/etc/aiticket-agent/policy.json')
    args = parser.parse_args()
    path = Path(args.state)
    from functools import partial
    send=partial(post,allow_http=args.allow_http)
    if args.command == 'enroll':
        if path.exists():
            raise SystemExit('Identity already exists. Revoke and remove it deliberately before re-enrollment.')
        base = endpoint(args.server or input('Application endpoint: '),allow_http=args.allow_http)
        reply = send(base, '/api/agent/enroll', {'token': getpass.getpass('Single-use enrollment token: ')}, args.ca)
        write_state(path, {'server': base, 'ca': args.ca, 'allow_http':args.allow_http, **reply})
        print('Enrolled. Credentials saved with mode 0600; no agent IP configured.')
        return
    state = json.loads(path.read_text())
    if args.command=='recovery-credential':
        credential=getpass.getpass('Separate action credential from the application UI: ').strip()
        if not 16<=len(credential)<=2048:
            raise SystemExit('Invalid action credential.')
        state['action_credential']=credential
        write_state(path,state)
        print('Separate action credential saved. Restart the agent to advertise validated local recovery capability.')
        return
    allow_http=args.allow_http or state.get('allow_http') is True
    send=partial(post,allow_http=allow_http)
    base = endpoint(state['server'],allow_http=allow_http)
    from diagnostics import load_policy,capabilities
    policy=load_policy(args.policy)
    from commands import recover,drain,start,policy_config
    recover(state);write_state(path,state)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    delay = 30
    while running:
        try:
            policy=load_policy(args.policy)
            drain(state,path,write_state)
            while state.get('command_results'):
                try:
                    send(base,'/api/agent/command-result',state['command_results'][0],state.get('ca'),state['credential'])
                except urllib.error.HTTPError as exc:
                    if exc.code not in (400,409): raise
                state['command_results'].pop(0);write_state(path,state)
            if state.get('action_result'):
                send(base,'/api/agent/action-result',state['action_result'],state.get('ca'),state.get('action_credential',''))
                state.pop('action_result',None)
                write_state(path,state)
            if state.get('diagnostic_result'):
                try:
                    send(base,'/api/agent/result',state['diagnostic_result'],state.get('ca'),state['credential'])
                except urllib.error.HTTPError as exc:
                    if exc.code not in (400,409):
                        raise
                state.pop('diagnostic_result',None)
                write_state(path,state)
            # Retain stable event identity after ambiguous delivery or process restart.
            pending = state.get('pending')
            if not pending:
                advertised=capabilities(policy)
                advertised['shell_commands']=policy_config(args.policy).get('enabled') is True
                if not state.get('action_credential'):
                    advertised.pop('power_operations',None)
                    advertised.pop('actions',None)
                    advertised.pop('action_services',None)
                pending = {'event_id': str(uuid.uuid4()), 'version': VERSION, 'telemetry': telemetry(state), 'sampled_at':time.time(), 'capabilities':advertised,'host_info':host_info(),'network':network_info()}
                state['pending'] = pending
                write_state(path, state)
            response=send(base, '/api/agent/heartbeat', pending, state.get('ca'), state['credential'])
            state.pop('pending', None)
            write_state(path, state)
            start(state,path,response.get('commands',[]),write_state,lambda job:send(base,'/api/agent/command-permission',{'id':job['id'],'dispatch_token':job['dispatch_token']},state.get('ca'),state['credential']).get('allowed') is True,lambda:policy_config(args.policy))
            process_jobs(state,path,response.get('jobs',[]),policy)
            process_actions(state,path,response.get('actions',[]),policy,lambda payload:send(base,'/api/agent/action-authorize',payload,state.get('ca'),state.get('action_credential','')),policy_loader=lambda:load_policy(args.policy))
            requested=response.get("poll_interval_seconds",30)
            delay=requested if type(requested) is int and 20<=requested<=300 else 30
            monitor_checks(send,base,state,path)
        except Exception as exc:
            print('Heartbeat unavailable: ' + type(exc).__name__, flush=True)
            delay = min(delay * 2, 300)
        for _ in range(delay):
            if not running:
                break
            time.sleep(1)


if __name__ == '__main__':
    main()
