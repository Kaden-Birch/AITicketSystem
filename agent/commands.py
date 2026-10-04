"""Explicitly enabled remote shell execution. Never replay an uncertain command."""
import fcntl
import json,os,queue,selectors,signal,subprocess,threading,time
from pathlib import Path

finished=queue.Queue()
worker=None


def policy_config(path):
    p=Path(path)
    if not p.exists(): return {'enabled':False}
    document=json.loads(p.read_text());cfg=document.get('commands',{})
    if not isinstance(cfg,dict): raise ValueError('Invalid command policy.')
    if cfg.get('enabled') is not True: return {'enabled':False}
    if p.is_symlink() or p.stat().st_uid!=0 or p.stat().st_mode & 0o022 or p.parent.is_symlink() or p.parent.stat().st_uid!=0 or p.parent.stat().st_mode & 0o022:
        raise ValueError('Enabled command policy must be root-owned and not group/world writable.')
    timeout=cfg.get('timeout',120);limit=cfg.get('output_limit',8192)
    if type(timeout) is not int or not 5<=timeout<=3600 or type(limit) is not int or not 1024<=limit<=65536 or type(cfg.get('sudo',False)) is not bool:
        raise ValueError('Invalid local command bounds.')
    return {'enabled':True,'timeout':timeout,'output_limit':limit,'sudo':cfg.get('sudo',False)}


def execute(job,authorize,load_policy):
    cfg=load_policy()
    command=job.get('command')
    if not cfg.get('enabled') or not isinstance(command,str) or not 1<=len(command)<=16000 or '\0' in command or not authorize():
        return {'state':'cancelled','exit_code':None,'stdout':'','stderr':'Command permission unavailable before execution.','truncated':False}
    if type(job.get('timeout')) is not int or not 1<=job['timeout']<=3600 or type(job.get('output_limit')) is not int or not 1024<=job['output_limit']<=65536:
        raise ValueError('Invalid command execution bounds.')
    timeout=min(job['timeout'],cfg['timeout']);limit=min(job['output_limit'],cfg['output_limit'])
    argv=(['/usr/bin/sudo','-n','--'] if cfg['sudo'] else [])+['/bin/sh','-c',command]
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},start_new_session=True)
    buffers={'stdout':bytearray(),'stderr':bytearray()};truncated=False;state=None
    selector=selectors.DefaultSelector()
    for stream,name in ((process.stdout,'stdout'),(process.stderr,'stderr')):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    deadline=time.monotonic()+timeout;next_check=0
    try:
        while selector.get_map() or process.poll() is None:
            now=time.monotonic()
            if now>=deadline:
                state='unknown';break
            if now>=next_check:
                try: allowed=load_policy()==cfg and authorize()
                except Exception: allowed=False
                if not allowed: state='cancelled';break
                next_check=now+2
            for key,_ in selector.select(.2):
                data=os.read(key.fileobj.fileno(),8192)
                if not data: selector.unregister(key.fileobj);continue
                remaining=max(0,limit-sum(len(b) for b in buffers.values()))
                buffers[key.data].extend(data[:remaining]);truncated=truncated or len(data)>remaining
            if process.poll() is not None and not selector.get_map(): break
        if state:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        code=process.wait(timeout=5)
        output={};remaining=limit
        for name in ('stdout','stderr'):
            encoded=buffers[name].decode('utf-8','replace').encode('utf-8')
            output[name]=encoded[:remaining].decode('utf-8','ignore')
            truncated=truncated or len(encoded)>remaining
            remaining-=len(output[name].encode('utf-8'))
        return {'state':state or ('completed' if code==0 else 'failed'),'exit_code':code,**output,'truncated':truncated}
    finally:
        # A background child must not survive the shell/job boundary.
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        selector.close();process.stdout.close();process.stderr.close()


def recover(state):
    for identifier,record in state.get('command_ledger',{}).items():
        if record['state']=='running':
            record['state']='unknown'
            state.setdefault('command_results',[]).append({'id':identifier,'dispatch_token':record['dispatch_token'],'result':{'state':'unknown','exit_code':None,'stdout':'','stderr':'Agent restarted during command; never replayed.','truncated':False}})


def drain(state,path,write_state):
    while not finished.empty():
        payload=finished.get_nowait()
        state['command_ledger'][payload['id']]['state']=payload['result']['state']
        state.setdefault('command_results',[]).append(payload)
        write_state(path,state)


def start(state,path,jobs,write_state,authorize,load_policy):
    global worker
    if worker and worker.is_alive(): return
    for job in jobs[:1]:
        ledger=state.setdefault('command_ledger',{})
        if job['id'] in ledger: return
        ledger[job['id']]={'state':'running','dispatch_token':job['dispatch_token']}
        write_state(path,state)
        execution=open(Path(path).parent/'execution.lock','a')
        fcntl.flock(execution,fcntl.LOCK_SH)
        def run():
            try: result=execute(job,lambda:authorize(job),load_policy)
            except Exception: result={'state':'unknown','exit_code':None,'stdout':'','stderr':'Command runner failed; no replay.','truncated':False}
            finally: execution.close()
            finished.put({'id':job['id'],'dispatch_token':job['dispatch_token'],'result':result})
        worker=threading.Thread(target=run,daemon=True,name='remote-command');worker.start()
