"""Bounded read-only process and mounted CIFS health checks."""
import json
import subprocess
import sys
import time
from pathlib import Path


_children=[]

def mount_probe(argv):
    # Kernel CIFS I/O can remain uninterruptible after SIGKILL. Never wait
    # indefinitely, and cap outstanding children across disconnected mounts.
    _children[:]=[p for p in _children if p.poll() is None]
    if len(_children)>=4: return False
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    _children.append(child)
    try:
        return child.wait(timeout=5)==0
    except subprocess.TimeoutExpired:
        child.kill()
        return False


DOCKER_FORMAT='{"status":{{json .State.Status}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}},"restart_count":{{json .RestartCount}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"not_configured"{{end}}}'


def docker_probe(target,require_health=False):
    try:
        reply=subprocess.run(['docker','container','inspect','--format',DOCKER_FORMAT,'--',target],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C'})
        if reply.returncode:
            missing=b'No such container' in reply.stderr[:4096] or b'No such object' in reply.stderr[:4096]
            return (False if missing else None), {'status':'missing' if missing else 'unknown','reason':'Container does not exist' if missing else 'Docker inspection unavailable; check daemon and agent permissions'}
        data=json.loads(reply.stdout[:4096])
        if not isinstance(data,dict) or type(data.get('running')) is not bool or data.get('health') not in ('healthy','unhealthy','starting','not_configured'):
            raise ValueError('Malformed Docker state')
        if require_health and data['running'] and not data.get('paused') and not data.get('restarting') and data['health']=='not_configured':
            return None, {**data,'reason':'Required Docker HEALTHCHECK is not configured'}
        healthy=data['running'] and not data.get('paused') and not data.get('restarting') and data['health'] in ('healthy','not_configured')
        return bool(healthy),data
    except (OSError,subprocess.SubprocessError,ValueError):
        return None, {'status':'unknown','reason':'Docker inspection unavailable; check CLI, daemon and agent permissions'}


def evaluate(check):
    target=check['config']['target']
    healthy=False
    details={}
    try:
        if check['kind']=='docker':
            healthy,details=docker_probe(target,check['config'].get('require_health',False))
        elif check['kind']=='process':
            if target.endswith('.service'):
                healthy=subprocess.run(['systemctl','is-active','--quiet',target],timeout=3,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
            else:
                for p in Path('/proc').glob('[0-9]*/comm'):
                    try:
                        if p.read_text().strip()==target:
                            healthy=True;break
                    except OSError:
                        continue
        elif check['kind']=='smb':
            # A child bounds filesystem reads: disconnected CIFS can block the caller.
            script="""import os,sys
from pathlib import Path
path=os.path.realpath(sys.argv[1])
mounts=[]
for line in Path('/proc/self/mountinfo').read_text().splitlines():
 left,right=line.split(' - ',1); fields=left.split(); mount=fields[4].replace('\\\\040',' ').replace('\\\\134','\\\\')
 if path==mount or path.startswith(mount.rstrip('/')+'/'): mounts.append((len(mount),right.split()[0]))
if not mounts or max(mounts)[1] not in ('cifs','smb3'): sys.exit(1)
with os.scandir(path) as entries: next(entries,None)
os.statvfs(path)
"""
            healthy=mount_probe([sys.executable,'-c',script,target])
    except (OSError,subprocess.SubprocessError):
        pass
    return {'sampled_at':time.time(),'id':check['id'],'config':check['config'],'healthy':healthy,'details':details}



def container_facts(items,runner=None):
    """Use selected inspect fields; never collect environment or full configuration."""
    from diagnostics import redact
    names=[x['target'] for x in items if isinstance(x.get('target'),str) and x['target'] and not x['target'].startswith('-')][:100]
    if not names:return {}
    template='{"name":{{json .Name}},"restart_count":{{json .RestartCount}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}},"started_at":{{json .State.StartedAt}},"image_id":{{json .Image}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"not_configured"{{end}},"exit_reason":{{json .State.Error}}}'
    argv=['docker','container','inspect','--format',template,'--',*names]
    if runner:
        reply=runner(argv,timeout=4,limit=60000)
        if reply['state']!='completed':raise ValueError('Inspection unavailable')
        raw=reply['stdout']
    else:
        import selectors,os
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,shell=False)
        selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
        output=bytearray();deadline=time.monotonic()+4
        try:
            while time.monotonic()<deadline and len(output)<60000:
                if selector.select(min(.2,max(0,deadline-time.monotonic()))):
                    block=os.read(process.stdout.fileno(),min(4096,60000-len(output)))
                    if not block:break
                    output.extend(block)
                elif process.poll() is not None:break
            if process.poll() is None:
                process.kill();process.wait();raise ValueError('Inspection exceeded limits')
            if process.returncode:raise ValueError('Inspection unavailable')
        finally:
            selector.close();process.stdout.close()
            if process.poll() is None:process.kill();process.wait()
        raw=output.decode(errors='replace')
    rows={}
    for line in raw.splitlines()[:100]:
        item=json.loads(line);name=item.pop('name','').lstrip('/')
        item['exit_reason']=redact(item.get('exit_reason',''))[:500]
        rows[name]=item
    for item in items:item.update(rows.get(item['target'],{}))
    return rows

def discover(state):
    """Inventory names and counters, never environment variables or command lines."""
    import os,shutil
    result={'docker_installed':bool(shutil.which('docker')),'containers':[],'processes':[],'warnings':[]}
    if result['docker_installed']:
        try:
            reply=subprocess.run(['docker','ps','-a','--format','{{json .}}'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4)
            if reply.returncode:raise ValueError()
            lines=reply.stdout[:60000].decode().splitlines();result['containers_truncated']=len(lines)>100
            for line in lines[:100]:
                x=json.loads(line);result['containers'].append({'target':x['Names'],'name':x['Names'],'image':x.get('Image',''),'state':x.get('State','unknown'),'status':x.get('Status',''),'ports':x.get('Ports','')})
            reply=subprocess.run(['docker','stats','--no-stream','--format','{{json .}}'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4)
            stats={x['Name']:x for x in [json.loads(line) for line in reply.stdout[:60000].decode().splitlines()[:100]]} if not reply.returncode else {}
            for item in result['containers']:
                row=stats.get(item['name'],{})
                for key,out in [('CPUPerc','cpu_percent'),('MemPerc','memory_percent')]:
                    try:item[out]=float(row[key].rstrip('%'))
                    except (KeyError,ValueError):pass
        except (OSError,ValueError,subprocess.SubprocessError):result['warnings'].append('Docker inventory is unavailable. Check the daemon and agent permissions.')
    try:container_facts(result['containers'])
    except (OSError,ValueError,subprocess.SubprocessError):result['warnings'].append('Detailed container state is unavailable.')
    now=time.monotonic();previous=state.get('discovery_cpu',{});elapsed=now-state.get('discovery_at',now);ticks=os.sysconf('SC_CLK_TCK');page=os.sysconf('SC_PAGE_SIZE');current={}
    for directory in list(Path('/proc').glob('[0-9]*'))[:4096]:
        try:
            pid=int(directory.name);name=(directory/'comm').read_text().strip();raw=(directory/'stat').read_text();columns=raw[raw.rfind(')')+2:].split();counter=(int(columns[11])+int(columns[12]))/ticks
            # Process start time prevents PID reuse from corrupting CPU deltas.
            identity=str(pid)+':'+columns[19];current[identity]=counter
            cpu=max(0,100*(counter-previous[identity])/elapsed) if identity in previous and elapsed>0 else None
            item={'pid':pid,'name':name,'target':name,'memory_bytes':max(0,int(columns[21]))*page}
            if cpu is not None:item['cpu_percent']=round(cpu,1)
            result['processes'].append(item)
        except (OSError,ValueError,IndexError):continue
    result['processes'].sort(key=lambda p:(p.get('cpu_percent',0),p['memory_bytes']),reverse=True)
    result['processes_truncated']=len(result['processes'])>200;result['processes']=result['processes'][:200];state['discovery_cpu']=current;state['discovery_at']=now
    return result
