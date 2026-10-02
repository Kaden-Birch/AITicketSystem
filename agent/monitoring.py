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
