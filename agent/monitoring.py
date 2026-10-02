"""Bounded read-only process and mounted CIFS health checks."""
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


def evaluate(check):
    target=check['config']['target']
    healthy=False
    try:
        if check['kind']=='process':
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
    return {'sampled_at':time.time(),'id':check['id'],'config':check['config'],'healthy':healthy}
