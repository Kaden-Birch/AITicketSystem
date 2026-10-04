#!/usr/bin/env python3
"""Independent signed-release updater. Imports no monitoring-agent modules."""
import argparse
import base64
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

FEED = 'https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-stable/agent-manifest.json'
FILES = ('agent.py', 'diagnostics.py', 'monitoring.py', 'network.py', 'actions.py', 'commands.py', 'install_verify.py')
STATES = ('current', 'available', 'scheduled', 'waiting', 'installing', 'updated', 'rolled_back', 'failed')


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        os.chmod(tmp, 0o600)
        json.dump(value, f)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)


def fetch(url, limit, data=None, headers=None, ca=None):
    class HTTPSOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            if not newurl.startswith('https://'): raise ValueError('Unsafe release redirect')
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)
    opener = urllib.request.build_opener(HTTPSOnly, urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    with opener.open(urllib.request.Request(url, data=data, headers=headers or {}), timeout=15) as reply:
        body = reply.read(limit + 1)
        if len(body) > limit: raise ValueError('Update response exceeds size limit')
        return body


def manifest(body, public_key):
    envelope = json.loads(body)
    payload = base64.b64decode(envelope['payload'], validate=True)
    signature = base64.b64decode(envelope['signature'], validate=True)
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp); (p/'payload').write_bytes(payload); (p/'signature').write_bytes(signature)
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public_key), '-rawin', '-in', str(p/'payload'), '-sigfile', str(p/'signature')], capture_output=True)
        if result.returncode: raise ValueError('Release signature verification failed')
    doc = json.loads(payload)
    if set(doc) != {'version', 'url', 'sha256', 'published', 'rollout_minutes'}: raise ValueError('Invalid release manifest')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\+[a-f0-9]{12}', doc['version']): raise ValueError('Invalid release version')
    if not re.fullmatch(r'https://github\.com/Kaden-Birch/AITicketSystem/releases/download/agent-[0-9]+\.[0-9]+\.[0-9]+\+[a-f0-9]{12}/agent\.tar\.gz', doc['url']): raise ValueError('Invalid release URL')
    if not re.fullmatch('[a-f0-9]{64}', doc['sha256']): raise ValueError('Invalid release checksum')
    if type(doc['published']) is not int or doc['published'] < 1 or doc['published'] > time.time()+300: raise ValueError('Invalid publication time')
    if type(doc['rollout_minutes']) is not int or not 0 <= doc['rollout_minutes'] <= 1440: raise ValueError('Invalid rollout')
    return doc


def extract(body, destination):
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(FILES) or {m.name for m in members} != set(FILES): raise ValueError('Unexpected release contents')
        if any(not m.isfile() or m.size > 2_000_000 for m in members): raise ValueError('Invalid release member')
        destination.mkdir(mode=0o755)
        for member in members:
            path = destination/member.name
            path.write_bytes(archive.extractfile(member).read()); path.chmod(0o644)
    # Compile every module and validate imports without executing a job or enrolling.
    subprocess.run(['/usr/bin/python3', '-m', 'compileall', '-q', str(destination)], check=True, timeout=30)
    subprocess.run(['/usr/bin/python3', '-c', 'import agent,diagnostics,monitoring,network,actions,commands,install_verify'], cwd=destination, check=True, timeout=30, capture_output=True)


def activate(root, target):
    link = root/'current.next'
    link.unlink(missing_ok=True); link.symlink_to(target)
    os.replace(link, root/'current')


class Updater:
    def __init__(self, root=Path('/opt/aiticket-agent'), state=Path('/var/lib/aiticket-agent'), config=Path('/etc/aiticket-agent/updater.json')):
        self.root, self.state = Path(root), Path(state)
        self.config = json.loads(Path(config).read_text())
        self.path = self.state/'update-status.json'
        self.status = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.identity = json.loads((self.state/'identity.json').read_text())

    def report(self):
        """Application reporting is optional; its failure never blocks release checks."""
        try:
            base = self.identity['server'].rstrip('/')
            if not base.startswith('https://') and not (base.startswith('http://') and self.identity.get('allow_http') is True): raise ValueError('Invalid application endpoint')
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args): return None
            opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=self.identity.get('ca'))))
            status = {k: self.status.get(k) for k in ('state','installed','available','checked','detail','automatic','handled_request')}
            req = urllib.request.Request(base+'/api/agent/updater', data=json.dumps(status).encode(), headers={'Content-Type':'application/json','Authorization':'Bearer '+self.identity['credential']})
            with opener.open(req, timeout=10) as reply:
                result = json.loads(reply.read(8192))
                return result.get('request')
        except Exception:
            return None

    def record(self, state, detail='', **fields):
        self.status.update(state=state, detail=detail, **fields); save(self.path, self.status)

    def service(self, action):
        subprocess.run(['systemctl', action, 'aiticket-agent'], check=True, timeout=30, capture_output=True)

    def healthy(self, version, since):
        try:
            health=json.loads((self.state/'health.json').read_text())
            return health.get('version') == version and health.get('at',0) >= since
        except (OSError, ValueError): return False

    def run(self):
        self.state.mkdir(parents=True, exist_ok=True)
        with open(self.state/'updater.lock','a') as lock:
            try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: return
            request = self.report()
            self.status.update(checked=time.time(), automatic=self.config.get('automatic',True))
            try:
                # Recover an interrupted installation before considering another release.
                if self.status.get('state') == 'installing':
                    with open(self.state/'execution.lock','a') as recovery_lock:
                        fcntl.flock(recovery_lock,fcntl.LOCK_EX)
                        self.service('stop'); activate(self.root, self.status['previous']); self.service('start')
                    self.record('rolled_back','Interrupted update restored the previous release.', failed_release=self.status.get('available'), installed=self.status.get('previous_version'))
                doc=manifest(fetch(FEED,65536), self.root/'release-public.pem')
                if doc['published'] < self.status.get('highest_published',0): raise ValueError('Older release manifest rejected')
                self.status.update(highest_published=doc['published'], available=doc['version'])
                if self.status.get('installed') == doc['version']:
                    self.record('current', 'Agent is up to date.', handled_request=request); return
                if self.status.get('failed_release') == doc['version']:
                    self.record('rolled_back','This release failed verification. Waiting for a newer release.', handled_request=request); return
                if not request and not self.config.get('automatic',True): self.record('available','Automatic updates are paused.'); return
                bucket=int(hashlib.sha256(self.identity['agent_id'].encode()).hexdigest()[:8],16)%100
                ready=doc['published']+(0 if bucket<10 else doc['rollout_minutes']*60)
                if not request and time.time()<ready: self.record('scheduled','Update scheduled during the staged rollout.'); return
                body=fetch(doc['url'],20_000_000)
                if hashlib.sha256(body).hexdigest()!=doc['sha256']: raise ValueError('Release checksum verification failed')
                with tempfile.TemporaryDirectory(dir=self.root/'releases') as temp:
                    stage=Path(temp)/'bundle'; extract(body,stage)
                    # Shared execution lock prevents updates interrupting diagnostics or commands.
                    with open(self.state/'execution.lock','a') as execution:
                        try: fcntl.flock(execution, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError: self.record('waiting','Waiting for active agent work to finish.'); return
                        identity=json.loads((self.state/'identity.json').read_text())
                        if any(r.get('state')=='running' for r in identity.get('command_ledger',{}).values()):
                            self.record('waiting','Waiting for completed command results to be saved.'); return
                        previous=str((self.root/'current').resolve()); previous_version=self.status.get('installed','unknown')
                        destination=self.root/'releases'/doc['version']
                        if destination.exists():
                            if any((destination/name).read_bytes()!=(stage/name).read_bytes() for name in FILES): raise ValueError('Release directory collision')
                        else: shutil.move(stage,destination)
                        self.record('installing','Installing verified release.', previous=previous, previous_version=previous_version)
                        self.service('stop'); activate(self.root,destination); since=time.time(); self.service('start')
                    deadline=time.monotonic()+120
                    while time.monotonic()<deadline and not self.healthy(doc['version'],since): time.sleep(2)
                    if not self.healthy(doc['version'],since):
                        self.service('stop'); activate(self.root,previous); self.service('start')
                        self.record('rolled_back','New agent did not establish a verified heartbeat; previous release restored.',failed_release=doc['version'], installed=previous_version,handled_request=request)
                    else:
                        self.record('updated','Update verified by an authenticated agent heartbeat.',installed=doc['version'],handled_request=request)
            except Exception as exc:
                if self.status.get('state')=='installing':
                    try:
                        self.service('stop'); activate(self.root,self.status['previous']); self.service('start')
                        self.record('rolled_back','Installation failed; previous release restored.',failed_release=self.status.get('available'),installed=self.status.get('previous_version'),handled_request=request)
                    except Exception: self.record('failed','Update recovery failed. Inspect the updater journal.',handled_request=request)
                else: self.record('failed',str(exc)[:240],handled_request=request)
            finally:
                save(self.path,self.status); self.report()


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--config',default='/etc/aiticket-agent/updater.json'); args=parser.parse_args()
    Updater(config=Path(args.config)).run()
