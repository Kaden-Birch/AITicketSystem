"""Independent Windows signed updater, running as its own SYSTEM scheduled task."""
import base64,hashlib,io,json,os,re,shutil,sys,tarfile,tempfile,time,urllib.request,ssl
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from platform_support import locks,current,activate,ps,literal

ROOT=Path(__file__).resolve().parent
FEED='https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-stable/windows-agent-manifest.json'
FILES={'agent.py','commands.py','diagnostics.py','actions.py','monitoring.py','network.py','install_verify.py','windows/runner.py','windows/backend.py','windows/platform_support.py'}


def save(path,data):
    temporary=path.with_suffix('.tmp')
    with temporary.open('w') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
    os.replace(temporary,path)


def download(url,limit):
    class HTTPSOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,url):
            if not url.startswith('https://'):raise ValueError('Unsafe release redirect')
            return super().redirect_request(req,fp,code,msg,headers,url)
    with urllib.request.build_opener(HTTPSOnly,urllib.request.HTTPSHandler(context=ssl.create_default_context())).open(url,timeout=15) as reply:
        body=reply.read(limit+1)
        if len(body)>limit:raise ValueError('Release exceeds size limit')
        return body


def verify(body,key):
    envelope=json.loads(body);payload=base64.b64decode(envelope['payload'],validate=True)
    load_pem_public_key(Path(key).read_bytes()).verify(base64.b64decode(envelope['signature'],validate=True),payload)
    doc=json.loads(payload)
    if set(doc)!={'version','url','sha256','published','rollout_minutes'} or not re.fullmatch(r'\d+\.\d+\.\d+\+[a-f0-9]{12}',doc['version']):raise ValueError('Invalid Windows manifest')
    if doc['url']!='https://github.com/Kaden-Birch/AITicketSystem/releases/download/agent-'+doc['version']+'/windows-agent.tar.gz' or not re.fullmatch('[a-f0-9]{64}',doc['sha256']):raise ValueError('Invalid Windows release source')
    if type(doc['published']) is not int or not 0<doc['published']<=time.time()+300 or type(doc['rollout_minutes']) is not int or not 0<=doc['rollout_minutes']<=1440:raise ValueError('Invalid release timing')
    return doc


def extract(body,path):
    with tarfile.open(fileobj=io.BytesIO(body),mode='r:gz') as archive:
        members=archive.getmembers()
        if len(members)!=len(FILES) or {m.name for m in members}!=FILES or any(not m.isfile() or m.size>2000000 for m in members):raise ValueError('Invalid Windows archive')
        path.mkdir();(path/'windows').mkdir()
        for member in members:(path/member.name).write_bytes(archive.extractfile(member).read())
    import subprocess
    subprocess.run([sys.executable,'-m','compileall','-q',str(path)],check=True,timeout=30)
    subprocess.run([sys.executable,'-c','import sys;sys.path.insert(0,sys.argv[1]);import backend,platform_support,runner',str(path/'windows')],cwd=path/'windows',check=True,timeout=30,capture_output=True)


class Updater:
    def __init__(self,root=ROOT):
        self.root=Path(root);self.state=self.root/'state';self.path=self.state/'update-status.json';self.status=json.loads(self.path.read_text()) if self.path.exists() else {}
        self.identity=json.loads((self.state/'identity.json').read_text());self.config=json.loads((self.root/'config'/'updater.json').read_text())
    def record(self,state,detail='',**fields):self.status.update(state=state,detail=detail,**fields);save(self.path,self.status)
    def report(self):
        try:
            identity=self.identity;base=identity['server'].rstrip('/')
            if not base.startswith('https://') and not (base.startswith('http://') and identity.get('allow_http') is True):raise ValueError('Invalid application endpoint')
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args):return None
            handlers=[NoRedirect,urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=identity.get('ca')))]
            body={k:self.status.get(k) for k in ('state','installed','available','checked','detail','automatic','handled_request')}
            req=urllib.request.Request(base+'/api/agent/updater',data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+identity['credential']})
            with urllib.request.build_opener(*handlers).open(req,timeout=10) as reply:return json.loads(reply.read(8192)).get('request')
        except Exception:return None
    def task(self,action):
        verb='Stop-ScheduledTask' if action=='stop' else 'Start-ScheduledTask'
        ps(verb+" -TaskName 'AITicketAgent'",timeout=15)
        if action=='stop':
            # Scheduler stop must complete before replacing a running release.
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if ps("(Get-ScheduledTask -TaskName 'AITicketAgent').State.ToString()")!='Running':return
                time.sleep(1)
            raise ValueError('Agent task did not stop')
    def healthy(self,version,since):
        try:
            health=json.loads((self.state/'health.json').read_text());return health['version']==version and health['at']>=since
        except (OSError,ValueError,KeyError):return False
    def rollback(self):
        self.task('stop');activate(self.root,self.status['previous']);self.task('start')
        self.record('rolled_back','Previous agent restored; waiting for a newer corrective release.',installed=self.status.get('previous_version','unknown'),failed_release=self.status.get('available'))
    def run(self):
        with (self.state/'updater.lock').open('a') as lock:
            try:locks.flock(lock,locks.LOCK_EX|locks.LOCK_NB)
            except BlockingIOError:return
            request=self.report();self.status.update(checked=time.time(),automatic=self.config.get('automatic',True))
            try:
                if self.status.get('state')=='installing':
                    with (self.state/'execution.lock').open('a') as recovery:
                        locks.flock(recovery,locks.LOCK_EX);self.rollback()
                doc=verify(download(FEED,65536),self.root/'release-public.pem')
                if doc['published']<self.status.get('highest_published',0):raise ValueError('Older release rejected')
                self.status.update(highest_published=doc['published'],available=doc['version'])
                if self.status.get('installed')==doc['version']:self.record('current','Windows agent is up to date.',handled_request=request);return
                if self.status.get('failed_release')==doc['version']:self.record('rolled_back','This release failed verification; waiting for a newer release.',handled_request=request);return
                if not request and not self.config.get('automatic',True):self.record('available','Automatic updates paused.');return
                bucket=int(hashlib.sha256(self.identity['agent_id'].encode()).hexdigest()[:8],16)%100
                if not request and time.time()<doc['published']+(0 if bucket<10 else doc['rollout_minutes']*60):self.record('scheduled','Staged update scheduled.');return
                body=download(doc['url'],20000000)
                if hashlib.sha256(body).hexdigest()!=doc['sha256']:raise ValueError('Windows archive checksum failed')
                with tempfile.TemporaryDirectory(dir=self.root/'releases') as temp:
                    stage=Path(temp)/'bundle';extract(body,stage)
                    with (self.state/'execution.lock').open('a') as work:
                        try:locks.flock(work,locks.LOCK_EX|locks.LOCK_NB)
                        except BlockingIOError:self.record('waiting','Waiting for active agent work.');return
                        identity=json.loads((self.state/'identity.json').read_text())
                        if any(r.get('state')=='running' for r in identity.get('command_ledger',{}).values()):self.record('waiting','Waiting for saved command results.');return
                        previous=current(self.root);destination=self.root/'releases'/doc['version']
                        if destination.exists():
                            if any((destination/name).read_bytes()!=(stage/name).read_bytes() for name in FILES):raise ValueError('Release directory collision')
                        else:shutil.move(stage,destination)
                        self.record('installing','Verifying new Windows agent.',previous=str(previous),previous_version=self.status.get('installed','unknown'))
                        self.task('stop');activate(self.root,destination);since=time.time();self.task('start')
                    deadline=time.monotonic()+120
                    while time.monotonic()<deadline and not self.healthy(doc['version'],since):time.sleep(2)
                    if self.healthy(doc['version'],since):self.record('updated','Authenticated Windows heartbeat verified.',installed=doc['version'],handled_request=request)
                    else:self.rollback();self.status['handled_request']=request
            except Exception:
                if self.status.get('state')=='installing':
                    try:self.rollback()
                    except Exception:self.record('failed','Update recovery failed; inspect the updater log.')
                else:self.record('failed','Windows update check or validation failed; inspect connectivity and release configuration.')
                self.status['handled_request']=request
            finally:save(self.path,self.status);self.report()

if __name__=='__main__':Updater().run()
