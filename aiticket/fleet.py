"""Administrator fleet tasks reuse the durable host command ledger."""
import base64,json,re,shlex,time,uuid
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from .db import uid


def name(value):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',value): raise ValueError('Use a Linux account/group name: lowercase letters, digits, underscore or hyphen.')
    return value


def generate(store,vault,label,passphrase=''):
    if not label.strip() or len(label)>100: raise ValueError('Provide a key name up to 100 characters.')
    if len(passphrase)>500:raise ValueError('Passphrase must be at most 500 characters.')
    key=ed25519.Ed25519PrivateKey.generate()
    encryption=serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,encryption).decode()
    public=key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
    identifier=uid()
    with store.connect() as c:
        c.execute('INSERT INTO fleet_keys VALUES(?,?,?,?,?)',(identifier,label,public,vault.encrypt(private),time.time()))
        store.audit(c,'fleet.key_generated',identifier,{'label':label})
    return identifier


def command(store,values):
    kind=values.get('kind');user=name(values.get('username','')) if kind in ('user','key','revoke') else None
    if kind=='script':
        script=values.get('script','')
        if not script.strip() or len(script)>14000: raise ValueError('Script must contain 1–14000 characters.')
        return script
    if kind=='packages':
        packages=values.get('packages','').split()
        if not packages or any(not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,100}',p) for p in packages): raise ValueError('Provide Ubuntu/Debian package names separated by spaces.')
        return 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -- '+ ' '.join(map(shlex.quote,packages))
    if kind not in ('user','key','revoke'): raise ValueError('Choose a fleet task.')
    groups=[name(x.strip()) for x in values.get('groups','').split(',') if x.strip()] if kind=='user' else []
    access=values.get('access','standard')
    if access not in ('standard','administrator'): raise ValueError('Choose standard or administrator access.')
    if access=='administrator' and kind=='user':groups.append('sudo')
    public=None
    if values.get('key_id'):
        rows=store.rows('SELECT public FROM fleet_keys WHERE id=?',(values['key_id'],))
        if not rows: raise ValueError('Unknown SSH key.')
        public=rows[0]['public']
    if kind in ('key','revoke') and not public:raise ValueError('Select an SSH key.')
    payload={'kind':kind,'user':user,'groups':groups,'public':public}
    # Agent OS privileges apply; no sudo bypass or passwordless administrator grant.
    source='''import json,pwd,grp,os,stat,subprocess,base64
p=json.loads(base64.b64decode(PAYLOAD))
for group in p['groups']: grp.getgrnam(group)
try: account=pwd.getpwnam(p['user']); exists=True
except KeyError: exists=False
if p['kind']=='user':
    if exists: raise SystemExit('Account already exists; preserved without modification')
    subprocess.run(['useradd','--create-home','--shell','/bin/bash']+(['--groups',','.join(p['groups'])] if p['groups'] else [])+[p['user']],check=True)
    account=pwd.getpwnam(p['user'])
elif not exists: raise SystemExit('Account does not exist')
if p['public']:
    directory=os.path.join(account.pw_dir,'.ssh'); path=os.path.join(directory,'authorized_keys')
    if os.path.islink(directory) or os.path.islink(path): raise SystemExit('Refusing symlink SSH paths')
    os.makedirs(directory,mode=0o700,exist_ok=True)
    os.chown(directory,account.pw_uid,account.pw_gid); os.chmod(directory,0o700)
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise SystemExit('Authorized keys must be a regular file')
        lines=f.read().splitlines(); key=p['public'].split()[:2]
        if p['kind']=='revoke': lines=[line for line in lines if not any(line.split()[i:i+2]==key for i in range(len(line.split())))]
        elif not any(line.split()[i:i+2]==key for line in lines for i in range(len(line.split()))): lines.append(p['public'])
        f.seek(0); f.write('\\n'.join(lines)+'\\n'); f.truncate(); f.flush(); os.fsync(f.fileno())
        os.fchown(f.fileno(),account.pw_uid,account.pw_gid); os.fchmod(f.fileno(),0o600)
print('Fleet task completed for',p['user'])
'''.replace('PAYLOAD',repr(base64.b64encode(json.dumps(payload).encode()).decode()))
    encoded=base64.b64encode(source.encode()).decode()
    return 'python3 -c '+shlex.quote("import base64; exec(base64.b64decode("+repr(encoded)+"))")


def launch(store,vault,values,targets):
    from .commands import queue
    if not values.get('label','').strip() or len(values['label'])>100:raise ValueError('Provide a task name up to 100 characters.')
    targets=list(dict.fromkeys(targets))
    if not targets or len(targets)>200: raise ValueError('Select between 1 and 200 hosts.')
    available={r['id'] for r in store.rows("SELECT id FROM machines WHERE id NOT LIKE 'unifi:%' AND id NOT LIKE 'unifi-device:%'")}
    if set(targets)-available: raise ValueError('Fleet targets must be enrolled hosts, not network appliances.')
    text=command(store,values);identifier=values.get('fleet_id') or uid()
    try:uuid.UUID(identifier)
    except (ValueError,TypeError):raise ValueError('Invalid fleet submission ID.')
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        previous=c.execute('SELECT * FROM fleet_jobs WHERE id=?',(identifier,)).fetchone()
        if previous:
            old_targets={r[0] for r in c.execute('SELECT machine_id FROM fleet_targets WHERE job_id=?',(identifier,))}
            if vault.decrypt(previous['command'])!=text or old_targets!=set(targets):raise ValueError('Fleet submission ID already has different parameters.')
            return identifier
        definition={k:values.get(k,'') for k in ('label','kind','username','key_id','access','groups','packages','script')}
        c.execute('INSERT INTO fleet_jobs VALUES(?,?,?,?,?,?)',(identifier,values.get('label','Fleet task')[:100],values['kind'],time.time(),vault.encrypt(text),vault.encrypt(json.dumps(definition))))
        for machine in targets:c.execute('INSERT INTO fleet_targets VALUES(?,?,?,?,?)',(identifier,machine,uid(),'queued',''))
        store.audit(c,'fleet.created',identifier,{'targets':targets,'kind':values['kind']})
    for row in store.rows('SELECT * FROM fleet_targets WHERE job_id=?',(identifier,)):
        try:
            queue(store,vault,row['machine_id'],text,row['command_id']);state='submitted';error=''
        except ValueError as exc:state='blocked';error=str(exc)
        with store.connect() as c:c.execute('UPDATE fleet_targets SET state=?,error=? WHERE job_id=? AND machine_id=?',(state,error,identifier,row['machine_id']))
    return identifier
