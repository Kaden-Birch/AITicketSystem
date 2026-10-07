"""Local-first, independently retained SMB archives. SMB never holds a live SQLite file."""
import gzip
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from . import network_logs as logs
from .db import uid
from .smb_archive_io import metadata

PERIODS = [(7, '7 days'), (30, '1 month'), (180, '6 months'), (365, '12 months'), (0, 'Indefinitely')]
DEFAULTS = {'enabled': False, 'server': '', 'share': '', 'folder': '', 'username': '', 'domain': '',
            'encrypt': False, 'days': 365, 'buffer_mb': 256}


def validate(store, vault, values):
    previous = config(store)
    result = {**previous, **{k: values.get('smb_'+k, '').strip() for k in ('server', 'share', 'folder', 'username', 'domain')}}
    result.update(enabled=values.get('smb_enabled') == 'yes', encrypt=values.get('smb_encrypt') == 'yes')
    try:
        result['days'] = int(values.get('smb_days', 365))
        result['buffer_mb'] = int(values.get('smb_buffer_mb', 256))
    except ValueError: raise ValueError('Choose a retention period and a whole-number upload buffer size.')
    if result['days'] not in {p[0] for p in PERIODS} or not 16 <= result['buffer_mb'] <= 16384:
        raise ValueError('Choose a supported retention period and a 16–16,384 MB upload buffer.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}', result['server']):
        raise ValueError('Enter the SMB server IP or hostname, without a URL or share path.')
    if not re.fullmatch(r'[^\\/:*?"<>|\x00-\x1f]{1,80}', result['share']) or result['share'] in ('.', '..'):
        raise ValueError('Enter the share name only, for example Logs.')
    folder = result['folder'].replace('\\', '/').strip('/')
    if len(folder) > 240 or any(not part or part in ('.', '..') or re.search(r'[:*?"<>|\x00-\x1f]', part) for part in folder.split('/')) and folder:
        raise ValueError('Use a relative archive folder without parent-directory segments.')
    result['folder'] = folder
    if not result['username'] or len(result['username']) > 150 or len(result['domain']) > 150 or re.search(r'[\x00-\x1f]', result['username'] + result['domain']):
        raise ValueError('Enter a valid SMB username and optional domain.')
    password = values.get('smb_password', '')
    saved = store.setting('network_log_smb_secret', '')
    # Blank passwords can only retain credentials for the same account and destination.
    same = all(previous.get(k) == result.get(k) for k in ('server', 'share', 'username', 'domain'))
    if not password and not (saved and same):
        raise ValueError('Enter the SMB password. A changed server, share or account requires its password again.')
    if len(password) > 1024: raise ValueError('SMB password is too long.')
    result['namespace'] = previous.get('namespace') or uuid.uuid4().hex
    result['secret'] = vault.encrypt(password) if password else saved
    return result


def config(store):
    return {**DEFAULTS, **store.setting('network_log_smb', {})}


def save(store, result):
    values = dict(result); secret = values.pop('secret')
    store.save_many({'network_log_smb': values, 'network_log_smb_secret': secret,**({'telemetry_capture_enabled':True} if values['enabled'] else {})}, actor='administrator')


def connection(store, vault):
    result = config(store)
    result['password'] = vault.decrypt(store.setting('network_log_smb_secret', ''))
    return result


def submit(store, vault, kind, cfg, params=None):
    identifier = uid(); now = time.time()
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute("SELECT count(*) FROM log_archive_jobs WHERE state IN ('pending','running')").fetchone()[0] >= 4:
            raise ValueError('Archive work is already queued. Wait for it to finish before submitting another request.')
        cfg = dict(cfg)
        if 'secret' in cfg: cfg['password'] = vault.decrypt(cfg.pop('secret'))
        c.execute('INSERT INTO log_archive_jobs VALUES(?,?,?,?,?,?,?,?,?)',
                  (identifier, kind, json.dumps(params or {}), vault.encrypt(json.dumps(cfg)), 'pending', now, now, None, None))
        store.audit(c, 'network_logs.archive_'+kind, identifier)
    return identifier


def job(store, identifier):
    rows = store.rows('SELECT id,kind,params,state,created,updated,result,error FROM log_archive_jobs WHERE id=?', (identifier,))
    if not rows: return None
    row = rows[0]
    row['params'] = json.loads(row['params']); row['result'] = json.loads(row['result']) if row['result'] else {}
    return row


def archive_status(store):
    result = store.setting('network_log_archive_status', {})
    result['available'] = bool(result.get('heartbeat') and 0 <= time.time() - result['heartbeat'] < 120)
    return result


def operation(cfg, action, timeout=30, **kwargs):
    """Isolate network timeouts and SMB sessions from collection and web requests."""
    request = {'connection': cfg, 'operation': action, **kwargs}
    try:
        completed = subprocess.run([sys.executable, '-m', 'aiticket.smb_archive_io'], input=json.dumps(request),
                                   text=True, capture_output=True, timeout=timeout)
        result = json.loads(completed.stdout)
    except subprocess.TimeoutExpired:
        raise OSError('SMB request timed out. Local collection continues; pending uploads will retry.') from None
    except (ValueError, OSError):
        raise OSError('SMB worker could not complete the request. Check the archive service and test the connection.') from None
    if not result.get('ok'): raise OSError(result.get('error', 'SMB request failed.'))
    return result


def results_path(store, identifier):
    # Only UUIDs from our job table may select result paths.
    uuid.UUID(identifier)
    return Path(store.path).parent / 'log-archive-results' / (identifier + '.json')


def search_results(store, identifier, strict=False):
    task = job(store, identifier)
    if not task or task['kind'] != 'search' or task['state'] != 'complete': return []
    path = results_path(store, identifier)
    try:
        if path.stat().st_size > 8 * 1048576: raise ValueError('Search cache exceeds its size limit.')
        records = json.loads(path.read_text())
        if not isinstance(records,list) or any(not isinstance(r,dict) for r in records):raise ValueError('Invalid search cache.')
        if task['params'].get('dataset')=='telemetry':
            from .telemetry_archive import sanitize,validate_document
            if any(not validate_document(r) for r in records):raise ValueError('Invalid telemetry cache.')
            return sanitize(records)
        with store.connect() as c:
            return logs.decorate(c, records)
    except (OSError, ValueError, KeyError,TypeError):
        if strict:raise ValueError('Search cache is unavailable or invalid.')
        return []


def select_files(files, params):
    return sorted((item for item in files if item['end'] >= params['start'] and item['start'] <= params['end']),
                  key=lambda item: item['end'], reverse=True)


class Archiver:
    def __init__(self, store, vault, io=operation):
        self.store = store; self.vault = vault; self.io = io
        self.archive = logs.Archive(logs.database(store))
        self.directory = self.archive.path.parent / 'smb-transfer'
        self.directory.mkdir(exist_ok=True, mode=0o700)
        self.state = store.setting('network_log_archive_status', {})
        from .telemetry_archive import Exporter
        self.telemetry=Exporter(store,io,self.directory)
        self.next_upload = self.next_cleanup = self.next_storage = self.next_capacity = 0
        self.failures = 0
        self.configuration = hashlib.sha256(json.dumps(connection(store,vault),sort_keys=True).encode()).hexdigest()

    def publish(self, **values):
        from .telemetry_archive import status
        telemetry=status(self.store);backlog=self.archive.backlog()
        backlog['pending']+=(telemetry['pending'] or 0)
        backlog['pending_bytes']+=telemetry['pending_bytes']
        oldest=[t for t in (backlog.get('oldest_pending'),telemetry['oldest']) if t]
        backlog['oldest_pending']=min(oldest) if oldest else None
        successes=[t for t in (self.state.get('last_success'),self.store.setting('telemetry_archive_success',{}).get('at')) if t]
        if successes:self.state['last_success']=max(successes)
        self.state.update(heartbeat=time.time(), **values, **backlog,telemetry=telemetry)
        self.store.save('network_log_archive_status', self.state)

    def pending_batch(self):
        manifest = self.directory / 'pending.json'; compressed = self.directory / 'pending.jsonl.gz'
        if manifest.exists() and compressed.exists():
            try:
                data = json.loads(manifest.read_text())
                if hashlib.sha256(compressed.read_bytes()).hexdigest() == metadata(data['name'])['checksum']:
                    return data, compressed
            except (ValueError, KeyError, TypeError): pass
            raise OSError('Pending archive checksum failed. Keep the upload queue and inspect the archive service.')
        with self.archive.connect() as c:
            rows = c.execute('SELECT * FROM smb_outbox ORDER BY id LIMIT 1000').fetchall()
        selected = []; size = 0
        for row in rows:
            size += len(row['payload'].encode()) + 1
            if size > 8 * 1048576: break
            selected.append(row)
        if not selected: return None, None
        events = [json.loads(row['payload']) for row in selected]
        body = gzip.compress(('\n'.join(row['payload'] for row in selected)+'\n').encode(), mtime=0)
        checksum = hashlib.sha256(body).hexdigest()
        # Receipt time sets retention. Event bounds find delayed observations during historical searches.
        batch_id = hashlib.sha256(','.join(e['event_key'] for e in events).encode()).hexdigest()[:32]
        name = f"logs-{int(max(e['received'] for e in events))}-{int(min(e['at'] for e in events))}-{int(max(e['at'] for e in events))+1}-{batch_id}-{checksum}.jsonl.gz"
        data = {'name': name, 'keys': [e['event_key'] for e in events], 'ids': [r['id'] for r in selected]}
        temp = self.directory / 'building.gz'
        temp.write_bytes(body); os.chmod(temp, 0o600); temp.replace(compressed)
        temporary = self.directory / 'building.json'
        temporary.write_text(json.dumps(data)); os.chmod(temporary, 0o600); temporary.replace(manifest)
        return data, compressed

    def upload(self, cfg):
        target = hashlib.sha256(json.dumps({k:cfg[k] for k in ('server','share','folder','namespace')}, sort_keys=True).encode()).hexdigest()
        with self.archive.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            previous = c.execute("SELECT value FROM archive_meta WHERE key='smb_target'").fetchone()
            if not previous or previous['value'] != target:
                c.execute('UPDATE events SET archived=0')
                c.execute("INSERT INTO archive_meta VALUES('smb_target',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (target,))
        self.archive.enqueue_existing(cfg['buffer_mb'])
        data, compressed = self.pending_batch()
        if not data: return
        uploaded = self.io(cfg, 'upload', file=str(compressed), name=data['name'])
        with self.archive.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.executemany('UPDATE events SET archived=1 WHERE event_key=?', [(k,) for k in data['keys']])
            c.executemany('DELETE FROM smb_outbox WHERE event_key=?', [(k,) for k in data['keys']])
        # A crash before unlink is safe: retries use the same verified remote filename.
        (self.directory / 'pending.json').unlink(missing_ok=True)
        compressed.unlink(missing_ok=True)
        self.state.update(last_success=time.time(), uploaded_events=self.state.get('uploaded_events', 0)+len(data['keys']),
                          uploaded_bytes=self.state.get('uploaded_bytes', 0)+uploaded['bytes'], error=None)

    def cleanup(self, cfg):
        if not cfg['days']:
            self.next_cleanup = time.monotonic() + 300
            return
        cutoff = time.time() - cfg['days'] * 86400
        catalog = self.io(cfg, 'catalog', cutoff=cutoff)
        files = catalog['files']
        expired = [f['name'] for f in files if cfg['days'] and f['received'] < cutoff]
        if expired: self.io(cfg, 'delete', names=expired[:100])
        self.state.update(retention_pending=bool(catalog.get('truncated')), last_retention=time.time())
        self.next_cleanup = time.monotonic() + (30 if catalog.get('truncated') else 300)

    def process_job(self):
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute("SELECT * FROM log_archive_jobs WHERE state='pending' ORDER BY created LIMIT 1").fetchone()
            if not row: return False
            c.execute("UPDATE log_archive_jobs SET state='running',updated=? WHERE id=?", (time.time(), row['id']))
        try:
            cfg = json.loads(self.vault.decrypt(row['connection']))
            if row['kind'] == 'test': result = self.io(cfg, 'test')
            else:
                params = json.loads(row['params'])
                if params.get('ai_job'):
                    with self.store.connect() as c:
                        from .commands import ai_allowed
                        from .ticket_groups import machines
                        ai_job=ai_allowed(c,params['ai_job'])
                        if not ai_job or params['machine'] not in machines(c,ai_job['incident_id']):raise OSError('Archive search authorization expired or its target was removed.')
                if params.get('machine'):
                    params['bindings'] = self.store.rows('SELECT source_id,mac,machine_id FROM log_host_bindings')
                catalog = self.io(cfg, 'catalog', **({'dataset':'telemetry'} if params.get('dataset')=='telemetry' else {}), start=params['start'], end=params['end'])
                files = select_files(catalog['files'], params)
                path = results_path(self.store, row['id']); path.parent.mkdir(exist_ok=True, mode=0o700)
                maximum=min(100,max(1,int(params.get('max_files',100))))
                result = self.io(cfg, 'search', timeout=30 if params.get('ai_job') else 60, names=[f['name'] for f in files[:maximum]], params=params, file=str(path), **({'dataset':'telemetry'} if params.get('dataset')=='telemetry' else {}))
                if path.stat().st_size > 8 * 1048576:
                    path.unlink(); raise OSError('Search result exceeded its size limit. Narrow the time range.')
                os.chmod(path, 0o600)
                result['truncated'] = result.get('truncated', False) or len(files) > maximum or catalog.get('truncated', False)
            self.finish(row['id'], 'complete', result=result)
        except Exception as exc:
            if row['kind']=='search':
                results_path(self.store,row['id']).unlink(missing_ok=True)
            # io already sanitizes errors; other exceptions are not exposed.
            message = str(exc) if isinstance(exc, OSError) else 'Archive request failed. Check the connection and try again.'
            self.finish(row['id'], 'failed', error=message[:300])
        self.expire_jobs()
        return True

    def finish(self, identifier, state, result=None, error=None):
        with self.store.connect() as c:
            c.execute('UPDATE log_archive_jobs SET state=?,updated=?,result=?,error=?,connection=? WHERE id=?',
                      (state, time.time(), json.dumps(result or {}), error, '', identifier))

    def refresh_storage(self,cfg):
        from .archive_storage import identity
        target=identity(cfg);prior=self.store.setting('archive_storage',{})
        if not cfg.get('server'):return
        if prior.get('target')==target and time.monotonic()<self.next_storage:return
        try:
            result=self.io(cfg,'usage',timeout=15)
            self.store.save('archive_storage',{'target':target,'at':time.time(),**result})
            from .capacity_forecasts import record as capacity_record
            with self.store.connect() as c:
                if not result.get('archive_partial') and all(k in result for k in ('archive_bytes','total','available')):
                    capacity_record(c,'logs:smb:'+target,None,'smb_logs','SMB archive',time.time(),result['archive_bytes'],result['total'],result['available'])
            self.next_storage=time.monotonic()+300
        except OSError:
            self.store.save('archive_storage',{**(prior if prior.get('target')==target else {}),'target':target,'error':'SMB archive file usage could not be read. Check connectivity and share permissions.','attempted':time.time()})
            self.next_storage=time.monotonic()+60

    def step(self):
        from .capacity_forecasts import backfill,sample_local
        backfill(self.store)
        from .host_storage import backfill as backfill_hosts
        backfill_hosts(self.store)
        if time.monotonic()>=self.next_capacity:
            sample_local(self.store)
            self.next_capacity=time.monotonic()+300
        self.refresh_storage(connection(self.store,self.vault))
        self.publish()
        if config(self.store)['enabled']:self.telemetry.capture_dashboard()
        if self.process_job(): self.publish(); return
        cfg = connection(self.store, self.vault)
        token = hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
        if self.configuration != token:
            self.configuration = token
            self.next_upload = self.next_cleanup = self.failures = 0
            self.state.update(error=None, error_since=None, next_retry=None)
        if not cfg['enabled']: return
        if time.monotonic() < self.next_upload: return
        try:
            backlog = self.archive.backlog()
            # Small batches wait up to five minutes after the first successful upload.
            if not (self.state.get('last_success') and not backlog['waiting_local'] and backlog['pending'] < 1000 and backlog['oldest_pending'] and time.time()-backlog['oldest_pending'] < 300):
                self.upload(cfg)
            self.telemetry.step(cfg,force=False)
            if time.monotonic() >= self.next_cleanup: self.cleanup(cfg)
            self.failures = 0; self.state['error'] = None
            self.state['next_retry'] = None; self.state['error_since'] = None
            backlog = self.archive.backlog()
            self.next_upload = time.monotonic() + (1 if backlog['pending'] >= 1000 or backlog['waiting_local'] else 5)
        except OSError as exc:
            self.failures += 1
            delay = min(300, 15 * 2 ** min(self.failures-1, 5))
            self.next_upload = time.monotonic() + delay
            self.state.update(error=str(exc)[:300], error_since=self.state.get('error_since') or time.time(), next_retry=time.time()+delay)
        self.publish()

    def expire_jobs(self):
        rows = self.store.rows("SELECT id FROM log_archive_jobs WHERE created<? OR id IN (SELECT id FROM log_archive_jobs WHERE kind='search' AND state='complete' ORDER BY updated DESC LIMIT -1 OFFSET 8)", (time.time()-86400,))
        for row in rows: results_path(self.store, row['id']).unlink(missing_ok=True)
        with self.store.connect() as c:
            c.executemany("UPDATE log_archive_jobs SET state='expired',result=NULL,connection='' WHERE id=?", [(r['id'],) for r in rows])
            c.execute("DELETE FROM log_archive_jobs WHERE id IN (SELECT id FROM log_archive_jobs WHERE state NOT IN ('pending','running') ORDER BY created DESC LIMIT -1 OFFSET 50)")


def run(store, vault):
    # Only one archive process may acknowledge this durable queue, even if a service is duplicated.
    import fcntl
    lock = Path(logs.database(store)).parent / 'smb-archiver.lock'
    lock.parent.mkdir(exist_ok=True, parents=True)
    with lock.open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker = Archiver(store, vault); stopping = False
        def stop(*_):
            nonlocal stopping
            stopping = True
        for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, stop)
        with store.connect() as c:
            c.execute("UPDATE log_archive_jobs SET state='pending' WHERE state='running'")
        print('SMB log archiver running. Local collection is independent.', flush=True)
        last_expiry = 0
        while not stopping:
            try:
                worker.step()
                if time.monotonic()-last_expiry > 300:
                    worker.expire_jobs(); last_expiry = time.monotonic()
            except Exception:
                worker.state['error_since']=worker.state.get('error_since') or time.time()
                worker.state['error'] = 'Archive service could not complete its work. Check the service logs and test the connection.'
                try: worker.publish()
                except Exception: pass
                print('Archive worker unavailable; local collection continues.', flush=True)
            time.sleep(1)
