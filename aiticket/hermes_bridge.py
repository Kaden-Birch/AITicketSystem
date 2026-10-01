"""Companion service on the Hermes VM, using a durable, non-replaying job ledger."""
import argparse
import contextlib
import json
import os
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from cryptography.fernet import Fernet
from flask import Flask, abort, request
from .ai import authenticate
from .security import Vault, hermes_headers, validate_url


def isolated_environment(source, home, gateway, ca=None):
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(home), 'HERMES_HOME': str(home),
           'PYTHONPATH': str(Path(__file__).resolve().parent.parent)+os.pathsep+str(source),
           'AITICKET_HERMES_SOURCE': str(source), 'AITICKET_GATEWAY': gateway,
           'PYTHONUNBUFFERED': '1', 'HERMES_SINGLE_QUERY_SESSION': '1'}
    if ca:
        env.update(SSL_CERT_FILE=ca, REQUESTS_CA_BUNDLE=ca)
    return env


class Ledger:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = self.directory / 'bridge.key'
        try:
            fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as f:
                f.write(Fernet.generate_key())
                f.flush()
                os.fsync(f.fileno())
        self.vault = Vault(key)
        self.path = self.directory / 'bridge.db'
        with self.connect() as c:
            c.execute('CREATE TABLE IF NOT EXISTS executions(id TEXT PRIMARY KEY,payload_hash TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL,summary TEXT NOT NULL DEFAULT \'\',expires REAL NOT NULL)')
            # Single bridge process owns this ledger. An interrupted run is never restarted.
            c.execute("UPDATE executions SET state='interrupted',summary='Bridge restarted during execution; no automatic replay.' WHERE state='running'")
        os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('PRAGMA synchronous=FULL')
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def accept(self, job):
        import hashlib
        if not isinstance(job, dict) or set(job) != {'version','execution_id','model','evidence','credential','max_calls','expires'} or job['version'] != 1:
            raise ValueError('Invalid execution envelope.')
        try:
            uuid.UUID(job['execution_id'])
        except (ValueError, TypeError, AttributeError):
            raise ValueError('Invalid execution identity.')
        if any(not isinstance(job[k], str) for k in ('model','evidence','credential')) or not 1 <= len(job['model']) <= 100 or len(job['evidence'])>16000 or not 16 <= len(job['credential']) <= 2048 or type(job['max_calls']) is not int or not 1 <= job['max_calls'] <= 100 or type(job['expires']) not in (int,float) or not time.time() < job['expires'] <= time.time()+3700:
            raise ValueError('Execution parameters exceed limits.')
        payload = json.dumps(job, separators=(',', ':'), sort_keys=True)
        fingerprint = hashlib.sha256(payload.encode()).hexdigest()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            previous = c.execute('SELECT * FROM executions WHERE id=?', (job['execution_id'],)).fetchone()
            if previous and previous['payload_hash'] != fingerprint:
                raise ValueError('Execution identity was reused with different parameters.')
            if not previous:
                if c.execute("SELECT count(*) FROM executions WHERE state IN ('accepted','running')").fetchone()[0]>=10:
                    raise ValueError('Bridge queue is full.')
                c.execute("INSERT INTO executions(id,payload_hash,payload,state,expires) VALUES(?,?,?,'accepted',?)", (job['execution_id'], fingerprint, self.vault.encrypt(payload), job['expires']))
        return self.status(job['execution_id'])

    def status(self, execution_id):
        with self.connect() as c:
            row = c.execute('SELECT id,state,summary FROM executions WHERE id=?', (execution_id,)).fetchone()
            return {'execution_id': execution_id, 'state': row['state'] if row else 'not_found', 'summary': row['summary'] if row else ''}

    def claim(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute("UPDATE executions SET state='failed',summary='Execution expired before dispatch.' WHERE state='accepted' AND expires<=?", (time.time(),))
            row = c.execute("SELECT * FROM executions WHERE state='accepted' ORDER BY rowid LIMIT 1").fetchone()
            if not row:
                return None
            c.execute("UPDATE executions SET state='running' WHERE id=?", (row['id'],))
            return json.loads(self.vault.decrypt(row['payload']))

    def complete(self, execution_id, result):
        with self.connect() as c:
            c.execute("UPDATE executions SET state=?,summary=? WHERE id=? AND state='running'", (result['state'], result['summary'][:16000], execution_id))


def child_command(python, argument):
    return [python, '-m', 'aiticket.hermes_runner', argument]


def check_adapter(python, source, gateway, ca=None):
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        (home/'config.yaml').write_text('model:\n  streaming: false\n')
        try:
            result = subprocess.run(child_command(python, '--check'), env=isolated_environment(source, home, gateway, ca), cwd=home, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


def run_child(job, python, source, gateway, ca=None):
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        (home/'config.yaml').write_text('model:\n  streaming: false\n')
        input_path, result_path = home/'input.json', home/'result.json'
        input_path.write_text(json.dumps(job))
        os.chmod(input_path, 0o600)
        command = child_command(python, str(input_path))+[str(result_path)]
        process = subprocess.Popen(command, env=isolated_environment(source, home, gateway, ca), cwd=home, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=max(1, min(180, job['expires']-time.time())))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return {'state': 'interrupted', 'summary': 'Hermes exceeded the elapsed-time limit. In-flight provider usage may be unknown.'}
        if process.returncode or not result_path.exists() or result_path.stat().st_size>80000:
            return {'state': 'failed', 'summary': 'Hermes adapter could not produce a compatible result.'}
        result = json.loads(result_path.read_text())
        if not isinstance(result, dict) or result.get('state') not in ('completed','failed') or not isinstance(result.get('summary'), str):
            raise ValueError('Invalid runner result.')
        return result


def create_bridge(ledger, secret, compatible=False):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 65536

    @app.before_request
    def guard():
        if not authenticate(secret, request.get_data(), request.headers):
            abort(401)

    def signed(document):
        body = json.dumps(document, separators=(',', ':'), sort_keys=True).encode()
        response = app.response_class(body, mimetype='application/json')
        response.headers.update(hermes_headers(secret, body, document.get('execution_id', 'capabilities')))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/v1/capabilities')
    def capabilities():
        return signed({'version': 1, 'compatible': compatible, 'tools': [], 'model_gateway': True, 'workspace_modes': ['advice', 'exploration','recovery_proposal']})

    @app.post('/v1/executions')
    def accept():
        if not compatible:
            abort(503)
        try:
            return signed(ledger.accept(request.get_json()))
        except ValueError:
            abort(400)

    @app.get('/v1/executions/<execution_id>')
    def status(execution_id):
        return signed(ledger.status(execution_id))

    return app


def run(ledger, python, source, gateway, stop, ca=None):
    while not stop.is_set():
        job = ledger.claim()
        if job:
            try:
                result = run_child(job, python, source, gateway, ca)
            except Exception:
                result = {'state': 'interrupted', 'summary': 'Bridge execution failed; no automatic replay.'}
            ledger.complete(job['execution_id'], result)
        stop.wait(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', required=True)
    parser.add_argument('--secret-file', required=True)
    parser.add_argument('--hermes-source', required=True)
    parser.add_argument('--hermes-python', required=True)
    parser.add_argument('--gateway', required=True, help='Verified HTTPS application IP URL')
    parser.add_argument('--ca')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8090)
    args = parser.parse_args()
    validate_url(args.gateway, ('https',))
    secret = Path(args.secret_file).read_text().strip()
    if len(secret)<16:
        raise SystemExit('Use a bridge secret of at least 16 characters.')
    # flock prevents a second process from marking another process's live job interrupted.
    import fcntl
    Path(args.data).mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = open(Path(args.data)/'bridge.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    ledger = Ledger(args.data)
    compatible = check_adapter(args.hermes_python, args.hermes_source, args.gateway, args.ca)
    stop = threading.Event()
    worker = threading.Thread(target=run, args=(ledger,args.hermes_python,args.hermes_source,args.gateway,stop,args.ca), daemon=True)
    if compatible:
        worker.start()
    from waitress import serve
    try:
        serve(create_bridge(ledger, secret, compatible), host=args.host, port=args.port, threads=4)
    finally:
        stop.set()
        if compatible:
            worker.join(timeout=5)
        lock.close()


if __name__ == '__main__':
    main()
