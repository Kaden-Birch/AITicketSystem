import argparse
import getpass
import os
import secrets
import threading
from pathlib import Path
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash
from .db import Store
from .security import Vault


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'serve', 'worker', 'reset-password', 'rotate-key'])
    parser.add_argument('--data', default=os.environ.get('AITICKET_DATA', 'data'))
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=8080, type=int)
    parser.add_argument('--new-key', help='New, nonexistent key file for offline rotation')
    args = parser.parse_args()
    directory = Path(args.data)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = Path(os.environ.get('AITICKET_KEY_FILE', str(directory / 'encryption.key')))
    if args.command == 'init':
        store = Store(directory / 'app.db')
        if store.setting('admin_hash'):
            raise SystemExit('Already initialized; refusing to reset credentials.')
        password = getpass.getpass('Administrator password (at least 12 characters): ')
        if len(password) < 12 or password != getpass.getpass('Confirm password: '):
            raise SystemExit('Password is too short or confirmation does not match.')
        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as f:
                f.write(Fernet.generate_key())
        vault = Vault(key_path)
        store.save('session_secret', vault.encrypt(secrets.token_urlsafe(48)))
        store.save('admin_hash', generate_password_hash(password))
        os.chmod(directory / 'app.db', 0o600)
        print('Initialized. Protect the encryption key separately from the database.')
        return
    store = Store(directory / 'app.db')
    vault = Vault(key_path)
    if args.command == 'reset-password':
        from .administration import change_password
        password = getpass.getpass('New administrator password: ')
        if password != getpass.getpass('Confirm password: '):
            raise SystemExit('Password confirmation does not match.')
        change_password(store, password, actor='console')
        with store.connect() as c:
            c.execute('DELETE FROM login_attempts')
        print('Password reset. Existing administrator sessions are invalidated.')
        return
    if args.command == 'rotate-key':
        if not args.new_key:
            raise SystemExit('Stop app and workers first; provide --new-key pointing to a new file.')
        from .administration import rotate_key
        rotate_key(store, vault, args.new_key)
        print('Database reencrypted. Set AITICKET_KEY_FILE to the new key before restarting. Retain old key with old backups.')
        return
    from .worker import run
    stop = threading.Event()
    if args.command == 'worker':
        try:
            run(store, vault, stop)
        except KeyboardInterrupt:
            stop.set()
    else:
        from .app import create_app
        from waitress import serve
        thread = threading.Thread(target=run, args=(store, vault, stop), daemon=True)
        thread.start()
        try:
            serve(create_app(directory), host=args.host, port=args.port, threads=4)
        finally:
            stop.set()
            thread.join(timeout=15)


if __name__ == '__main__':
    main()
