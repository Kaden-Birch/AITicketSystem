import contextlib
import json
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = '''
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES(1);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS machines(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT REFERENCES machines(id), created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS checks(id TEXT PRIMARY KEY, machine_id TEXT NOT NULL REFERENCES machines(id), name TEXT NOT NULL, kind TEXT NOT NULL, config TEXT NOT NULL, interval INTEGER NOT NULL, failures INTEGER NOT NULL DEFAULT 0, successes INTEGER NOT NULL DEFAULT 0, fail_after INTEGER NOT NULL DEFAULT 3, recover_after INTEGER NOT NULL DEFAULT 2, severity TEXT NOT NULL DEFAULT 'medium', health TEXT NOT NULL DEFAULT 'unknown', next_run REAL NOT NULL DEFAULT 0, lease_until REAL, lease_token TEXT, maintenance_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, check_id TEXT NOT NULL REFERENCES checks(id), at REAL NOT NULL, health TEXT NOT NULL, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, machine_id TEXT NOT NULL REFERENCES machines(id), check_id TEXT NOT NULL REFERENCES checks(id), severity TEXT NOT NULL, status TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL, report TEXT NOT NULL, closed REAL);
CREATE UNIQUE INDEX IF NOT EXISTS active_incident ON incidents(check_id) WHERE closed IS NULL;
CREATE TABLE IF NOT EXISTS timeline(id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), at REAL NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), event_key TEXT NOT NULL UNIQUE, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL, lease_until REAL, lease_token TEXT, last_error TEXT, created REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS enrollments(digest TEXT PRIMARY KEY, machine_id TEXT NOT NULL REFERENCES machines(id), expires REAL NOT NULL, used REAL);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, machine_id TEXT NOT NULL UNIQUE REFERENCES machines(id), credential_digest TEXT NOT NULL UNIQUE, revoked INTEGER NOT NULL DEFAULT 0, last_seen REAL, address TEXT, version TEXT, telemetry TEXT);
CREATE TABLE IF NOT EXISTS agent_events(agent_id TEXT NOT NULL REFERENCES agents(id), event_id TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(agent_id,event_id));
CREATE TABLE IF NOT EXISTS login_attempts(address TEXT PRIMARY KEY, failures INTEGER NOT NULL, blocked_until REAL NOT NULL);
'''


def uid():
    return str(uuid.uuid4())


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as c:
            c.executescript(SCHEMA)

    @contextlib.contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
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

    def setting(self, key, default=None):
        with self.connect() as c:
            row = c.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def save(self, key, value):
        with self.connect() as c:
            c.execute('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, json.dumps(value)))

    def rows(self, sql, args=()):
        with self.connect() as c:
            return [dict(r) for r in c.execute(sql, args)]

    @staticmethod
    def timeline(c, incident, kind, text, actor='monitor', now=None):
        c.execute('INSERT INTO timeline VALUES(?,?,?,?,?,?)', (uid(), incident, now or time.time(), actor, kind, text))
