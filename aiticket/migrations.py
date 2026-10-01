"""Ordered schema upgrades; each upgrade and its version marker commit together."""
CURRENT_VERSION = 3
MIGRATIONS = {
    3: (
        'ALTER TABLE checks ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1',
        'CREATE TABLE proxmox_clusters(id TEXT PRIMARY KEY,name TEXT NOT NULL)',
        '''CREATE TABLE proxmox_connections(id TEXT PRIMARY KEY,cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id),name TEXT NOT NULL,url TEXT NOT NULL UNIQUE,token_id TEXT NOT NULL,token_secret TEXT NOT NULL,ca TEXT,last_test TEXT,last_discovery REAL)''',
        '''CREATE TABLE proxmox_objects(id TEXT PRIMARY KEY,cluster_id TEXT NOT NULL REFERENCES proxmox_clusters(id),kind TEXT NOT NULL,object_key TEXT NOT NULL,generation INTEGER NOT NULL,name TEXT NOT NULL,node TEXT,status TEXT,template INTEGER NOT NULL,present INTEGER NOT NULL,last_seen REAL NOT NULL,machine_id TEXT REFERENCES machines(id),check_id TEXT REFERENCES checks(id),UNIQUE(cluster_id,kind,object_key,generation))''',
        "CREATE UNIQUE INDEX present_proxmox_object ON proxmox_objects(cluster_id,kind,object_key) WHERE present=1",
    ),
    2: (
        '''CREATE TABLE audit(id TEXT PRIMARY KEY, at REAL NOT NULL, actor TEXT NOT NULL,
           action TEXT NOT NULL, target TEXT NOT NULL, details TEXT NOT NULL)''',
        'CREATE INDEX audit_at ON audit(at)',
        'CREATE INDEX incident_history ON incidents(first_seen, severity, status)',
        'CREATE INDEX observation_check_at ON observations(check_id,at)',
        "CREATE TRIGGER timeline_no_update BEFORE UPDATE ON timeline BEGIN SELECT RAISE(ABORT,'Timeline is immutable'); END",
        "CREATE TRIGGER timeline_no_delete BEFORE DELETE ON timeline BEGIN SELECT RAISE(ABORT,'Timeline is immutable'); END",
        "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'Audit is immutable'); END",
        "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'Audit is immutable'); END",
    ),
}


def upgrade(connection):
    connection.execute('BEGIN IMMEDIATE')
    versions = [r[0] for r in connection.execute('SELECT version FROM schema_version')]
    if len(versions) > 1:
        raise RuntimeError('Invalid schema version markers; manual review required.')
    version = versions[0] if versions else 1
    if version > CURRENT_VERSION:
        raise RuntimeError('Database is newer than this application; refusing to start.')
    for next_version in range(version + 1, CURRENT_VERSION + 1):
        for statement in MIGRATIONS[next_version]:
            connection.execute(statement)
    connection.execute('DELETE FROM schema_version')
    connection.execute('INSERT INTO schema_version VALUES(?)', (CURRENT_VERSION,))
