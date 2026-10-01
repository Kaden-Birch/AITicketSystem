"""Ordered schema upgrades; each upgrade and its version marker commit together."""
CURRENT_VERSION = 2
MIGRATIONS = {
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
