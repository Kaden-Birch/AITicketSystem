"""Ordered schema upgrades; each upgrade and its version marker commit together."""
CURRENT_VERSION = 9
MIGRATIONS = {
    9: (
        "ALTER TABLE ai_jobs ADD COLUMN mode TEXT NOT NULL DEFAULT 'triage'",
        'ALTER TABLE ai_jobs ADD COLUMN request_id TEXT',
        'ALTER TABLE ai_jobs ADD COLUMN request_fingerprint TEXT',
        'CREATE UNIQUE INDEX ai_request_identity ON ai_jobs(request_id) WHERE request_id IS NOT NULL',
        """CREATE TABLE ai_messages(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),job_id TEXT NOT NULL REFERENCES ai_jobs(id),role TEXT NOT NULL,text TEXT NOT NULL,created REAL NOT NULL,UNIQUE(job_id,role))""",
        'CREATE INDEX ai_messages_incident ON ai_messages(incident_id,created)',
        "CREATE TRIGGER ai_messages_no_update BEFORE UPDATE ON ai_messages BEGIN SELECT RAISE(ABORT,'Conversation is immutable'); END",
        "CREATE TRIGGER ai_messages_no_delete BEFORE DELETE ON ai_messages BEGIN SELECT RAISE(ABORT,'Conversation is immutable'); END",
        'CREATE INDEX ai_calls_job ON ai_calls(job_id,created)',
    ),
    8: (
        """CREATE TABLE ai_jobs(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,model TEXT NOT NULL,allowance INTEGER NOT NULL,max_calls INTEGER NOT NULL,evidence TEXT NOT NULL,credential_digest TEXT NOT NULL,credential TEXT NOT NULL,endpoint TEXT NOT NULL,bridge_secret TEXT NOT NULL,next_attempt REAL NOT NULL,lease_until REAL,lease_token TEXT,attempts INTEGER NOT NULL DEFAULT 0,summary TEXT,error TEXT,completed REAL)""",
        'CREATE INDEX ai_job_queue ON ai_jobs(state,next_attempt)',
        "CREATE UNIQUE INDEX ai_incident_active ON ai_jobs(incident_id) WHERE state IN ('pending','dispatching','running','unknown')",
        """CREATE TABLE ai_calls(id TEXT PRIMARY KEY,job_id TEXT NOT NULL REFERENCES ai_jobs(id),created REAL NOT NULL,state TEXT NOT NULL,input_reserved INTEGER NOT NULL,output_reserved INTEGER NOT NULL,cost_reserved INTEGER NOT NULL,input_tokens INTEGER,output_tokens INTEGER,cached_tokens INTEGER,cost_actual INTEGER,prices TEXT NOT NULL)""",
        'CREATE INDEX ai_call_usage ON ai_calls(created,job_id)',
    ),
    7: (
        'CREATE INDEX incident_observation_lookup ON incident_observations(observation_id)',
        'CREATE INDEX agent_event_retention ON agent_events(at)',
    ),
    6: (
        "ALTER TABLE incidents ADD COLUMN severity_floor TEXT NOT NULL DEFAULT 'info'",
        'ALTER TABLE incidents ADD COLUMN silence_until REAL NOT NULL DEFAULT 0',
        '''CREATE TABLE maintenance_windows(id TEXT PRIMARY KEY,name TEXT NOT NULL,machine_id TEXT REFERENCES machines(id),kind TEXT NOT NULL,timezone TEXT NOT NULL,start REAL,end REAL,weekday INTEGER,start_minute INTEGER,end_minute INTEGER,enabled INTEGER NOT NULL DEFAULT 1)''',
    ),
    5: (
        "ALTER TABLE agents ADD COLUMN capabilities TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE agents ADD COLUMN sampled_at REAL",
        '''CREATE TABLE diagnostic_jobs(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL REFERENCES agents(id),incident_id TEXT NOT NULL REFERENCES incidents(id),operation TEXT NOT NULL,parameters TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,lease_until REAL,lease_token TEXT,result TEXT,completed REAL)''',
        'CREATE INDEX diagnostic_agent_queue ON diagnostic_jobs(agent_id,state,created)',
    ),
    4: (
        "ALTER TABLE checks ADD COLUMN first_failure_at REAL",
        "ALTER TABLE incidents ADD COLUMN condition_key TEXT NOT NULL DEFAULT ''",
        "UPDATE incidents SET condition_key='check:' || check_id",
        'CREATE TABLE incident_sources(incident_id TEXT NOT NULL REFERENCES incidents(id),check_id TEXT NOT NULL REFERENCES checks(id),report TEXT NOT NULL,PRIMARY KEY(incident_id,check_id))',
        'INSERT INTO incident_sources SELECT id,check_id,report FROM incidents',
        'CREATE TABLE incident_observations(incident_id TEXT NOT NULL REFERENCES incidents(id),observation_id TEXT NOT NULL REFERENCES observations(id),PRIMARY KEY(incident_id,observation_id))',
        'CREATE TABLE incident_links(left_id TEXT NOT NULL REFERENCES incidents(id),right_id TEXT NOT NULL REFERENCES incidents(id),reason TEXT NOT NULL,PRIMARY KEY(left_id,right_id))',
    ),
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
