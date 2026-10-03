"""Ordered schema upgrades; each upgrade and its version marker commit together."""
CURRENT_VERSION = 33
MIGRATIONS = {
    33: (
        "CREATE TABLE IF NOT EXISTS fleet_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE COLLATE NOCASE)",
        "CREATE TABLE IF NOT EXISTS fleet_group_members(group_id TEXT NOT NULL REFERENCES fleet_groups(id) ON DELETE CASCADE,machine_id TEXT NOT NULL REFERENCES machines(id) ON DELETE CASCADE,PRIMARY KEY(group_id,machine_id))",
    ),
    32: (
        "CREATE TABLE health_rules(scope TEXT NOT NULL,metric TEXT NOT NULL,config TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(scope,metric))",
        "INSERT OR IGNORE INTO health_rules(scope,metric,config,enabled) SELECT machine_id,json_extract(config,'$.metric'),config,enabled FROM checks WHERE kind='agent_metric' AND json_extract(config,'$.metric') IS NOT NULL ORDER BY id",
    ),
    31: ("ALTER TABLE machines ADD COLUMN offline_expected INTEGER NOT NULL DEFAULT 0",),
    30: (
        "CREATE TABLE fleet_keys(id TEXT PRIMARY KEY,label TEXT NOT NULL,public TEXT NOT NULL,private TEXT,created REAL NOT NULL)",
        "CREATE TABLE fleet_jobs(id TEXT PRIMARY KEY,label TEXT NOT NULL,kind TEXT NOT NULL,created REAL NOT NULL,command TEXT NOT NULL,definition TEXT NOT NULL)",
        "CREATE TABLE fleet_targets(job_id TEXT NOT NULL REFERENCES fleet_jobs(id),machine_id TEXT NOT NULL REFERENCES machines(id),command_id TEXT NOT NULL UNIQUE,state TEXT NOT NULL,error TEXT NOT NULL,PRIMARY KEY(job_id,machine_id))",
    ),
    29: (
        "ALTER TABLE unifi_connections ADD COLUMN deleted REAL",
        "ALTER TABLE unifi_devices ADD COLUMN deleted REAL",
    ),
    28: (
        "CREATE TABLE unifi_devices(connection_id TEXT NOT NULL REFERENCES unifi_connections(id),device_id TEXT NOT NULL,machine_id TEXT NOT NULL UNIQUE REFERENCES machines(id),check_id TEXT NOT NULL,data TEXT NOT NULL,last_seen REAL NOT NULL,PRIMARY KEY(connection_id,device_id))",
    ),
    27: (
        "UPDATE ai_jobs SET state='cancelled',completed=strftime('%s','now'),lease_token=NULL,lease_until=NULL WHERE incident_id IN (SELECT id FROM incidents WHERE check_id IN (SELECT check_id FROM unifi_connections)) AND state IN ('pending','dispatching','running','unknown')",
        "UPDATE incident_control SET owner=CASE WHEN owner='ai' THEN 'available' ELSE owner END,generation=generation+1 WHERE incident_id IN (SELECT id FROM incidents WHERE check_id IN (SELECT check_id FROM unifi_connections))",
        "UPDATE command_jobs SET state=CASE WHEN state IN ('awaiting','pending') THEN 'cancelled' ELSE 'cancelling' END WHERE incident_id IN (SELECT id FROM incidents WHERE check_id IN (SELECT check_id FROM unifi_connections)) AND state IN ('awaiting','pending','dispatched','running')",
        "UPDATE proxmox_api_jobs SET state='cancelled' WHERE ai_job_id IN (SELECT id FROM ai_jobs WHERE incident_id IN (SELECT id FROM incidents WHERE check_id IN (SELECT check_id FROM unifi_connections))) AND state='awaiting'",
        "INSERT INTO machines(id,name,created) SELECT 'unifi:' || id,'UniFi ' || name,strftime('%s','now') FROM unifi_connections",
        "UPDATE checks SET machine_id=(SELECT 'unifi:' || id FROM unifi_connections WHERE check_id=checks.id),lease_token=NULL,lease_until=NULL,next_run=0 WHERE id IN (SELECT check_id FROM unifi_connections)",
        "UPDATE incidents SET machine_id=(SELECT 'unifi:' || id FROM unifi_connections WHERE check_id=incidents.check_id) WHERE check_id IN (SELECT check_id FROM unifi_connections)",
        "UPDATE unifi_connections SET machine_id='unifi:' || id",
    ),
    26: (
        "CREATE TABLE unifi_connections(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,url TEXT NOT NULL,secret TEXT NOT NULL,ca TEXT,insecure_tls INTEGER NOT NULL DEFAULT 0,site TEXT NOT NULL DEFAULT '',machine_id TEXT NOT NULL REFERENCES machines(id),ai_context INTEGER NOT NULL DEFAULT 0,check_id TEXT NOT NULL,snapshot TEXT)",
    ),
    25: (
        "CREATE TABLE metric_samples(entity_id TEXT NOT NULL,source TEXT NOT NULL,at REAL NOT NULL,metrics TEXT NOT NULL,PRIMARY KEY(entity_id,source,at))",
        "CREATE INDEX metric_samples_at ON metric_samples(at)",
    ),
    24: (
        "ALTER TABLE command_jobs ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 1",
        "UPDATE command_jobs SET requires_approval=0 WHERE machine_id IN (SELECT machine_id FROM command_policies WHERE approval='immediate')",
        "DROP TRIGGER command_immutable",
        "CREATE TRIGGER command_immutable BEFORE UPDATE OF machine_id,agent_id,incident_id,ai_job_id,command,fingerprint,policy_version,timeout,output_limit,created,expires,requires_approval ON command_jobs BEGIN SELECT RAISE(ABORT,'Command identity is immutable'); END",
    ),
    23: (
        "ALTER TABLE incident_control ADD COLUMN handling_mode TEXT NOT NULL DEFAULT 'automatic'",
        "UPDATE incident_control SET handling_mode='human' WHERE owner='user'",
        "CREATE TABLE work_sessions(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),job_id TEXT REFERENCES ai_jobs(id),actor TEXT NOT NULL,started REAL NOT NULL,ended REAL,outcome TEXT NOT NULL DEFAULT 'working',summary TEXT NOT NULL DEFAULT '')",
        "CREATE UNIQUE INDEX work_active ON work_sessions(incident_id,actor) WHERE ended IS NULL",
        "CREATE TABLE ticket_blockers(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),job_id TEXT REFERENCES ai_jobs(id),reason TEXT NOT NULL,created REAL NOT NULL,cleared REAL)",
        "CREATE UNIQUE INDEX blocker_active ON ticket_blockers(incident_id) WHERE cleared IS NULL",
    ),
    22: ("ALTER TABLE ai_jobs ADD COLUMN resolution_summary TEXT",),
    21: (
        "CREATE TABLE proxmox_api_jobs(id TEXT PRIMARY KEY,machine_id TEXT NOT NULL REFERENCES machines(id),ai_job_id TEXT REFERENCES ai_jobs(id),payload TEXT NOT NULL,fingerprint TEXT NOT NULL,policy_version INTEGER NOT NULL,binding TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,dispatched REAL,result TEXT,completed REAL)",
        "CREATE TRIGGER proxmox_api_immutable BEFORE UPDATE OF machine_id,ai_job_id,payload,fingerprint,policy_version,binding,created,expires ON proxmox_api_jobs BEGIN SELECT RAISE(ABORT,'Proxmox request identity is immutable'); END",
        "CREATE TRIGGER proxmox_api_no_delete BEFORE DELETE ON proxmox_api_jobs BEGIN SELECT RAISE(ABORT,'Proxmox request history is immutable'); END",
        "CREATE UNIQUE INDEX proxmox_api_active ON proxmox_api_jobs(machine_id) WHERE state IN ('dispatched','unknown')",
    ),
    20: (
        "ALTER TABLE ai_jobs ADD COLUMN command_tools INTEGER NOT NULL DEFAULT 0",
        "CREATE TABLE command_policies(machine_id TEXT PRIMARY KEY REFERENCES machines(id),enabled INTEGER NOT NULL DEFAULT 0,approval TEXT NOT NULL DEFAULT 'required',hermes INTEGER NOT NULL DEFAULT 0,external INTEGER NOT NULL DEFAULT 0,timeout INTEGER NOT NULL DEFAULT 120,output_limit INTEGER NOT NULL DEFAULT 8192,version INTEGER NOT NULL)",
        "CREATE TABLE command_jobs(id TEXT PRIMARY KEY,machine_id TEXT NOT NULL REFERENCES machines(id),agent_id TEXT NOT NULL REFERENCES agents(id),incident_id TEXT REFERENCES incidents(id),ai_job_id TEXT REFERENCES ai_jobs(id),command TEXT NOT NULL,fingerprint TEXT NOT NULL,policy_version INTEGER NOT NULL,timeout INTEGER NOT NULL,output_limit INTEGER NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,dispatch_token TEXT,dispatched REAL,result TEXT,completed REAL)",
        "CREATE UNIQUE INDEX command_active_agent ON command_jobs(agent_id) WHERE state IN ('awaiting','pending','dispatched','running','cancelling','unknown')",
        "CREATE TRIGGER command_immutable BEFORE UPDATE OF machine_id,agent_id,incident_id,ai_job_id,command,fingerprint,policy_version,timeout,output_limit,created,expires ON command_jobs BEGIN SELECT RAISE(ABORT,'Command identity is immutable'); END",
        "CREATE TRIGGER command_no_delete BEFORE DELETE ON command_jobs BEGIN SELECT RAISE(ABORT,'Command ledger is immutable'); END",
    ),
    19: (
        "ALTER TABLE ai_jobs ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'gateway'",
        "ALTER TABLE ai_jobs ADD COLUMN reasoning_effort TEXT NOT NULL DEFAULT 'low'",
        "ALTER TABLE ai_jobs ADD COLUMN run_timeout INTEGER NOT NULL DEFAULT 90",
        "CREATE INDEX codex_run_counts ON ai_jobs(execution_mode,created,incident_id)",
    ),
    18: (
        "CREATE TABLE power_policies(machine_id TEXT PRIMARY KEY REFERENCES machines(id),backend TEXT NOT NULL,object_id TEXT REFERENCES proxmox_objects(id),connection_id TEXT REFERENCES proxmox_connections(id),token_id TEXT,token_secret TEXT,enabled INTEGER NOT NULL DEFAULT 0,validated INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL)",
        "CREATE TABLE power_jobs(id TEXT PRIMARY KEY,machine_id TEXT NOT NULL REFERENCES machines(id),agent_id TEXT REFERENCES agents(id),payload TEXT NOT NULL,payload_hash TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,policy_version INTEGER NOT NULL,dispatch_token TEXT,dispatched REAL,task TEXT,result TEXT,completed REAL)",
        "CREATE UNIQUE INDEX power_lock ON power_jobs(machine_id) WHERE state IN ('awaiting','approved','dispatched','authorized','verifying','unknown')",
        "CREATE TRIGGER power_immutable BEFORE UPDATE OF machine_id,agent_id,payload,payload_hash,created,expires,policy_version ON power_jobs BEGIN SELECT RAISE(ABORT,'Power proposal is immutable'); END",
        "CREATE TRIGGER power_no_delete BEFORE DELETE ON power_jobs BEGIN SELECT RAISE(ABORT,'Power ledger is immutable'); END",
    ),
    17: (
        "ALTER TABLE proxmox_objects ADD COLUMN metrics TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE agents ADD COLUMN host_info TEXT NOT NULL DEFAULT '{}'",
    ),
    16: (
        'CREATE TABLE recovery_drafts(job_id TEXT PRIMARY KEY REFERENCES ai_jobs(id),incident_id TEXT NOT NULL REFERENCES incidents(id),payload TEXT NOT NULL,created REAL NOT NULL)',
        'CREATE TABLE draft_adoptions(job_id TEXT PRIMARY KEY REFERENCES recovery_drafts(job_id),proposal_id TEXT NOT NULL UNIQUE REFERENCES action_proposals(id))',
        "CREATE TRIGGER draft_no_update BEFORE UPDATE ON recovery_drafts BEGIN SELECT RAISE(ABORT,'Draft is immutable'); END",
        "CREATE TRIGGER draft_no_delete BEFORE DELETE ON recovery_drafts BEGIN SELECT RAISE(ABORT,'Draft is immutable'); END",
        "CREATE TRIGGER adoption_no_update BEFORE UPDATE ON draft_adoptions BEGIN SELECT RAISE(ABORT,'Adoption is immutable'); END",
        "CREATE TRIGGER adoption_no_delete BEFORE DELETE ON draft_adoptions BEGIN SELECT RAISE(ABORT,'Adoption is immutable'); END",
    ),
    15: (
        'ALTER TABLE incidents ADD COLUMN archived_at REAL',
        'CREATE TABLE incident_archives(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),created REAL NOT NULL,document TEXT NOT NULL)',
        "CREATE TRIGGER archive_no_update BEFORE UPDATE ON incident_archives BEGIN SELECT RAISE(ABORT,'Archive is immutable'); END",
        "CREATE TRIGGER archive_no_delete BEFORE DELETE ON incident_archives BEGIN SELECT RAISE(ABORT,'Archive is immutable'); END",
    ),
    14: (
        'CREATE TABLE notification_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE)',
        'CREATE TABLE machine_groups(machine_id TEXT PRIMARY KEY REFERENCES machines(id),group_id TEXT NOT NULL REFERENCES notification_groups(id))',
        'CREATE TABLE notification_overrides(scope_kind TEXT NOT NULL,scope_id TEXT NOT NULL,policy TEXT NOT NULL,PRIMARY KEY(scope_kind,scope_id))',
    ),
    13: (
        'ALTER TABLE incidents ADD COLUMN merged_into TEXT REFERENCES incidents(id)',
        "CREATE TABLE incident_merges(source_id TEXT PRIMARY KEY REFERENCES incidents(id),target_id TEXT NOT NULL REFERENCES incidents(id),created REAL NOT NULL,reason TEXT NOT NULL)",
        "CREATE TRIGGER merge_no_update BEFORE UPDATE ON incident_merges BEGIN SELECT RAISE(ABORT,'Merge ledger is immutable'); END",
        "CREATE TRIGGER merge_no_delete BEFORE DELETE ON incident_merges BEGIN SELECT RAISE(ABORT,'Merge ledger is immutable'); END",
    ),
    12: (
        "CREATE TABLE discovery_schedules(connection_id TEXT PRIMARY KEY REFERENCES proxmox_connections(id),interval INTEGER NOT NULL DEFAULT 0,next_run REAL NOT NULL DEFAULT 0,lease_token TEXT,lease_until REAL,last_error TEXT)",
        "ALTER TABLE proxmox_objects ADD COLUMN review_required INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE proxmox_objects ADD COLUMN missing_since REAL",
        "UPDATE proxmox_objects SET review_required=0 WHERE machine_id IS NOT NULL",
    ),
    11: (
        'ALTER TABLE agents ADD COLUMN action_credential_digest TEXT',
        "ALTER TABLE machines ADD COLUMN recovery_role TEXT NOT NULL DEFAULT 'protected'",
        """CREATE TABLE action_proposals(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),agent_id TEXT NOT NULL REFERENCES agents(id),version INTEGER NOT NULL,parent_id TEXT REFERENCES action_proposals(id),payload TEXT NOT NULL,payload_hash TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,approved_generation INTEGER,dispatch_token TEXT,dispatched REAL,result TEXT,completed REAL,verification TEXT)""",
        'CREATE INDEX action_incident ON action_proposals(incident_id,created)',
        "CREATE UNIQUE INDEX action_target_lock ON action_proposals(agent_id) WHERE state IN ('dispatched','authorized','verifying','unknown')",
        """CREATE TRIGGER action_payload_immutable BEFORE UPDATE OF payload,payload_hash,version,parent_id,incident_id,agent_id,created,expires ON action_proposals BEGIN SELECT RAISE(ABORT,'Proposal is immutable'); END""",
        "CREATE TRIGGER action_no_delete BEFORE DELETE ON action_proposals BEGIN SELECT RAISE(ABORT,'Proposal is immutable'); END",
    ),
    10: (
        'ALTER TABLE ai_jobs ADD COLUMN control_generation INTEGER NOT NULL DEFAULT 0',
        """CREATE TABLE incident_control(incident_id TEXT PRIMARY KEY REFERENCES incidents(id),owner TEXT NOT NULL DEFAULT 'available',generation INTEGER NOT NULL DEFAULT 0,checkpoint_id TEXT,updated REAL NOT NULL)""",
        """CREATE TABLE handoff_checkpoints(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),job_id TEXT REFERENCES ai_jobs(id),created REAL NOT NULL,snapshot TEXT NOT NULL)""",
        "INSERT INTO incident_control SELECT id,CASE WHEN EXISTS(SELECT 1 FROM ai_jobs WHERE incident_id=incidents.id AND state IN ('pending','dispatching','running','unknown')) THEN 'ai' ELSE 'available' END,0,NULL,last_seen FROM incidents",
        "CREATE TRIGGER checkpoints_no_update BEFORE UPDATE ON handoff_checkpoints BEGIN SELECT RAISE(ABORT,'Checkpoint is immutable'); END",
        "CREATE TRIGGER checkpoints_no_delete BEFORE DELETE ON handoff_checkpoints BEGIN SELECT RAISE(ABORT,'Checkpoint is immutable'); END",
    ),
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
