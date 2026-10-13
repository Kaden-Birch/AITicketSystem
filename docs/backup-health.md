# Backup health

Open **Backups** in the navigation menu. Existing Proxmox connections are polled
read-only every five minutes. TrueNAS snapshot and replication tasks are read on
the normal host refresh. No separate credentials or agent update is required.

Proxmox uses `/cluster/backup` and bounded per-node `vzdump` task history. The token
needs schedule and task-history read access (root `Sys.Audit` for schedules; node
`Sys.Audit` for tasks). Backup actions are never started by this collector. Up to
100 schedules and 100 recent tasks per node on 16 nodes are examined. Limit and
permission gaps are disclosed. Guest attribution uses VM IDs within the configured
cluster namespace, not display names. Pool-based schedules and multiple matching
schedules are displayed with unavailable/ambiguous attribution. A guest completion
is an observed guest backup, not proof of a particular destination's integrity.

TrueNAS uses `pool.snapshottask.query`, `replication.query` and the timezone from
`system.general.config`. Read-only roles must expose these methods. Up to 100 tasks
of each kind are captured; unavailable methods are reported independently of host
health. Cron schedules use the server timezone, including DST. Unsupported,
ambiguous or timezone-less schedules do not invent deadlines. Local snapshots are
labelled as local snapshots, not independent backups.

Overdue detection begins after a future deadline was observed. A known deadline
must pass by one hour without a subsequently observed successful run. Existing
future deadlines are preserved across refreshes and reset on schedule changes.
Running/waiting jobs, disabled jobs and stale/unavailable evidence are not counted
as failed completed runs. Failures and overdue jobs use normal host checks with
two failed/recovery readings, medium severity, and the existing maintenance,
notification, AI and remediation policies. Users can tune or disable those checks
in host settings. Removing a discovered job disables its automatic source only on
a complete read; source deletion or confirmed host unlink also disables checks.
History is retained and no recovery is asserted solely because a job disappeared.

The host page shows up to three backup jobs and links to the complete searchable,
paginated Backups page. That page includes last successful/last run times, reported
status, duration when provided, schedule, destination/dataset, run reference and
collection time. All items explicitly say restore testing has not been verified.

Host-associated projections are captured as `backup` telemetry using the existing
local and SMB retention/budget. AI requests current pages with `evidence` and
`source: backups`, then bounded local/SMB `archive_search` with
`archive_type: telemetry` and `record_type: backup` for older evidence. Evidence
remains host-scoped and is not automatically injected as full logs into prompts.
