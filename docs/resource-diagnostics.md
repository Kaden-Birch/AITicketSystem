# Resource-health rules and Linux diagnostics

Health preferences are available under **Agent health** in navigation, and **Hosts → your host → Host settings → Agent health**. The current agent installer and permission verification are documented in [agent installation](agent.md). This milestone needs only a main application update; existing agents already report the required metrics.

## Fleet defaults and host overrides

All five metrics are listed automatically: CPU usage, available memory, memory pressure, free storage and available file entries. New fleet defaults start disabled. Existing resource rules become host overrides and preserve their check identities, settings and ticket history. Existing enabled rules stay enabled. Multiple legacy rules for the same host/metric are consolidated into one deterministic setting; duplicate checks are disabled with their history retained.

Use the switch and **Save default** to configure an inherited fleet default. A host without an override follows later changes automatically, including hosts enrolled in the future. On a host, **Save override** makes that metric independent of the default; **Disable** turns its alerts off on that host; **Use defaults** deletes the override and restores inheritance.

**Pause everywhere** stops that metric on all hosts, including overrides. **Resume everywhere** restores each host's saved enabled/disabled preference. Turning off only the default leaves explicit host overrides intact; use Pause everywhere when you want a fleet-wide stop.

Disabling or pausing monitoring does not assert that an issue recovered or automatically close its existing ticket. Existing ticket history remains available. Automatic AI admission and queued nonrecovery notifications are suppressed for tickets whose sources are exclusively disabled managed health checks. Mixed-source tickets continue independently, and already-running investigations are not automatically cancelled.

## Threshold controls

Each card shows a readable metric name, a slider and a directly editable value. Memory and storage can use **Percentage** or **Free space · GB**. An unqualified amount means GB; typing `50 GB`, `500 MB` or `0.5 TB` converts the value to GB, regardless of capitalization. GB/MB/TB use decimal units (1 GB = 1,000,000,000 bytes). Switching units starts a suggested threshold in the new units; review it before saving.

CPU and memory pressure alert on high usage. Memory, storage and file-entry rules alert on low availability. For example, free storage below 15% or below 50 GB. File entries are slots for files/folders, sometimes called inodes; exhaustion can prevent creating files even when disk space remains.

**Recovery & timing** contains recovery threshold, sustained duration and ticket priority. Recovery must be above a free-space threshold or below a usage/pressure threshold. The browser adjusts recovery when a threshold edit would otherwise make it invalid; you can customize it. A failure must persist for the duration, and two healthy readings establish recovery. Editing a rule resets its threshold counters and fences older polling leases.

CPU uses consecutive `/proc/stat` samples; its first reading may be unavailable. Available memory includes reclaimable cache. Memory pressure uses Linux PSI full avg10 when available. Storage and file-entry rules cover the root filesystem; other mounts need separate checks. Missing, unsupported or stale values remain unknown, not healthy or proof of exhaustion. Only new telemetry samples contribute sustained failures. Health checks follow the application's agent reporting interval, configurable down to 20 seconds.

Health defaults/overrides are retained in full database backups. Inventory configuration exports carry materialized check definitions; fleet defaults themselves are not included. Importing health checks creates disabled host overrides pending administrator review, preventing inherited defaults from silently re-enabling them.

## Diagnostics

The incident page lists agents belonging to its machine and their advertised operations/services. Requests are explicit manual actions, never AI calls. Process summaries return at most 100 process names/PIDs, excluding command arguments/environments. Service status reads selected properties through fixed `systemctl show` argv. Logs read at most 50 journal lines and require explicit local opt-in.

Local policy: `/etc/aiticket-agent/policy.json`, for example:

```json
{"services":{"web":"nginx.service"},"logs":false}
```

Keep the policy administrator-managed. Restart the agent after edits. No local policy grants OS permissions; denied unprivileged journal access is reported as a diagnostic failure. These diagnostic operations still use fixed, bounded commands. The current installer runs the service as root; general remote shell access is separately governed by the main application host access mode.

Commands have five-second wall-time and 16 KB output limits. Agent and server redact common password/token/key/authorization assignments; server also removes embedded URL credentials. This is pattern-based redaction, not a guarantee that arbitrary free-text logs contain no sensitive data. Logs default off; choose allowlisted services deliberately. Diagnostic outputs are escaped in the UI and never trigger actions.

## Durable execution

Server jobs have stable UUIDs, ten-minute expiry, bounded per-agent queue, 90-second ownership leases, duplicate active-request suppression and authenticated result reporting. Heartbeats fetch one job at a time. The agent durably records execution before starting and caches bounded results. Re-delivery of a completed UUID returns cached output with the current lease. Restart during execution returns a failed/ambiguous result without blindly replaying it. Accepted results append incident timeline and audit events; repeated results are no-ops.

Results rejected for expired/superseded leases are dropped from the agent delivery outbox; a later valid redelivery can still use its cached ledger. The ledger retains 100 identities, exceeding the maximum ten-minute active-job horizon under the thirty-second polling model. Job states expire even if the agent never reconnects. Agent revocation blocks job polling and result submission. These diagnostics do not themselves perform remediation; general host command and recovery features are documented separately.

## Validation limits

Tests use Linux-like filesystem fixtures, mocked service providers and harmless local subprocesses for bounded output. Real Ubuntu/systemd/journal permissions, container runtime and production enrollment remain unverified. No infrastructure, AI or backup endpoint was contacted.

Metric definitions follow the Linux kernel documentation: https://docs.kernel.org/accounting/psi.html and https://docs.kernel.org/filesystems/proc.html .
