# Architecture and status

Python 3.11+, Flask, SQLite WAL with synchronous FULL, and one bounded worker. Ubuntu 24.04 uses Compose. Agents initiate verified HTTPS to the static app IP. A persistent UUID and unique credential establish identity independently of DHCP addresses. User-facing DNS is optional.

Machine records and check sources are explicitly linked. Names/IPs never auto-merge identities. Parent relationships suppress new dependent incidents while preserving observations. Proxmox API monitoring is read-only and selected resource state remains distinct from application checks. No allocated-RAM value is presented as memory pressure.

The worker transactionally stores observations, incidents and notification jobs. A partial unique index prevents duplicate condition incidents. Atomic leases have ownership tokens, so an expired worker cannot overwrite newer results. Crash-abandoned jobs resume after lease expiry. Discord delivery is at-least-once: a lost acceptance reply can cause a duplicate message. Resolved incidents supersede queued opening alerts.

Manual resolution while a check is unhealthy retains that incident until independent recovery. Health and workflow stay separate; new duplicate tickets are suppressed. Notes do not invoke AI. Database triggers reject updates/deletes of timeline and audit records. Configuration, enrollment and manual workflow changes are audited transactionally; no secret values are included. Earlier changes are not retroactively reconstructed.

Secrets are Fernet-encrypted using a separately managed key. Cookies require HTTPS in production; CSRF protects UI mutations. Agent tokens are unique, stored hashed, revocable and renewed by re-enrollment. Enrollment tokens expire after ten minutes and are consumed transactionally. The agent stores pending telemetry before sending and retries its stable event identity after ambiguous delivery.

## Remaining scope

Not implemented: automatic Proxmox discovery/cluster deduplication, rich source lifecycle/linking, sustained metric thresholds/hysteresis, multi-source correlation, scheduled maintenance, reminders, retention, configuration export/import, detailed Linux diagnostics/jobs, credential rotation UI, login/security-event auditing, live Hermes orchestration, budget reservations, chat/exploration/handoff, approvals/action broker and remediation.

Ordered transactional migrations upgrade schema 1 to schema 2 while preserving existing records. Failed upgrades roll back DDL and the version marker together. Newer schemas are rejected. History supports machine/severity/status/date filters and bounded pagination. GUI budget fields are preferences only; AI stays disabled until enforceable bridge controls are verified.

Local validation uses Python 3.14. Target Python 3.12/Ubuntu and Docker execution require separate deployment validation. No production endpoint is a test fixture.
