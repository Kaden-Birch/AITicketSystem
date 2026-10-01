# Architecture and status

Python 3.11+, Flask, SQLite WAL with synchronous FULL, and one bounded worker. Ubuntu 24.04 uses Compose. Agents initiate verified HTTPS to the static app IP. A persistent UUID and unique credential establish identity independently of DHCP addresses. User-facing DNS is optional.

Machine records and check sources are explicitly linked. Names/IPs never auto-merge identities. Parent relationships suppress new dependent incidents while preserving observations. Proxmox API monitoring is read-only and selected resource state remains distinct from application checks. No allocated-RAM value is presented as memory pressure.

The worker transactionally stores observations, incidents and notification jobs. A partial unique index prevents duplicate condition incidents. Atomic leases have ownership tokens, so an expired worker cannot overwrite newer results. Crash-abandoned jobs resume after lease expiry. Discord delivery is at-least-once: a lost acceptance reply can cause a duplicate message. Resolved incidents supersede queued opening alerts.

Manual resolution while a check is unhealthy retains that incident until independent recovery. Health and workflow stay separate; new duplicate tickets are suppressed. Notes do not invoke AI. The activity timeline is append-only through application interfaces; database-level immutability and full configuration audit remain future work.

Secrets are Fernet-encrypted using a separately managed key. Cookies require HTTPS in production; CSRF protects UI mutations. Agent tokens are unique, stored hashed, revocable and renewed by re-enrollment. Enrollment tokens expire after ten minutes and are consumed transactionally. The agent stores pending telemetry before sending and retries its stable event identity after ambiguous delivery.

## Remaining scope

Not implemented: automatic Proxmox discovery/cluster deduplication, rich source lifecycle/linking, sustained metric thresholds/hysteresis, multi-source correlation, scheduled maintenance, reminders, history filtering/retention, configuration export/import, detailed Linux diagnostics/jobs, credential rotation UI, full audit, ordered upgrade migrations, live Hermes orchestration, budget reservations, chat/exploration/handoff, approvals/action broker and remediation.

Initial schema installation is idempotent and versioned as 1. Before schema changes, ordered transactional migrations and upgrade tests are required. GUI budget fields are preferences only; AI stays disabled until enforceable bridge controls are verified.

Local validation uses Python 3.14. Target Python 3.12/Ubuntu and Docker execution require separate deployment validation. No production endpoint is a test fixture.
