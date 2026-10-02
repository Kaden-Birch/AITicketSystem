# Architecture and status

Python 3.11+, Flask, SQLite WAL with synchronous FULL, a bounded monitoring worker and a separate bounded AI orchestration thread. Ubuntu 24.04 uses Compose. Agents initiate verified HTTPS to the static app IP. A persistent UUID and unique credential establish identity independently of DHCP addresses. User-facing DNS is optional.

Machine records and check sources are explicitly linked. Names/IPs never auto-merge identities. Parent relationships suppress new dependent incidents while preserving observations. Proxmox API monitoring is read-only and selected resource state remains distinct from application checks. No allocated-RAM value is presented as memory pressure.

The worker transactionally stores observations, incidents and notification jobs. A partial unique index prevents duplicate condition incidents. Atomic leases have ownership tokens, so an expired worker cannot overwrite newer results. Crash-abandoned jobs resume after lease expiry. Discord delivery is at-least-once: a lost acceptance reply can cause a duplicate message. Resolved incidents supersede queued opening alerts.

Manual resolution while a check is unhealthy retains that incident until independent recovery. Health and workflow stay separate; new duplicate tickets are suppressed. Notes do not invoke AI. Database triggers reject updates/deletes of timeline and audit records. Configuration, enrollment and manual workflow changes are audited transactionally; no secret values are included. Earlier changes are not retroactively reconstructed.

Secrets are Fernet-encrypted using a separately managed key. Cookies require HTTPS in production; CSRF protects UI mutations. Agent tokens are unique, stored hashed, revocable and renewed by re-enrollment. Enrollment tokens expire after ten minutes and are consumed transactionally. The agent stores pending telemetry before sending and retries its stable event identity after ambiguous delivery.

## Remaining scope

Not implemented: automatic cluster identity verification, additional mount/swap rules, installed Hermes/provider validation, live AI diagnostic/tool execution, autonomous recovery and higher-risk remediation.

Ordered transactional migrations upgrade schema 1 to schema 2 while preserving existing records. Failed upgrades roll back DDL and the version marker together. Newer schemas are rejected. History supports machine/severity/status/date filters and bounded pagination. GUI budget fields drive transactional per-call admission; AI defaults to disabled until installed bridge/provider controls are verified.

Local validation uses Python 3.14. Target Python 3.12/Ubuntu and Docker execution require separate deployment validation. No production endpoint is a test fixture.

Milestone 3: schema 3 adds reusable Proxmox connections, explicit cluster namespaces, manually refreshed inventory, confirmed machine/source links, retirement generations, unlink-preserved history and disabled checks. See proxmox.md for identity limitations and deployment details.

Schema 4 introduces incident-source snapshots, incident observation associations and uncertain incident links. Guest-stop/agent-communication correlation is implemented; other checks remain separate. See correlation.md.

Schema 5 implements durable read-only agent diagnostics and resource-health rules. The agent ledger distinguishes completed, failed and interrupted executions; arbitrary shell and all mutation capabilities remain absent. See resource-diagnostics.md.

Schema 6 provides one-time/weekly maintenance and global reminder/escalation policies with durable deduplication and incident silence. Bundled timezone data is versioned. See maintenance-notifications.md.

Schema 7 indexes observation references and heartbeat timestamps for bounded retention. Authentication generations invalidate cookies after password recovery. Key rotation requires stopped processes and an explicit switch to a separately created key; details in recovery.md.

Schema 8 adds encrypted durable AI jobs and a model-call reservation/usage ledger. A separate orchestration thread polls a signed companion bridge and never blocks check probes. The bridge uses an isolated tool-free Hermes adapter; provider keys stay on the main application, which admits and meters every supported model call. Unknown usage holds capacity and fences further admission. See hermes-contract.md for provider-bound assumptions and deferred validation.

Schema 9 adds job modes, request fingerprints and immutable incident conversation records. Selected context is scoped to one incident; completed conversation history is bounded. Advice/exploration share the existing per-call ledger and cumulative incident ceiling.

Schema 10 adds persistent incident ownership generations and immutable handoff checkpoints. All model calls validate the execution’s ownership generation. User takeover cancels active jobs atomically; terminal completion releases only its matching generation. AI and manual diagnostic queueing cannot overlap. Checkpoint resume creates a new budgeted read-only execution; it never replays old work.

Schema 11 adds immutable recovery proposals, separate hashed action credentials and a default-protected machine role. The application broker and agent both enforce exact allowlisted service recovery; see action-broker.md.

Schema 16 adds immutable recovery drafts and adoption bindings. AI supplies bounded text for administrator-selected targets, with shared budget admission; reviewed drafts become awaiting-approval proposals only after current preconditions are revalidated.

Explicit `AITICKET_ALLOW_INSECURE_HTTP=1` permits direct HTTP browser login and HTTP integration URLs. Agent `--allow-http` opt-in persists in its local identity; HTTPS still validates certificates. Compose defaults to loopback/secure cookies but supports a configured bind address for direct HTTP or an external proxy.

Schemas 17–18 add inventory metric snapshots, bounded agent OS information, host workspaces and a separate manual power broker. The broker isolates monitoring credentials from power credentials, persists immutable proposals and single dispatches, fences identity/migration changes, requires local agent allowlists and verifies outcomes independently. AI cannot submit these manual power jobs. Unknown outcomes are never retried. Full inventory import excludes power secrets and disables power policies on affected targets. Key rotation includes encrypted power tokens.

Schema 19 adds Codex subscription execution snapshots and transactional incident/day/month run admission. The restricted bridge resolves a dedicated Hermes OAuth profile for the native Codex Responses transport; no API provider credential or fabricated token/cost meter is involved. Signed status binds model and reasoning, and scoped application permission polling fences cancellation, ownership changes, disablement and expiry. See hermes-codex.md for elapsed-time and in-flight usage limitations.
