# Resource-health rules and Linux diagnostics

Schema 5 adds agent capability reports, sample timestamps and durable read-only diagnostic jobs. Agent 0.2.0 requires both `agent.py` and `diagnostics.py`; update deliberately through a trusted channel. No automatic updates exist.

## Metrics

CPU percentage uses consecutive `/proc/stat` samples (first sample has no CPU percentage). Memory usage derives from `MemAvailable / MemTotal`, so reclaimable cache is not automatically classified as pressure. Memory pressure uses Linux PSI `full avg10` when available. Disk and inode usage cover the root filesystem, using space available to the unprivileged agent. Additional mounts and swap-specific rules remain future scope.

Add a rule under Resources. Configure failure threshold, lower recovery threshold and minimum sustained duration. Resource checks poll every 30 seconds; two healthy samples establish recovery. Only new telemetry samples contribute observations/duration. Stale, missing or unsupported telemetry is unknown and resets sustained-failure tracking. Old heartbeat retries preserve their original sample timestamp so they cannot appear fresh after an outage. Agent clock skew greater than the accepted window produces unknown data; synchronize clocks.

## Diagnostics

The incident page lists agents belonging to its machine and their advertised operations/services. Requests are explicit manual actions, never AI calls. Process summaries return at most 100 process names/PIDs, excluding command arguments/environments. Service status reads selected properties through fixed `systemctl show` argv. Logs read at most 50 journal lines and require explicit local opt-in.

Local policy: `/etc/aiticket-agent/policy.json`, for example:

```json
{"services":{"web":"nginx.service"},"logs":false}
```

Keep the policy administrator-managed. Restart the agent after edits. No local policy grants OS permissions; denied unprivileged journal access is reported as a diagnostic failure. Do not broaden root or journal access automatically. The service remains unprivileged, and no shell or remotely supplied command/path is accepted.

Commands have five-second wall-time and 16 KB output limits. Agent and server redact common password/token/key/authorization assignments; server also removes embedded URL credentials. This is pattern-based redaction, not a guarantee that arbitrary free-text logs contain no sensitive data. Logs default off; choose allowlisted services deliberately. Diagnostic outputs are escaped in the UI and never trigger actions.

## Durable execution

Server jobs have stable UUIDs, ten-minute expiry, bounded per-agent queue, 90-second ownership leases, duplicate active-request suppression and authenticated result reporting. Heartbeats fetch one job at a time. The agent durably records execution before starting and caches bounded results. Re-delivery of a completed UUID returns cached output with the current lease. Restart during execution returns a failed/ambiguous result without blindly replaying it. Accepted results append incident timeline and audit events; repeated results are no-ops.

Results rejected for expired/superseded leases are dropped from the agent delivery outbox; a later valid redelivery can still use its cached ledger. The ledger retains 100 identities, exceeding the maximum ten-minute active-job horizon under the thirty-second polling model. Job states expire even if the agent never reconnects. Agent revocation blocks job polling and result submission. No mutations or remediation are implemented.

## Validation limits

Tests use Linux-like filesystem fixtures, mocked service providers and harmless local subprocesses for bounded output. Real Ubuntu/systemd/journal permissions, container runtime and production enrollment remain unverified. No infrastructure, AI or backup endpoint was contacted.

Metric definitions follow the Linux kernel documentation: https://docs.kernel.org/accounting/psi.html and https://docs.kernel.org/filesystems/proc.html .
