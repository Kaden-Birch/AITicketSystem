# Requirements checklist

| Requirement | Status |
|---|---|
| Local administrator, CSRF, hashed password, safe rendering | Implemented and tested |
| Secret encryption and no saved-secret redisplay | Implemented and tested |
| HTTP/TCP checks | Implemented; provider tests |
| Proxmox discovery / linked checks | Implemented with explicit cluster namespaces; duplicate endpoint, migration, stopped guest and retirement tests |
| Failure/recovery thresholds and sustained resource metrics | Implemented and tested; root filesystem and Linux PSI scope |
| Parent suppression and scheduled maintenance | Implemented; one-time/weekly/global/machine windows and temporary snooze |
| Deterministic incident before AI | Implemented and tested |
| Manual notes and resolved-but-unhealthy visibility | Implemented and tested |
| Durable outbox, leases, TTL, retry and obsolete delivery handling | Implemented and tested |
| DHCP identity, duplicate heartbeat, revoke/re-enroll | Implemented and tested |
| Linux read-only diagnostics and durable jobs | Implemented and tested; all action/mutation jobs unavailable |
| Explicit Proxmox/agent machine linking and source unlink | Implemented; guest-stop/agent correlation implemented; broader metric correlation pending |
| Hermes V2 signing | Implemented on companion requests/responses with durable execution polling; installed spike pending |
| Durable AI completion and enforceable budgets | Fixture-tested signed execution states and transactional token/configured-price admission; restricted companion/adapter supplied; live Hermes/provider validation pending and default disabled |
| Advice/exploration/handoff | Advice and selected-evidence exploration implemented with fixtures; checkpoint-based handoff implemented; live AI diagnostic execution pending |
| Approval broker and recovery actions | Pending; all mutations unavailable |
| Configuration/enrollment/workflow audit and immutable timelines | Implemented and tested; login/security-event audit pending |
| Schema upgrades and incident history filters | Implemented and tested |
| Retention and configuration export/import | Routine unattached samples and heartbeat deduplication cleanup implemented; nonsecret preferences transfer implemented; full inventory transfer and incident archival pending |
| Docker/Ubuntu deployment | Files supplied; execution validation pending |
| No backup operations | No backup code or endpoints |

This milestone does not meet the full definition of done. Tests use mocks/disposable fixtures; no live system is stopped, stressed, rebooted or modified.

Correlation tests cover both arrival orders, explicit identity boundaries, API failure separation, stale evidence, independent recovery, severity filter crossing and uncertain links without merges.

Maintenance/notification tests cover timezone boundaries, inherited scope, preserved observations, silence, duplicate reminders, backlog coalescing, escalation severity floors and dispatch filtering. Per-scope notification overrides remain pending.

Password change/console recovery, session invalidation, agent credential rotation and offline key rotation implemented with fixture tests. Live recovery drills remain deferred.

AI tests cover simultaneous admission, all ceiling types, zero allowances, unknown-usage holds across dates/cancellation, capped provider forwarding, usage/price reconciliation, tools/model restrictions, signed freshness, duplicate results, uncertain-dispatch polling, bridge restart fencing, isolated environment and activation gates. Live AI diagnostic execution and action approvals remain absent.

Handoff tests cover durable ownership/checkpoints, pause fencing, stale forms/generations, racing queue/takeover, atomic manual resolution, no overlapping diagnostics, resumed fresh evidence, duplicate resume, immutable snapshots and preservation of unknown budget reservations.
