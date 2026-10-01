# Requirements checklist

| Requirement | Status |
|---|---|
| Local administrator, CSRF, hashed password, safe rendering | Implemented and tested |
| Secret encryption and no saved-secret redisplay | Implemented and tested |
| HTTP/TCP checks | Implemented; provider tests |
| Proxmox discovery / linked checks | Implemented with explicit cluster namespaces; duplicate endpoint, migration, stopped guest and retirement tests |
| Failure/recovery thresholds and sustained resource metrics | Implemented and tested; root filesystem and Linux PSI scope |
| Parent suppression, temporary maintenance | Implemented; schedules pending |
| Deterministic incident before AI | Implemented and tested |
| Manual notes and resolved-but-unhealthy visibility | Implemented and tested |
| Durable outbox, leases, TTL, retry and obsolete delivery handling | Implemented and tested |
| DHCP identity, duplicate heartbeat, revoke/re-enroll | Implemented and tested |
| Linux read-only diagnostics and durable jobs | Implemented and tested; all action/mutation jobs unavailable |
| Explicit Proxmox/agent machine linking and source unlink | Implemented; guest-stop/agent correlation implemented; broader metric correlation pending |
| Hermes V2 signing | Implemented helper; installed spike pending |
| Durable AI completion and enforceable budgets | Pending; no dispatch |
| Advice/exploration/handoff | Pending |
| Approval broker and recovery actions | Pending; all mutations unavailable |
| Configuration/enrollment/workflow audit and immutable timelines | Implemented and tested; login/security-event audit pending |
| Schema upgrades and incident history filters | Implemented and tested |
| Retention and configuration export/import | Pending |
| Docker/Ubuntu deployment | Files supplied; execution validation pending |
| No backup operations | No backup code or endpoints |

This milestone does not meet the full definition of done. Tests use mocks/disposable fixtures; no live system is stopped, stressed, rebooted or modified.

Correlation tests cover both arrival orders, explicit identity boundaries, API failure separation, stale evidence, independent recovery, severity filter crossing and uncertain links without merges.
