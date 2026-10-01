# Requirements checklist

| Requirement | Status |
|---|---|
| Local administrator, CSRF, hashed password, safe rendering | Implemented and tested |
| Secret encryption and no saved-secret redisplay | Implemented and tested |
| HTTP/TCP checks | Implemented; provider tests |
| Proxmox API / explicit resource checks | Partial; discovery and dedup pending |
| Failure/recovery thresholds | Implemented; sustained metrics pending |
| Parent suppression, temporary maintenance | Implemented; schedules pending |
| Deterministic incident before AI | Implemented and tested |
| Manual notes and resolved-but-unhealthy visibility | Implemented and tested |
| Durable outbox, leases, TTL, retry and obsolete delivery handling | Implemented and tested |
| DHCP identity, duplicate heartbeat, revoke/re-enroll | Implemented and tested |
| Linux structured diagnostics and durable action jobs | Pending; telemetry only |
| Multi-source correlation and linking lifecycle | Pending |
| Hermes V2 signing | Implemented helper; installed spike pending |
| Durable AI completion and enforceable budgets | Pending; no dispatch |
| Advice/exploration/handoff | Pending |
| Approval broker and recovery actions | Pending; all mutations unavailable |
| Full audit, retention, export/import, upgrade migrations | Pending; initial schema only |
| Docker/Ubuntu deployment | Files supplied; execution validation pending |
| No backup operations | No backup code or endpoints |

This milestone does not meet the full definition of done. Tests use mocks/disposable fixtures; no live system is stopped, stressed, rebooted or modified.
