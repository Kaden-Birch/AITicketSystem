# Incident correlation

Schema 4 records incident sources and links each newly attached observation to its incident. Existing incidents migrate as one-source incidents without rewriting their historical reports/timeline.

Automatic correlation is conservative: a Proxmox VM/LXC explicitly expected running but actually observed stopped can share an incident with missing agent communication on the same explicitly linked machine. Either source can arrive first. The partner must be recent (300-second window). Source identity uses machine UUID, never name/address.

An API connection or permission error is not evidence that a guest stopped, and does not qualify. A guest expected stopped does not qualify either. HTTP/TCP failures remain distinct conditions; nearby guest/agent incidents can be visibly linked as possible shared impact, without asserting a common cause. Unrelated HTTP checks remain separate.

Reports expose each source's latest evidence, threshold state, sample timestamp and freshness. Original observations remain stored and newly attached ones have explicit incident associations. Cause remains unknown; missing agent communication alone is not proof of OS failure. Broad memory-pressure correlation and audited manual merge/link controls remain future work.

Recovery requires every attached source to independently reach its recovery threshold with observations no older than max(180 seconds, three polling intervals). Disabled or stale sources cannot prove recovery. A recovered primary check cannot close an incident while its partner remains unhealthy/stale. A source that is unlinked therefore requires manual workflow review if it was attached to an open incident.

Severity is the highest attached-source severity. Escalation through the configured Discord filter schedules a separate deduplicated severity event. Manual resolution remains distinct from health; unhealthy conditions stay attached until verified recovery.

Correlation, source evidence, timeline updates and notification scheduling share one SQLite transaction. AI calls and recovery actions remain unavailable. This milestone does not claim general root-cause inference.

## Broader relationships and manual grouping

Concurrent failed resource-pressure rules, agent communication, guest-stop and HTTP/TCP checks on the same explicitly linked machine create possible-impact relationships within a five-minute evidence window. HTTP/TCP failures can also relate to each other. These remain separate incidents with cause unknown; resource pressure does not prove an outage cause. Stale or latest-healthy source evidence does not establish a new relationship.

The incident page can merge another active unresolved incident from the same machine into the current one. A reason and confirmation are required. Original records, source reports, timelines and observation memberships remain; an immutable merge ledger points to the continuing incident. The donor is closed as merged, not recovered. Its queued notifications are superseded. All combined sources must independently recover with fresh evidence. AI work, unknown usage and unfinished diagnostics/recovery proposals block merging. An incident with a consumed recovery attempt must remain the target, preserving the one-attempt limit. Completed diagnostic and AI history remain accessible on their original incident.
