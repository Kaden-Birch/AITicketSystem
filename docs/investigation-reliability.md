# Dependable investigations and application health

## Manual tasks start immediately

Creating a ticket with **AI handles it** queues its investigation immediately.
Administrator tasks are not filtered by the automatic monitoring severity threshold
or the automatic-triage switch. AI must still be enabled and validated; queue,
usage, ownership and outstanding-operation limits still apply. If admission fails,
the ticket remains open with a clear blocker. Human and paused tickets do not queue.
The background dispatcher also finds eligible manual tickets created outside the
page route. It never creates a second active execution for a ticket.

Replies and approvals retain existing ticket identity, checkpoints, policy fences,
and session tracking. Expired and uncertain dispatches request attention even if
no work session had started. An uncertain submission is polled, never replayed.

## Information available to AI

Every investigation mode receives a credential-filtered host snapshot: reported
metrics, sample and receipt times, clock offset, access mode, current check health,
last observations, retry/recovery counts, Proxmox inventory/metrics, and explicitly
configured application dependencies. Existing network topology and read-only
UniFi context remain included. Missing or stale samples are labelled explicitly.
Proxmox disk allocation does not establish guest filesystem free space.

Snapshots retain the existing 16,000-character context bound. Check lists are
limited to 30 and large check results are described rather than silently treated
as complete. Context coverage explains omissions; operational AI can use `targets`
for current host context, `network` for read-only UniFi refreshes, and the existing
command/status tools for authorized diagnostics. Read-only gateway investigations
have snapshots but no tools. Inventory data is evidence, never authorization.

## Monitoring health

**Monitoring health** identifies clock drift, stale/missing metric collection,
stale check results, collector errors and incomplete UniFi API coverage. The
dashboard links to it with an attention count. Agent reachability remains a
separate host check. Expected-offline machines are excluded from collector checks.
UniFi API errors without actual device/storage failure evidence produce an
unknown result rather than declaring the infrastructure down. Real reported pool,
disk or device faults continue through normal failure thresholds.

## Repair limits and recovery

Default limits allow two attempts at the same AI change and 20 change attempts
per ticket within 30 minutes, across investigation sessions. Change attempts are
counted conservatively using the existing read-only classifier. Recognized
read-only diagnostics and Proxmox GETs are exempt. Cancelled/expired/awaiting
operations are not counted as dispatched changes. Limits are configurable under
Monitoring health. Reaching a limit records a blocker and stops further AI changes
until administrator review/resumption; read-only diagnostics remain available.
These limits do not add approval prompts to Full access or restrict administrator
commands. Existing power and service-recovery cooldowns remain enforced.

An AI completion is a session result, not proof of recovery. Closure requested by
AI requires current, independently collected healthy results after its verification
request, configured recovery thresholds, and reconciliation of outstanding
operations. A ticket can still recover naturally through its monitored sources;
manually resolving a ticket remains an explicit administrator decision.

## Applications and dependency grouping

Create an application under **Applications**, select its checks across machines,
and optionally specify which checks depend on other selected checks. Dependencies
must not form cycles, including across applications. Application health requires
fresh, enabled check results; missing or disabled results are unknown.

A fresh confirmed upstream failure links related tickets and focuses automatic
investigation on the upstream ticket when it meets the configured AI threshold.
Duplicate opening notifications are deferred while the upstream failure remains
fresh and its own notification policy is enabled. Every original ticket, check and
observation remains retained. Dependencies guide investigation, not causation.
Downstream tickets do not close merely because an upstream ticket closes, and
become independently eligible when the upstream condition recovers or goes stale.
Explicit administrator investigations remain available.

Application definitions are stored in the application database and included in
full database backups. The portable inventory export does not currently include
them. Deleting an application removes its grouping configuration, not machines,
checks, ticket histories, or infrastructure.

## Harmless workflow exercise

Use **Monitoring health → Run workflow test**. It creates a labelled ticket,
queues the configured AI with current diagnostic context, and independently
observes successful AI completion through a server-side test check. That check is
disabled after resolution. The workflow is not a mock: it consumes the configured
AI allowance and uses the existing ticket/notification pipeline.

Server-side fencing prohibits host commands and infrastructure API operations,
including after checkpoint resumption. AI can inspect context, refresh read-only
network information, report a blocker, or request verification. Notification
eligibility and delivery follow existing policies. A successful test establishes
AI dispatch/completion and ticket recovery, not successful Discord delivery or
that every host permission/collector works. Review the delivery queue separately.

## Short, readable updates

Conversation cards show author, local timestamp and coloured textual state tags.
New AI replies are instructed to use two or three plain-language sentences.
Legacy closure boilerplate, raw execution IDs and the repetitive unverified prefix
are removed from normal conversation summaries. An AI completion is labelled
Session complete or Checking recovery; only monitoring recovery is Resolved.
Original immutable records remain available in explicitly opened technical event
history, including operation references and detailed evidence.

Update both the main application and the companion Hermes bridge checkout to
apply the new response instructions. Restart the bridge using its existing
service deployment procedure. No monitoring-agent reinstall is required.
