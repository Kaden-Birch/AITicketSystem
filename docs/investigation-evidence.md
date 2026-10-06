# Investigation evidence, related tickets and maintenance

Schema 38 adds evidence coverage, shared investigations and maintenance-aware AI work. Update the main application and the Hermes companion to the same revision. The companion supplies the expanded `aiticket_host` tool schema; an older companion will not advertise the new evidence/refresh actions. Follow the update instructions in [Hermes Codex setup](hermes-codex.md).

## Evidence available

The ticket page shows compact cards with **Current**, **Partial**, **Stale** or **Unavailable** badges. Expand a card for collection details and observation time. Freshness describes the evidence, not the health of the host or a confirmed diagnosis. Missing readings, collector errors and future-dated agent samples cannot prove that a machine is healthy.

The initial AI snapshot includes coverage, host facts, current telemetry, checks, linked integrations, dependencies and network context. Large snapshots explicitly direct the AI to retrieve smaller pages rather than silently losing access to the remaining saved inventory. Credentials are excluded and sensitive fields are redacted. Evidence is treated as untrusted observations, never as instructions.

### Coverage audit

| Evidence source | What the AI can retrieve |
| --- | --- |
| `metrics` | All saved metric values from the linked, non-revoked agent, sample time and server receipt time. |
| `checks` | All host checks except synthetic manual-ticket checks, enabled state, current and latest health, collection time, interval, failure/recovery counts, redacted configuration/thresholds and latest evidence. |
| `processes`, `containers` | Paginated saved agent inventories, including resource counters when the agent supplies them, collection warnings and truncation flags. |
| `services` | TrueNAS pools, topology/RAID details, datasets, apps, alerts, metrics and collection warnings as returned by the collector; Plex responsiveness, libraries, sessions and media-read result. Lists are split into individual records. |
| `proxmox` | Explicitly linked objects, status, API connection identities and collected allocations/metrics. Allocation is not guest filesystem free space. |
| `network_logs` | Redacted, paginated historical syslog/CEF events associated with this host, observed device/port fields and maintenance context. Logs are untrusted evidence, never authorization. |
| `network` | Saved host interfaces and observed uplinks, including freshness and the distinction between confirmed cabling and inferred forwarding paths. |
| `unifi` | Saved console device/client/port/network readings and endpoint errors for linked consoles or consoles explicitly enabled for AI context. |
| `history` | Saved metric samples from the host, linked Proxmox objects and integrations, including individual TrueNAS pool/app samples. |
| `check_history` | Recent check observations with time, result and redacted evidence. |

On the Hermes Codex companion, enable the existing operational host-tool option to use these retrieval actions. The tool-free API gateway mode receives its bounded initial snapshot and cannot issue follow-up tool calls.

Use `aiticket_host` with `action: evidence`, a `source`, optional affected `machine_id`, `offset` and `limit`. Pages contain at most 50 records and return `next_offset`; callers should continue until it is null. History is limited to the newest 1,000 records within seven days and explicitly reports truncation. Each page has a 50,000-character item budget; individual readings exceeding 20,000 characters are replaced by a truncation notice. Offset is capped at 10,000. Collector limits still apply: pagination exposes everything retained, and does not recover data the agent or upstream API never collected.

`action: refresh` accepts only a saved TrueNAS/Plex `connection_id` belonging to an affected host and runs the existing fixed, read-only collector. Network refresh remains available through `action: network`. Concurrent integration collection returns a collecting status. Connection edits and credential changes fence stale refresh results. These operations do not grant arbitrary API or shell access.

The available sources are the application's collected evidence. Docker logs, every process command line, full packet paths, historical inventory changes and playback/transcoding verification are not automatically collected by this change. Plex media access remains a sample read through Plex, including SMB-mounted files; it does not verify every file or the whole SMB service.

## Related tickets

**Affected hosts & services** lists the primary investigation and related failures with their host and current ticket state. Each ticket retains its source checks, observations, timeline and independent recovery. Resolving the primary ticket does not resolve related tickets. A closed ticket is labelled recovered only when its report records healthy monitoring.

Expand **Link a ticket or host** to attach an active ticket with a short explanation, or attach another host for read-only troubleshooting context. **Separate** restores independent coordination and prevents that pair from being automatically regrouped; it retains both histories. Additional hosts can be removed. Groups support 30 tickets and 20 additional hosts per ticket; groups cannot be nested.

Automatic grouping uses explicit application check dependencies and compatible parent/Proxmox hosting reachability failures with fresh observations. Similar timing alone does not create a group. Relationships are evidence of a possible shared cause, not proof. Existing same-host source grouping and manual merge behavior remain available.

The primary investigation receives affected ticket checks and can retrieve read-only evidence from attached hosts. Commands and Proxmox operations remain bound to the execution's original ticket target and its current permissions. Linking hosts never expands command authority. Start a separate explicit investigation on another ticket when changes on that host are needed.

Automatic members defer to an eligible active primary investigation. A primary under maintenance, below the configured severity threshold, controlled by a human, paused, or with completed/failed AI work does not indefinitely hold up independent member investigation. Automatic grouping avoids attaching tickets that already have AI history or are controlled by a human.

Pending opening notifications for related tickets are superseded when the primary has an eligible notification policy. The primary's notification lists affected hosts and states. Recovery notifications remain independent and respect existing notification policies. Messages already delivered are not recalled; reminders and escalation retain their existing per-ticket behavior.

## Maintenance and manual troubleshooting

Existing Policies schedules and check snoozes now gate AI admission and new AI changes as well as their existing monitoring/notification suppression. Scope remains global, or a host and its explicit descendants; grouping never extends maintenance to unrelated hosts.

During an active window:

- Monitoring and evidence collection continue. Maintenance does not resolve tickets.
- New automatic investigations are not admitted. Queued automatic work waits and requires fresh source results after maintenance ends before dispatch.
- Running AI may finish diagnostics and report findings, but new modifying shell/Proxmox requests are blocked.
- Queued modifying agent commands are checked again before agent execution. Already admitted running commands and in-flight HTTP operations are not forcibly interrupted.
- Explicit **Investigate with AI**, reply and resume actions remain available. They default to diagnostics during maintenance. To permit changes for that manual run, select **Allow this manual investigation to make changes during maintenance**. Normal host access, approval and execution limits still apply.

Read-only classification is intentionally conservative. An unrecognized shell command requires the manual change choice even if the administrator intended it as a diagnostic. Proxmox GET requests remain read-only. An approved queued Proxmox write is checked again against the originating AI job before it executes. Direct administrator power/command actions remain explicit manual operations under their existing controls.

Automatic work does not replay blocked commands after maintenance. Existing execution expiration and budgets remain in force; long windows can expire a queued run. A new eligible investigation may be admitted afterward under the existing limits. Weekly windows follow their configured timezone; one-time windows show their end in the ticket banner.

## Validation

Fixture tests cover schema-37 upgrades, automatic origin reconstruction, admission and queued dispatch gates, manual diagnostics/change choice, agent execution and Proxmox approval rechecks, read-only refresh scoping, credentials, evidence pagination/history, explicit dependency grouping, separation exclusions, independent recovery, notification consolidation and authenticated ticket controls. Local visual review uses disposable fixtures. No live infrastructure commands, API keys, model calls or notifications were used.
