# Ticket workspace, appearance and work sessions

The ticket creation form contains a title, searchable machine selection, priority,
issue description, assigned AI agent (currently Hermes), and three handling modes.
Selecting AI handling respects the existing automatic investigation switch,
minimum severity, bridge validation and usage limits. It does not enable AI globally.
Human and paused modes hold automatic investigation. Machine previews and the
saved ticket sidebar retain the explicit Proxmox association.

The saved ticket has a summary at the top, machine details on the left, a session
work log and conversation in the main column. Raw evidence, diagnostic requests,
usage details, recovery proposals, grouping, silence and archival remain under
**Technical evidence & advanced controls**. Host command history and approvals
are linked directly from the ticket. Existing detailed findings remain accessible.
New operational AI responses are instructed to use two or three short sentences
about the findings, actions, verification or help needed.

## Appearance

Choose **System**, **Light** or **Dark** in the application header. The browser
remembers the selection. System follows the operating system appearance. The
choice applies throughout the application, including sign-in.

## Work sessions

AI time starts when the bridge begins a permitted Codex execution or reports that
it is running; assignment and queue time do not count. Each session records the
start, duration, outcome and a bounded work summary. It stops at a blocker,
completion, failure, interruption, user takeover or resolution. A resumed
investigation creates another session in the same ticket. It is elapsed handling
time, not a token or billing measurement.

**Start my timer / Stop my timer** is optional human tracking. Opening a page or
taking control does not start a human timer. No timesheet or required work note
is needed. Active timers and totals tick every second; server state survives
browser refreshes. Background lifecycle checks reconcile stopped/expired runs.
Session history starts with this upgrade; earlier runs are not assigned invented
durations.

**AI handles it**, **I'm handling it** and **Paused** are separate controls with
the current mode highlighted. Switching from manual control back to AI resumes
the saved task under current validation and limits. Use the reply field to change
or clarify that task. In-flight commands may still be stopping; inspect their
actual state in the machine workspace.

## Blockers and notifications

The operational AI tool's `block` action records a short request for information,
permission or human intervention. Awaiting command/API approval and automatic
admission failures are also surfaced. The work timer stops and a prominent
banner explains what is needed. Failed or uncertain runs retain their honest
outcome and can request administrator attention.

Discord blocker notifications use the existing durable delivery queue, machine
and group notification policies, severity thresholds, maintenance and silence.
Identical active blockers do not enqueue another notification; changed blockers
receive a new event. Cleared blockers are suppressed before delivery. Network
ambiguity can still cause webhook duplicates, as with other notifications.

In **Settings → Discord**, configure **Public application URL**, for example
`https://tickets.example.com` (include a proxy path prefix if required), and
**Notify when AI needs human help**. Notification links append the actual ticket
route `/incidents/<ticket UUID>`. The public URL does not affect agent or bridge
network addresses. Leave it blank to omit links until an address is configured.

Provide clarification through **Reply & resume AI**. Approval must still be given
in the machine workspace. Preapproved queued commands may finish after a successful AI run. Explicit takeover, cancellation, expiry and permission changes still fence them.
Requests requiring approval remain subject to explicit administrator approval,
current host policy and expiry; expired/cancelled requests need a fresh request. Resumption
never replays an operation whose outcome is unknown.

On independently verified recovery, the same saved brief resolution text appears
at the top of the ticket and in the Discord recovery notification. AI-requested
closure still waits for fresh healthy monitoring. Administrator closure is
identified as such; AI prose alone is not a health check.

## Upgrade

On the **main application VM**:

```sh
cd /opt/aiticket
git pull --ff-only origin main
sudo docker compose up -d --build
curl --fail http://127.0.0.1:8080/health
```

On the **Hermes VM**:

```sh
sudo systemctl stop aiticket-hermes-bridge
sudo git -C /opt/aiticket-hermes pull --ff-only origin main
sudo systemctl start aiticket-hermes-bridge
sudo systemctl status aiticket-hermes-bridge --no-pager
```

No monitored-agent update is needed for this milestone. Keep operational host
command tools enabled on both the main app and bridge for AI blocker requests.
Run the signed compatibility check after upgrading. Existing tickets, monitoring,
command policies and approval requirements are preserved. Database schema 23 is
migrated automatically; take the normal application backup before upgrading.

## Verification

Fixture tests cover session deduplication, waiting-time exclusion, failed runs,
optional human timers, same-ticket clarification/resumption, authenticated blocker
requests, public URL validation and Discord links/stale blocker suppression.
Browser checks cover dark appearance, creation, machine selection, ticket layout,
live timers, blocker appearance and preservation of an unsent note. No real model,
Proxmox mutation or Discord delivery is performed by these tests.
