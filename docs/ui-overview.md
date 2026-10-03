# Dashboard, Hosts, Tickets and navigation

The top bar contains Menu, Search and Appearance. Move the mouse to the left edge to open the scrollable navigation drawer, or click Menu on any device. Escape closes it. **Cmd+K / Ctrl+K** opens search for pages, hosts, discovered Proxmox resources, checks and tickets. Arrow keys select a result; Enter opens it. Search results follow normal administrator authentication.

## Dashboard

The compact overview shows open tickets, all tickets, enrolled nonrevoked agents and tickets created in the last 30 calendar days. Fleet graphs show CPU, RAM and storage history over 24 hours, in 15-minute intervals. Each host has equal weight; linked agent telemetry takes precedence over Proxmox telemetry to avoid counting a VM twice. Network Devices have their own workspaces and are excluded from host performance averages. Missing values leave gaps. Storage percentages mix root filesystem usage and Proxmox-reported allocation, depending on the available source.

Thirty-day ticket graphs show creation counts, average elapsed time from creation to closure, and the percentage requiring manual intervention. Resolution time includes waiting; the Tickets work timer excludes waiting. Intervention means a recorded blocker, human work session or explicit takeover. Creating a manual ticket alone does not count as intervention. Days without applicable tickets have no resolution or intervention value. Charts use retained history; earlier data is not reconstructed.

## Hosts

Hosts is a compact list; selecting a machine opens its metrics, checks and ticket history. Discovered, unassigned Proxmox nodes/guests also appear and link to their inventory workspaces. UniFi appliances remain under Network Devices.

- Green: fresh telemetry and no failing or retrying checks.
- Yellow: a check is failing/retrying, or telemetry is missing/stale.
- Red: enrolled agent heartbeats are stale/missing, or an enabled critical check is down.
- Grey: an administrator marked the machine intentionally offline, or fresh Proxmox inventory reports its linked VM/container stopped.

Proxmox stopped state must be fresh (within 180 seconds). It explains absent guest heartbeats but does not prove that an application recovered. Stale readings are not presented as current metrics in the list.

All host configuration is accessed through **Host settings**, including enrollment tokens and credential rotation. **Add check** is available at the top of the host workspace.

### Intentional offline

Open **Hosts → your host → Host settings → Host availability** and choose **Mark intentionally offline**. This resolves open tickets whose sources are exclusively agent heartbeat or linked Proxmox guest reachability checks, records your explanation and queues the normal recovery notification. It does not claim a successful health observation. Incidents containing an unrelated service/application source remain open.

Reachability checks remain paused until you choose **Resume monitoring**. Application checks continue independently. A freshly observed Proxmox stopped VM also suppresses new heartbeat alerts, while the VM's own expected-state check remains meaningful.

## Tickets

Tickets replaces History in navigation, with both open and resolved tickets newest first. Existing History links still work for legacy filters and archives. The category cards filter the list:

- **New / queued** (grey): open, awaiting investigation.
- **AI working** (blue): a dispatched/running AI investigation.
- **Needs attention** (red): active blocker, approval needed or human ownership.
- **Resolved** (green): closed ticket.

Priority and agent are near the left, followed by host, subject, work timer and creation time. Search narrows by subject, host or ticket ID. The list is paginated at 50 tickets. Work time totals recorded AI/human sessions; active timers tick each second. Dashboard, Hosts and Tickets refresh stored information automatically every five seconds while preserving active forms. Appearance supports Light, Dark and System.

## Upgrade

On the main application VM:

```sh
cd /opt/aiticket
git pull --ff-only origin main && sudo docker compose up -d --build
```

Schema 31 adds persistent intentional-offline state automatically. Agent and Hermes installations need no update for this UI milestone.
