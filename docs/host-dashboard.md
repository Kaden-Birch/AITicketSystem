# Host dashboard and manual power controls

Open **Hosts** and click a machine name for its dedicated workspace. The compact list shows availability, uptime, CPU/RAM/storage usage, last ticket creation, reporting frequency and check count. The detail page includes operating system, kernel, architecture, agent version, last heartbeat, load averages, memory pressure, swap, inode usage, monitoring sources and clickable previous tickets/alerts. Unavailable values are shown explicitly. Stored samples update automatically in the browser.

Agent telemetry is preferred for guest filesystem usage. Proxmox metrics are snapshots of the last successful inventory discovery/refresh, not a continuous live feed. Configure scheduled discovery under Proxmox; values older than 180 seconds are marked stale. A Proxmox node page lists all visible discovered VMs and containers on that node, including unassigned guests and templates, with state, metrics and links. Token visibility determines which guests can be discovered. Proxmox disk figures may describe allocated capacity; they do not establish a VM's actual free filesystem space. Enroll a guest agent for that information.

## Automatic power controls

Power buttons are available automatically after an agent is enrolled or a Proxmox resource is linked. There is no separate enablement, backend selection, token, or action credential to configure.

Linked Proxmox guests and nodes use the cluster connection's existing API token. The application checks effective `VM.PowerMgmt` permission for guests and `Sys.PowerMgmt` for nodes. The host page caches that read-only check for up to 60 seconds; creating a request and dispatching it check permission again. Read-only permission discovery can use another configured cluster endpoint. A power write is sent once to the selected endpoint and is never replayed through another endpoint if delivery is uncertain.

Without a Proxmox link, an enrolled Linux root or Windows SYSTEM agent automatically advertises restart and shutdown support. Its existing enrollment credential authenticates the exact manual power job; service recovery still uses its separate credential and policy. Older agents need the automatic agent update before this capability appears. Explicit local power restrictions continue to apply.

Start is available for stopped linked Proxmox guests. Restart and Shutdown are available for running guests, online Proxmox nodes, or fresh capable standalone agents. Storage and templates have no power controls. A Proxmox permission denial does not silently switch to agent execution.

Click an available power button, then confirm the operation for the displayed host. No reason or settings-page setup is required. Target changes, stale inventory, conflicting work, expired proposals and unresolved prior executions still prevent dispatch. Graceful shutdown and reboot retain independent verification. Agent shutdown can require manual acknowledgment because absence of heartbeats is not proof of successful shutdown. Proxmox node restart is verified from fresh cluster state and new uptime. A node reported offline after shutdown still requires independent manual confirmation; an offline status or API acceptance alone does not prove it powered off.

For editing existing hosts, linking previously enrolled agents, viewing unassigned Proxmox resources and opening manual tickets, see [host editing and tickets](host-editing-tickets.md).

## Host performance workspace

Each host now has current CPU, memory, storage and uptime cards, with retained history charts for all supported telemetry (load averages, swap, inodes and memory pressure where supplied). Select **1h / 6h / 24h / 7d**. History starts accumulating after the main application update and is retained for seven days. Missing samples leave gaps; lines show bucket averages and captions show actual minimum/maximum samples. Proxmox allocation and agent filesystem values remain distinct.

System details are in a compact sidebar. Checks expand to show evidence; open tickets and historical tickets are below. **Add check** at the top opens a form already scoped to this host. Configure permissions, host details, associations and check enable/disable through **Host settings**. Operational power controls remain available on the host page; command history is collapsed until needed.

Only update/rebuild the main application for this workspace (schema 25). No agent or Hermes update is required. Existing data and check settings are retained. Graphs refresh using the existing five-second live page updates; collection speed still depends on the agent reporting and Proxmox discovery intervals.

Update/rebuild the main application for automatic Proxmox controls. Agents update independently to 0.10.1 or newer for automatic standalone power capability. Existing identities and permissions are preserved.

For the approved four-graph workspace, automatic agent I/O collection, synchronized event markers and evidence panels, see [Host I/O history and event correlation](host-performance.md).
