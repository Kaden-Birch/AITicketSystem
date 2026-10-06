# Dashboard

The main dashboard combines current host/check health, up to five open tickets, human decisions, Proxmox compute nodes, TrueNAS pools and workloads, connected applications, and compact UniFi equipment cards. The existing left-side navigation is unchanged. The page refreshes every five seconds; collection still follows each integration's schedule.

Open tickets are ordered by severity, then latest timeline update (or creation time). The section disappears when there are no open tickets. Human decisions have a separate compact list. Closed tickets are excluded from both lists.

Proxmox cards feature up to three running guests ranked by their share of node CPU plus RAM, using current inventory. CPU shares include the guest's allocated vCPU count; RAM uses bytes, rather than comparing percentages of differently sized guests. Offline/stale nodes do not display a current ranking. Load lights animate sequentially; resource bars smoothly change width and color. Reduced-motion preferences disable those animations.

TrueNAS cards support multiple hosts, pools, and dynamically sized drive inventories. Reported SSDs are half the width of HDDs; unreported media types are not inferred from model names. Pool status, capacity, drive errors and workload state remain separate. Stopped workloads are neutral. Missing or stale readings remain unknown.

UniFi ports are colored by negotiated speed: gray disconnected, yellow below 1 Gb/s, green 1 Gb/s, orange 2.5/5 Gb/s, blue 10 Gb/s, purple above 10 Gb/s. Dashed gray indicates unknown speed. AP rings show reported radio airtime; absent radio telemetry is not synthesized. NAS/NVR strips show reported storage only. Camera/NVR summaries appear only when corresponding device inventory is reported. The existing Network/Drive connector does not collect Protect recording streams or a complete Protect camera inventory; this dashboard does not imply that it does.

Unlinked equipment sections are hidden. Device, node, guest, drive and workload links lead to their existing workspaces. Monitoring rules, ticket creation, recovery, permissions and AI decisions are unchanged.

Resolution charts support seven or thirty days, mouse/touch inspection and keyboard arrow keys for exact daily values. Days without closures leave resolution gaps. Graph values use the configured display timezone for daily aggregation.

Update/rebuild the main application to install this dashboard. No agent update or database migration is required.
