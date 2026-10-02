# Host editing, Proxmox visibility and manual tickets

## Upgrade an existing HTTP installation

On the main VM, back up the application database and matching encryption key, then:

```sh
cd /opt/aiticket
sudo docker compose stop app
git pull --ff-only origin main
sha256sum -c SHA256SUMS
sudo docker compose build
sudo docker compose up -d
```

This milestone requires only the main application update. Agent and Hermes changes are not required. Existing machine IDs, enrollment credentials, monitoring checks and incident history are retained. There is no new database schema migration.

## Edit an existing agent host and link it to Proxmox

Open its dashboard card or **Hosts & checks → View / edit / link Proxmox**. Expand **Edit host & Proxmox association**. Save its display name and dependency in the left panel. Dependencies cannot form cycles; a linked guest's dependency follows its current Proxmox node.

In the association panel, select the exact discovered node/VM/container, choose its expected state and confirm the identity. A VM agent enrolled before Proxmox discovery can use this flow without reinstalling or re-enrolling. Linking retains the host ID and history and adds the existing Proxmox monitoring check. Names and IP addresses are never used to infer identity. Nodes and guests remain separate hosts; a machine cannot have multiple active node/guest associations. Manage unlinking and retirement under Proxmox; existing protections for outstanding power operations remain enforced.

If no resource appears, use **Proxmox → Discover / refresh** first. Resolve any certificate/authentication/visibility errors there. Connecting to an endpoint alone cannot populate resource metrics.

## Proxmox metrics on the dashboard

The dashboard shows saved Proxmox connections even before discovery. After discovery, unassigned nodes and guests have cards showing their stored CPU, RAM, storage and uptime values, with an explicit unassigned label. Templates remain in node inventory rather than the host card grid. Clicking an unassigned node shows all its discovered VMs/containers and their reported state; clicking a guest opens its own resource workspace.

A discovered workspace can be assigned to an existing host or explicitly create a new host with monitoring. Discovery itself does not enroll agents, enable power controls or assign monitoring. Linked resources share one host card with existing agent telemetry. A linked agent host also shows a separate Proxmox CPU/RAM/uptime snapshot so guest OS metrics and hypervisor metrics remain distinguishable.

Metrics are inventory snapshots, not a browser live stream. Configure automatic refresh under Proxmox (60 seconds is an available interval). Missing data is shown as unavailable; stale values are labelled. Proxmox disk allocation does not establish free space inside a guest filesystem; use agent telemetry for that.

## Open a manual ticket

Choose **Open ticket** on the dashboard or Hosts & checks, or **Open ticket for this host** in its workspace. Select the machine, title, description and severity. The host shortcut preselects that machine. Opening notifications are opt-in and still obey the machine's notification policy.

The ticket is labelled user-reported and appears in normal incident history and host history. Creation does not change monitoring health or automatically queue AI, even when automatic triage is enabled. You may explicitly request read-only AI triage or advice from the saved ticket using the configured integration limits. This also provides a way to perform your first Hermes trial without inducing an outage.

Resolve a manual ticket with a resolution note when complete. It closes independently and can then be archived. Monitoring recovery cannot close it, and it cannot be merged with monitored incidents. Its user-reported description is retained in the deterministic report and immutable timeline. Internally, a permanently disabled manual source preserves the incident foreign key; it cannot be enabled as a probe and is excluded from monitoring configuration export. Ticket archives retain the report and history separately.

All edits/linking/ticket creation require administrator authentication and CSRF validation and write audit records. Fixture tests cover late linking, parent updates, cycle rejection, retained ticket/agent identity, unassigned node guest views, manual closure, configuration export, explicit AI invocation and automatic-triage exclusion. Live infrastructure/power/provider operations were not used for development verification.
