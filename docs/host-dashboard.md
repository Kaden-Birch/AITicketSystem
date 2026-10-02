# Host dashboard and manual power controls

Click a host card on Dashboard (or its name in Hosts & checks) for a dedicated workspace. CPU, RAM, storage, uptime and active alert counts appear on the cards. The detail page includes operating system, kernel, architecture, agent version, last heartbeat, load averages, memory pressure, swap, inode usage, monitoring sources and clickable previous tickets/alerts. Unavailable values are shown explicitly. Refresh the page for the latest stored sample.

Agent telemetry is preferred for guest filesystem usage. Proxmox metrics are snapshots of the last successful inventory discovery/refresh, not a continuous live feed. Configure scheduled discovery under Proxmox; values older than 180 seconds are marked stale. A Proxmox node page lists all visible discovered VMs and containers on that node, including unassigned guests and templates, with state, metrics and links. Token visibility determines which guests can be discovered. Proxmox disk figures may describe allocated capacity; they do not establish a VM's actual free filesystem space. Enroll a guest agent for that information.

## Proxmox guest power

On a linked application's host page, expand **Configure power permissions**, choose **Proxmox guest power API**, select its cluster connection and enter a separate guest-scoped API token. The monitoring token cannot be reused. Grant the power token only the required guest audit/power and task-read permissions for the installed Proxmox version; consult its [API viewer](https://pve.proxmox.com/pve-docs/api-viewer/). The official [QEMU API implementation](https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu.pm) and [LXC API implementation](https://github.com/proxmox/pve-container/blob/master/src/PVE/API2/LXC/Status.pm) define the start, reboot and shutdown endpoints used here. Validate on a disposable guest before checking the validation/enabled boxes.

**Start** requires a stopped, explicitly associated Proxmox guest. **Restart** and **Shutdown** require a running guest. Templates, Proxmox nodes and storage cannot be powered through this application. Keep the monitoring VM, Hermes and other essential infrastructure protected. Enter a reason, create the proposal, review its exact identity/operation/impact and confirm **Approve once**. A migration, changed binding, stale inventory, expired proposal or changed policy invalidates the proposal. Shutdown is graceful; no forced stop fallback is sent. Restart calls the reboot API, rather than independently sending stop/start commands.

The worker persists dispatch before sending one request. Acceptance is followed by task/state verification. An ambiguous result blocks new power controls until you independently check the target and acknowledge it; this does not relabel the result as verified. Commands are never automatically retried. A five-minute cooldown applies after dispatch. Approval expires after five minutes. Planned shutdown does not rewrite expected monitoring states; use the existing maintenance/snooze controls first if appropriate.

## Linux agent restart/shutdown

An agent supports restart/shutdown, but cannot start a powered-off host. Prefer Proxmox guest power for guests. Agent execution requires all three of: the application power policy, a separate action credential and a root-managed local power allowlist. Existing monitoring installations gain no OS power permission automatically.

Add the following `power` section to `/etc/aiticket-agent/policy.json`, preserving existing service/recovery configuration:

```json
"power": {
  "enabled": false,
  "validated": false,
  "operations": ["host_restart", "host_shutdown"]
}
```

The agent runs fixed `/usr/bin/systemctl --no-ask-password reboot` or `poweroff` commands without a shell, sudo or privilege escalation. An administrator must separately configure narrow OS permissions for the `aiticket-agent` account if these commands should be allowed. Keep the unprivileged service account and hardened systemd unit; do not switch the entire agent to root. Test permissions on a disposable host, then explicitly enable and validate the local section and the application's policy. Issue the separate action credential on the host page and install it using the [existing action-credential procedure](agent.md#optional-service-recovery). Capability changes appear on the next heartbeat.

A fresh uptime sample and heartbeat are required. Restart is verified by new uptime; absence of a heartbeat alone cannot prove shutdown. Agent shutdown therefore requires independent manual confirmation. The permanent execution ledger prevents an acknowledged command from being replayed after a crash/restart.

## Upgrade an existing HTTP installation

Back up the matched database and encryption key using your normal procedure before the schema upgrade. On the main VM:

```sh
cd /opt/aiticket
sudo docker compose stop app
git pull --ff-only origin main
sha256sum -c SHA256SUMS
sudo docker compose build
sudo docker compose up -d
```

Do not run `init` again or delete volumes. Preserve `.env` and the existing Compose project name. Wait for health before opening the dashboard.

On each enrolled agent (adjust the source directory if different):

```sh
cd ~/aiticket-agent-source
git pull --ff-only origin main
sha256sum -c SHA256SUMS
sudo systemctl stop aiticket-agent
sudo install -o root -g root -m 0755 agent/agent.py /opt/aiticket-agent/agent.py
sudo install -o root -g root -m 0644 agent/diagnostics.py /opt/aiticket-agent/diagnostics.py
sudo install -o root -g root -m 0644 agent/monitoring.py /opt/aiticket-agent/monitoring.py
sudo install -o root -g root -m 0644 agent/actions.py /opt/aiticket-agent/actions.py
sudo systemctl start aiticket-agent
sudo systemctl status aiticket-agent --no-pager
```

Keep `/var/lib/aiticket-agent/identity.json` and its execution ledgers; reenrollment is unnecessary. Agent 0.4.0 adds OS information, CPU core count, swap and additional load averages. Earlier agents can still report their existing metrics.

Automated tests use mocked power endpoints/subprocesses. No real host/guest power operation has been run by development tests; live permission/runtime validation remains necessary before enabling controls.

For editing existing hosts, linking previously enrolled agents, viewing unassigned Proxmox resources and opening manual tickets, see [host editing and tickets](host-editing-tickets.md).
