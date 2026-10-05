# Agent recovery and operational attention

## Needs attention

Open **Needs attention** in the sidebar, or its count on the dashboard. It combines disconnected agents, failed or blocked updates, missing updater setup/contact, available releases, incomplete TrueNAS/Plex/UniFi connections, Proxmox refresh errors, Hermes connection problems, interrupted or overdue investigations, unresolved ticket blockers, and failed notifications.

Categories, search and 20-item pages keep the initial view compact. Items link to the existing host, update, connection, ticket or delivery controls. The page refreshes automatically and items disappear when their underlying state recovers; opening an item does not acknowledge or hide it. Notification issues are grouped by channel/outcome; old failed deliveries remain visible until their delivery state changes. A Proxmox endpoint error is a refresh issue, not evidence the entire cluster is down.

Revoked agents are excluded. Agent disconnects and collection availability issues are excluded for intentionally offline hosts and active maintenance, including inherited maintenance. Failed updates and unresolved tickets remain visible for explicit review. This page does not bypass maintenance policies or retry uncertain commands/messages.

## Compatibility before activation

The independent updater verifies the signed manifest, archive checksum and permitted module contents, then reads the release's static compatibility requirements without importing or executing monitoring code. It uses the saved enrollment to ask the main application whether the required heartbeat protocol and diagnostic capabilities are supported. That read-only check does not count as a heartbeat or grant host commands.

Installer upgrades also check compatibility before stopping the existing agent, using its saved enrollment. First-time installation still needs enrollment before authenticated checks are possible.

If compatibility cannot be confirmed, the update is **Blocked** and the currently installed agent remains running. Update the main application first, or correct application connectivity, certificate trust or enrollment. Automatic checks retry the preflight on later cycles. The updater can fetch and stage a corrective release even when the monitoring process is broken, but it needs the application reachable for compatibility and the subsequent authenticated probation heartbeat.

Release publication now also tests real Linux and Windows capability builders against the application's compatibility endpoint and heartbeat validator, before signing. This covers protocol compatibility, not every production permission or network condition.

**Existing installations must rerun the current installer once to upgrade the independent updater and its support module.** Automatically swapped monitoring bundles deliberately do not replace the updater itself. Existing enrollment and credentials are preserved. Older updaters do not acquire these flags or preflight checks merely by installing a new monitoring bundle.

## Local update now

After upgrading the updater, run on the affected Linux/Proxmox host:

```bash
sudo python3 /opt/aiticket-agent/updater.py --now
```

On Windows, use Administrator PowerShell. The task's configured Python path supports both the dedicated runtime and custom Python installations:

```powershell
$python = (Get-ScheduledTask -TaskName AITicketAgentUpdater).Actions[0].Execute; & $python 'C:\ProgramData\AITicketAgent\updater.py' --now
```

`--now` skips rollout delay and the local automatic-update pause. It works without the web UI or a functioning monitoring loop. It does not skip compatibility, signatures, archive validation, active-work locks, independent heartbeat verification or rollback. Another running updater cycle holds the same exclusive lock.

## Deliberately retry a failed release

The updater normally remembers failed releases to avoid repeatedly breaking a host. After correcting the cause, explicitly retry on Linux:

```bash
sudo python3 /opt/aiticket-agent/updater.py --now --retry-failed
```

Or on Windows:

```powershell
$python = (Get-ScheduledTask -TaskName AITicketAgentUpdater).Actions[0].Execute; & $python 'C:\ProgramData\AITicketAgent\updater.py' --now --retry-failed
```

This retries the currently signed stable release, not an arbitrary version or download. It still verifies compatibility before stopping the previous agent. A failed retry restores the previous version and remains suppressed until another explicit retry or a newer release. Do not delete enrollment or manually clear execution ledgers.

Host settings → Agent updates includes an expandable local-command guide. Installed/latest versions, blocked/failed/rollback states and updater contact remain visible even if the monitoring heartbeat has stopped.
