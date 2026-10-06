# AITicketSystem — LAN Incident Manager

Self-hosted monitoring with useful incidents even when AI and the internet are unavailable.

**Status: monitoring plus configurable AI operations; the full product is not complete.** AI defaults to disabled pending installed-Hermes/provider validation. API mode enforces per-call token and configured-price allowances through its budget gateway. Optional [Hermes Codex subscription mode](docs/hermes-codex.md) uses a dedicated OAuth login and separate run/time limits, without an API key or API spending meter. General host commands and operational Hermes tools default to disabled and require local/host permission. Recovery defaults to disabled; approval-required controls support allowlisted service recovery and separately enabled manual host/guest power operations.

Included: a compact fleet dashboard, searchable slide-out navigation, host workspaces, a unified Tickets list, Proxmox guest status, ticket history, authenticated UI, stable machine inventory, HTTP/TCP and read-only Proxmox checks, configurable failure/recovery thresholds, parent suppression, temporary maintenance, deterministic reports, manual notes/resolution, durable Discord delivery, filtered incident history, immutable configuration audit, transactional schema upgrades, and DHCP-safe Linux agent enrollment/telemetry.

Ticket investigations include [evidence coverage, related tickets and maintenance-aware AI controls](docs/investigation-evidence.md). Related failures retain independent recovery and exact-target permissions.

## Local development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m aiticket init
AITICKET_LOCAL_HTTP=1 .venv/bin/python -m aiticket serve
```

Open http://127.0.0.1:8080. Initialization prompts for the administrator password. The local HTTP option is only for loopback development; HTTPS is the default; direct HTTP requires the explicit setting in the HTTP installation guide. There is no default password or preconfigured infrastructure target.

## Ubuntu 24.04 deployment

For direct HTTP on the main VM and agents, follow the [HTTP installation guide](docs/installation-http.md). Set the explicit transport opt-in and bind address through the supplied `.env.http.example`. Your existing reverse proxy may provide optional HTTPS access.

Follow the [complete main VM and monitored-host installation guide](docs/installation.md) for HTTPS, administrator setup, agent enrollment, verification and upgrades.

```sh
docker compose build
docker compose run --rm app python -m aiticket init
docker compose up -d
```

Compose defaults to Ubuntu loopback port 8080; `AITICKET_BIND_ADDRESS` configures the exposed interface. Supply a trusted TLS reverse proxy pointing to that port. Agents use the static application IP; certificates must include that IP as a SAN. Browser access can use DNS. No router, VLAN, Proxmox cluster or production configuration is changed by this project.

Database and encryption key persist in separate named volumes. Protect the key separately; losing it makes credentials unreadable. The container runs unprivileged with dropped capabilities.

## Setup

Add a machine, optionally specifying its parent dependency. Add an HTTP/TCP check or a Proxmox HTTPS check with a read-only token. Selected Proxmox resource IDs such as `qemu/209` are explicit configuration, not defaults. Intentional stopped guests can have expected state `stopped`; templates are never automatically added. Enter a Discord webhook in Settings if wanted. Enroll Linux agents using the [agent guide](docs/agent.md).

All IPv4 destinations are permitted (`0.0.0.0/0`) as requested. Router/VLAN firewalls enforce network restrictions. This release has no CIDR filtering. Agent authentication, administrator login, CSRF and no-redirect checks remain enforced. HTTPS verifies TLS; optional HTTP has no transport encryption.

## Testing and scope

```sh
.venv/bin/pip install pytest
.venv/bin/pytest -q
```

Tests use temporary databases, Flask clients and mocked providers. No live infrastructure, Discord, Hermes, model or backup endpoint is contacted.

See [architecture and scope](docs/architecture.md), [acceptance coverage](docs/acceptance.md), [Hermes gate](docs/hermes-contract.md), [recovery guide](docs/recovery.md), and [execution results](docs/test-results.txt).

Milestone 2 adds schema 1 → 2 migration, immutable audit/timeline storage, atomic settings saves, and paginated history filters. Existing evidence is retained; changes predating the audit milestone are not reconstructed.

Milestone 3 adds [Proxmox discovery and linking](docs/proxmox.md): reusable connections, connection/capability results, explicit cluster namespaces, duplicate endpoint handling, migration-aware parents, template exclusion and source retirement/unlinking with preserved history.

Milestone 4 adds [conservative source correlation](docs/correlation.md), separate source evidence, uncertain related-incident links, and recovery that requires fresh healthy results from all attached sources.

Milestone 5 adds [agent resource rules and read-only diagnostics](docs/resource-diagnostics.md): sustained CPU/memory/disk/inode thresholds, capability reporting, incident-scoped diagnostic jobs, bounded service/process/log queries, and restart-safe execution/result tracking.

Milestone 6 adds [scheduled maintenance and notification policies](docs/maintenance-notifications.md): timezone-aware one-time/weekly windows, incident silence, coalesced reminders and persistent-severity escalation. Live deployment testing remains deferred.

Milestone 7 adds [administration and recovery](docs/recovery.md): routine-sample retention, nonsecret preference export/import, password change/console reset, agent rotation through re-enrollment, and offline encryption-key rotation. Schema 7 adds cleanup indexes. Live deployment testing remains deferred.

Milestone 8 adds [Hermes orchestration and budget admission](docs/hermes-contract.md), a companion bridge and restricted tool-free adapter, signed durable status polling, usage/reservation meters and cancellation. The installed Hermes v0.20.0 and live provider remain untested; runtime/provider verification must remain unchecked until those deferred tests pass.

Milestone 9 adds incident-scoped advice chat and selected-evidence exploration, immutable conversations, duplicate submission protection, and shared incident/global budget enforcement. Exploration analyzes already completed read-only diagnostics; it does not execute tools. Update the companion bridge alongside the application. Live testing remains deferred.

Milestone 10 adds persistent manual/AI investigation ownership, pause/take-control, immutable checkpoints and fresh read-only resume. Ownership generations fence old executions; queued manual diagnostics and AI investigations cannot overlap. Unknown provider usage stays reserved. Live testing remains deferred.

Milestone 11 adds [approval-required service recovery](docs/action-broker.md): immutable proposals, exact hash/version approval, separate action credentials, fresh failed-service checks, one attempt per incident, target locks, cooldowns and independent recovery verification. No live restart has been tested; activation requires explicit local and application validation.

Milestone 12 adds persistent scheduled Proxmox inventory refresh, new-resource review flags, visibility warnings and lease recovery. Explicit linking and retirement remain administrator decisions.

Milestone 13 adds conservative resource/outage relationships and explicit same-machine incident merging with preserved history and independent multi-source recovery.

Milestone 14 adds notification groups, per-machine/group overrides and visible effective policies, applied at enqueue, reminder/escalation and delivery time.

Milestone 15 adds atomic full inventory configuration transfer, reviewed check activation, immutable incident archive downloads, archive history filters and login/security auditing. Imported credentials and execution authority remain unavailable until locally restored and reviewed.

Milestone 16 adds budgeted AI preparation of recovery proposal text, immutable unverified drafts and reviewed conversion into the existing exact-approval broker. Update and recheck the Hermes companion/adapter before using this mode.

Milestone 17 adds [host dashboards and manual power controls](docs/host-dashboard.md): fresh/stale CPU, RAM, storage and uptime views, extra Linux metrics, node guest inventory, linked alert history, separate power credentials and exact-target approvals. Power defaults disabled; Proxmox node/storage shutdown remains protected. Live power permission/runtime validation remains deferred.

Milestone 18 adds [Hermes Codex subscription mode](docs/hermes-codex.md), schema 19, exact model/reasoning snapshots, transactional run limits, dedicated OAuth isolation and cancellation supervision. Live installed-Hermes/login/model validation remains pending.

Milestone 19 adds [host editing, Proxmox visibility and manual tickets](docs/host-editing-tickets.md): retained machine identity, late association with agent hosts, unassigned resource dashboard cards and node guest views, and user-reported machine-tagged tickets with explicit AI requests and independent resolution.

Milestone 20 adds [general remote commands](docs/remote-commands.md): arbitrary shell execution through outbound agents, per-host immediate/approval policies, isolated Codex command tools and independent Hermes MCP access, bounded results, cancellation, immutable identities and non-replaying dispatch. All execution access defaults disabled pending explicit local/GUI configuration.

Operational investigations preserve the current administrator task and linked Proxmox guest context. General token-authorized Proxmox API requests work without a live guest agent; see [remote command and Proxmox operations setup](docs/remote-commands.md).

Automatic AI investigations include eligible monitoring and manual tickets when enabled. AI can request verified resolution; fresh monitoring controls closure and recovery notifications include a brief summary.

Agent reporting is configurable down to 20 seconds in Settings. Dashboard, host and incident information updates automatically every five seconds while preserving unfinished forms.

Ticket workspace, dark appearance, work sessions and blocker notifications: [guide](docs/ticket-workspace.md).

[UniFi Network and experimental UNAS monitoring](docs/unifi.md) adds read-only telemetry, host checks and optional AI network context. No UniFi action or configuration tools are exposed.

Network Devices separates UniFi appliances from Hosts, with readable telemetry, seven-day metric history and device-specific availability tickets.

Fleet management: [SSH keys, users, packages and scripts](docs/fleet.md), with per-host permissions and execution results.

[Dashboard, Hosts, Tickets and navigation](docs/ui-overview.md): aggregate graphs, compact inventory, live ticket timers, category filters, global search and intentional-offline controls.

[Agent health defaults and host overrides](docs/resource-diagnostics.md): slider preferences, disabled-by-default fleet rules, host-specific settings and percentage/GB free-space thresholds.

Host [network topology](docs/network-topology.md) connects interface inventory and multiple switch/router ports with VM placement, recent link transitions, colored host tags and read-only AI troubleshooting context.

Linux agents now include an [independent signed-release updater](docs/agent.md#independent-automatic-updates), automatic rollout, heartbeat verification/rollback, and host-settings version/manual-update controls. Existing agents need one installer run to enable it.

Windows hosts use the [Windows agent installer](docs/agent-windows.md), with LocalSystem command access and independent signed automatic updates.

- [Investigation reliability, application health and workflow testing](docs/investigation-reliability.md)

TrueNAS SCALE / HexOS can be added directly through **Hosts → Add host → TrueNAS**, without an OS agent. Host-linked Plex server and media-read checks live under **Applications**. Linux/Windows agents also discover Docker containers and processes for one-click monitoring. See [TrueNAS, Plex and discovery setup](docs/storage-services.md).

[Settings, knowledge and diagnostics](docs/settings-and-knowledge.md): grouped settings, simpler Hermes activation, normal Hermes status queries, optional knowledge articles and AI drafting, container details/logs/trends, observed change history and allowlisted Telegram conversations.

UniFi syslog/CEF collection, searchable network events and AI troubleshooting evidence: [setup and limits](docs/network-logs.md).
