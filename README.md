# AITicketSystem — LAN Incident Manager

Self-hosted monitoring with useful incidents even when AI and the internet are unavailable.

**Status: initial runnable monitoring milestone, not the complete product.** AI investigations and all remediation are disabled. Budget settings are saved preferences, not enforced spending guarantees.

Included: authenticated UI, stable machine inventory, HTTP/TCP and read-only Proxmox checks, configurable failure/recovery thresholds, parent suppression, temporary maintenance, deterministic reports, manual notes/resolution, durable Discord delivery, filtered incident history, immutable configuration audit, transactional schema upgrades, and DHCP-safe Linux agent enrollment/telemetry.

## Local development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m aiticket init
AITICKET_LOCAL_HTTP=1 .venv/bin/python -m aiticket serve
```

Open http://127.0.0.1:8080. Initialization prompts for the administrator password. The local HTTP option is only for loopback development; production requires HTTPS. There is no default password or preconfigured infrastructure target.

## Ubuntu 24.04 deployment

```sh
docker compose build
docker compose run --rm app python -m aiticket init
docker compose up -d
```

Compose binds only to Ubuntu loopback port 8080. Supply a trusted TLS reverse proxy pointing to that port. Agents use the static application IP; certificates must include that IP as a SAN. Browser access can use DNS. No router, VLAN, Proxmox cluster or production configuration is changed by this project.

Database and encryption key persist in separate named volumes. Protect the key separately; losing it makes credentials unreadable. The container runs unprivileged with dropped capabilities.

## Setup

Add a machine, optionally specifying its parent dependency. Add an HTTP/TCP check or a Proxmox HTTPS check with a read-only token. Selected Proxmox resource IDs such as `qemu/209` are explicit configuration, not defaults. Intentional stopped guests can have expected state `stopped`; templates are never automatically added. Enter a Discord webhook in Settings if wanted. Enroll Linux agents using the [agent guide](docs/agent.md).

All IPv4 destinations are permitted (`0.0.0.0/0`) as requested. Router/VLAN firewalls enforce network restrictions. This release has no CIDR filtering. TLS, agent authentication, administrator login, CSRF and no-redirect checks remain enforced.

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
