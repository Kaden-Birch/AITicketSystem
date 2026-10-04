# Agent installation

Choose [Linux](#recommended-one-command-installation-or-upgrade) or the [Windows installer](agent-windows.md). Both report to the same application and use the same host access modes, checks, ticket workflows and independent signed update channel.

## Recommended one-command installation or upgrade

Run on the monitored Ubuntu/Debian host (curl must be available):

```bash
curl -fsSL https://raw.githubusercontent.com/Kaden-Birch/AITicketSystem/main/agent/install.sh -o /tmp/aiticket-agent-install.sh && sudo bash /tmp/aiticket-agent-install.sh --server http://10.128.2.203:8080
```

For a new host, open **Hosts → your host → Host settings** and create an enrollment token first, then enter it at the installer's hidden prompt. The installer downloads and verifies the agent bundle, installs all modules, enables local shell execution, enrolls and restarts the service automatically, then verifies its effective permissions. Upgrades preserve enrollment and execution history and do not require another token. HTTPS servers can add `--ca /absolute/path/to/ca.pem`. Run without `--server` to be prompted for the application URL on a fresh installation.

Every installation runs as root with local command execution enabled and access to the system Docker daemon when installed. The application host access mode controls which remote commands are admitted; choosing Full access requires no additional local policy edits. The installer adds a full-access drop-in to override the old standard restrictions, including private-user and dynamic-user isolation. Its postflight checks the effective unit settings, running process root UID/GID, required account/file capabilities, installed agent command and validated root-owned shell policy. Conflicting custom restrictions cause installation to exit with a clear failure instead of claiming success. It does not install Docker or alter the main application's permissions. Local limits allow up to one hour and 65536 bytes; application limits still apply. Read-only and approval modes are configured in Host settings on the main application.

## Verify and troubleshoot

Allow one reporting interval after installation, then open Host settings in the application. Local shell capability should be available; choose the application access mode you want. Docker monitoring requires Docker to be installed and its daemon running. Use container names rather than IDs for checks that should survive container replacement.

```bash
sudo systemctl status aiticket-agent --no-pager
sudo journalctl -u aiticket-agent -n 50 --no-pager
```

The agent has no inbound listener. Enrollment identity and command history persist through upgrades and DHCP changes; no agent IP is configured. The installer starts the service automatically after token entry and restarts it after upgrades. It also installs the independent automatic updater described below.

### Permission verification

`SystemCallFilter=~` is an empty systemd deny list and does not restrict commands. The installer accepts it; actual syscall filters still fail verification. If an older installer flags this value, rerun the current installer to update the checker while preserving enrollment.

A successful installation prints **Permission check passed**. If the check fails, inspect the reported properties and all service drop-ins:

```bash
sudo systemctl cat aiticket-agent --no-pager
sudo systemctl show aiticket-agent -p User -p Group -p ProtectSystem -p ProtectHome -p NoNewPrivileges -p PrivateUsers -p DynamicUser
sudo python3 /opt/aiticket-agent/install_verify.py
```

Correct conflicting custom restrictions and rerun the same installer. Enrollment is preserved. A container or hosting platform can also restrict root capabilities; the installer reports those limits but cannot grant privileges the platform denies. This verifies local command prerequisites, not the success of every possible command or application-side permissions.

After a heartbeat arrives, choose **Full access** in the main application's Host settings if fleet changes should execute without approval. The installer does not override that administrator-selected access mode. Retry only failed/blocked fleet targets after checking their existing results; successful targets need no repeat.

## Credential rotation

Rotate credentials through **Hosts → your host → Host settings**. Stop the service and deliberately remove `/var/lib/aiticket-agent/identity.json` after revoking the old enrollment, then rerun the installer with the replacement token. Keep other state files and command ledgers. The server retains machine links and incident history. Do not remove identity during a normal upgrade.

## Optional diagnostics and recovery

For service aliases, diagnostic logs and the separate recovery broker, see [remote commands](remote-commands.md) and [the broker guide](action-broker.md). Preserve the `commands` section when editing local policy. The current installer runs as root; older instructions describing an unprivileged service apply only to custom legacy installations.

## Uninstall

Revoke the agent in the application, then remove its service and installed files:

```bash
sudo systemctl disable --now aiticket-agent
sudo rm -f /etc/systemd/system/aiticket-agent.service
sudo rm -rf /etc/systemd/system/aiticket-agent.service.d
sudo systemctl daemon-reload
sudo rm -rf /opt/aiticket-agent /var/lib/aiticket-agent /etc/aiticket-agent
```

Incident history remains in the main application. These commands remove the local enrollment and execution history.

For main VM installation, see [HTTP installation](installation-http.md) or [HTTPS installation](installation.md).

Resource thresholds are configured centrally under **Agent health**, with optional per-host overrides in Host settings. See [health preferences](resource-diagnostics.md). No local rule creation or agent update is needed for these preferences.

## Network interface inventory

Agent 0.8.0 includes optional read-only interface, bridge, bond and existing LLDP discovery. Rerun the installer to install every required file, including `network.py`, and restart automatically while preserving enrollment. No new enrollment token is required for an upgrade. Missing optional discovery tools do not stop heartbeats. See [host network topology](network-topology.md) for switch-port associations, multiple uplinks and AI context.

## Independent automatic updates

Run the recommended installer once on each existing host after upgrading the main application. This adds `aiticket-agent-updater.service` and its five-minute timer; it preserves enrollment and credentials. New installations include them automatically. No further manual agent updates are normally needed.

The updater is a separate root-owned Python program and systemd service. It does not import the monitoring agent, use its heartbeat loop, call an AI model, or depend on the ticket application's availability to download releases. It retrieves a signed stable manifest from this repository's GitHub Releases, verifies the pinned Ed25519 public key and archive checksum, stages only the agent's seven permitted modules, validates syntax/imports, and atomically switches the active release. GitHub HTTPS access, system Python, OpenSSL and a functioning host are required. Existing HTTP enrollment opt-in affects application reporting only; release downloads always verify HTTPS.

Automatic rollout starts with a deterministic ten percent of agent identities. The remainder wait 30 minutes after publication, plus the next timer cycle. This is staggered deployment, not a centrally monitored canary gate. Updates wait for active commands/diagnostics to finish and command results to be saved. During probation, the main application accepts telemetry but dispatches no commands, diagnostics or power actions. A successful authenticated heartbeat from the new version must arrive within two minutes. Failed or interrupted updates restore the previous release and do not automatically retry that same failed release. A newer corrective release remains eligible, even when the monitoring agent is broken. If the main application is also down during probation, verification fails and the updater rolls back honestly.

Host settings show installed and available versions, automatic update state, last updater contact, and readable progress/failure information. **Update now** requests the next independent updater cycle and bypasses rollout delay; it does not bypass signature checks, active-work deferral or failed-release suppression. Updater contact does not count as a monitoring heartbeat or establish application health. Hosts without the updater show a one-time setup instruction. A revoked enrollment cannot report status or receive manual update requests.

Inspect the independent updater locally:

```bash
sudo systemctl status aiticket-agent-updater.timer --no-pager
sudo journalctl -u aiticket-agent-updater.service -n 50 --no-pager
sudo systemctl start aiticket-agent-updater.service
```

Automatic updates default enabled. To pause them locally, set `automatic` to `false` in `/etc/aiticket-agent/updater.json`; the updater still checks releases and reports availability. An administrator's Update now request remains usable. The updater and trust anchor themselves are deliberately outside automatically replaced agent bundles; upgrade those with the installer when required. The update process retains identity, enrollment credentials, local command policy and execution ledgers. It never replays an uncertain command. Release folders are retained for rollback.

## Publishing agent releases (maintainers)

`.github/workflows/agent-release.yml` validates Linux updater tests and native Windows runtime/installation tests and publishes when agent files change on main, or on manual dispatch. It signs manifests using the repository's encrypted `AGENT_RELEASE_SIGNING_KEY` secret. The public key is committed in `agent/release-public.pem`; private key material must never be committed. An immutable `agent-VERSION+COMMIT` release contains separate Linux and Windows archives; `agent-stable` contains separate signed Linux and Windows channel manifests. Publication refuses a signing-key mismatch and never overwrites an existing version's archive. Retain a protected backup of the signing key. Replacing the signing key requires deliberate trust-anchor deployment to installed updaters.

Only release bundles are fetched from GitHub. Application enrollment credentials are sent to the configured application endpoint, never to GitHub. A stopped VM, lost network connection, broken Python/OpenSSL installation or failed updater requires infrastructure recovery; an independent updater cannot repair a host it cannot run on.

## Automatic manual power controls

Root installations advertise host restart and shutdown automatically (agent 0.10.1 or newer). The main application uses the existing enrollment identity for exact, administrator-confirmed power jobs. No separate power credential or enablement page is needed. Explicit local power restrictions remain effective. Linked Proxmox resources use their existing cluster token instead; see [host power controls](host-dashboard.md#automatic-power-controls).
