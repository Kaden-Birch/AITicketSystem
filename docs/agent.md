# Linux agent installation

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

The agent has no inbound listener. Enrollment identity and command history persist through upgrades and DHCP changes; no agent IP is configured. The installer starts the service automatically after token entry and restarts it after upgrades.

### Permission verification

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
