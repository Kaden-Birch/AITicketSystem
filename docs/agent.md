# Linux agent installation

## Recommended one-command installation or upgrade

Run on the monitored Ubuntu/Debian host (curl must be available):

```bash
curl -fsSL https://raw.githubusercontent.com/Kaden-Birch/AITicketSystem/main/agent/install.sh -o /tmp/aiticket-agent-install.sh && sudo bash /tmp/aiticket-agent-install.sh --server http://10.128.2.203:8080
```

For a new host, create an enrollment token in the main application first, then enter it at the installer's hidden prompt. The installer downloads and verifies the agent bundle, installs all modules, enables local shell execution, enrolls and restarts the service automatically. Upgrades preserve enrollment and execution history and do not require another token. HTTPS servers can add `--ca /absolute/path/to/ca.pem`. Run without `--server` to be prompted for the application URL on a fresh installation.

Every installation runs as root with local command execution enabled and access to the system Docker daemon when installed. The application host access mode controls which remote commands are admitted; choosing Full access requires no additional local policy edits. Existing unrelated custom systemd restrictions may still limit execution. The installer adds a full-access drop-in to override the old standard restrictions. It does not install Docker or alter the main application's permissions. Local limits allow up to one hour and 65536 bytes; application limits still apply. Read-only and approval modes are configured in Host settings on the main application.

The manual instructions below are retained for reference; the installer is the supported setup path.


For the complete main VM and agent walkthrough, see [installation.md](installation.md).

Requires Linux `/proc`, Python 3.11+, and verified HTTPS by default, or explicit HTTP opt-in. See [HTTP installation](installation-http.md) for `--allow-http`, which is persisted at enrollment. The unprivileged agent has no listener or shell execution. Read-only process/service diagnostics use a local allowlist and durable execution ledger. It never self-reboots or updates automatically.

Deliver reviewed files through an authenticated trusted channel and verify the artifact digest. Do not pipe unauthenticated LAN downloads into a shell.

On the intended guest after securely copying files:

```sh
sudo useradd --system --home /var/lib/aiticket-agent --shell /usr/sbin/nologin aiticket-agent
sudo install -d -m 0755 /opt/aiticket-agent
sudo install -m 0644 agent/agent.py /opt/aiticket-agent/agent.py
sudo install -m 0644 agent/diagnostics.py /opt/aiticket-agent/diagnostics.py
sudo install -m 0644 agent/monitoring.py /opt/aiticket-agent/monitoring.py
sudo install -m 0644 agent/actions.py /opt/aiticket-agent/actions.py
sudo install -d -o aiticket-agent -g aiticket-agent -m 0700 /var/lib/aiticket-agent
sudo install -m 0644 agent/aiticket-agent.service /etc/systemd/system/aiticket-agent.service
```

Generate an enrollment token on the machine's UI entry, then:

```sh
sudo -u aiticket-agent python3 /opt/aiticket-agent/agent.py enroll --server https://192.0.2.10 --ca /path/to/trusted-ca.pem
sudo systemctl daemon-reload
sudo systemctl enable --now aiticket-agent
```

Replace the documentation IP with the application's static IP/HTTPS port. The certificate must cover the IP SAN. Omit `--ca` only when system trust already includes the issuer. Enter the single-use token at the hidden prompt, never in shell history. No agent IP is configured.

Agent credentials persist mode 0600 through DHCP changes. Observed IPs may be NAT/proxy addresses; they do not authenticate agents. Stable telemetry event IDs suppress duplicate ingestion.

If the enrollment reply is lost, revoke the orphan agent through the UI and generate a new token. For re-enrollment, stop the service, revoke credentials, deliberately remove the old identity file and enroll again. The server preserves UUID/history while invalidating old credentials.

## Uninstall

Revoke in the UI, then inspect and run these agent-specific removal commands:

```sh
sudo systemctl disable --now aiticket-agent
sudo rm /etc/systemd/system/aiticket-agent.service
sudo systemctl daemon-reload
sudo rm -r /opt/aiticket-agent /var/lib/aiticket-agent
sudo userdel aiticket-agent
```

Incident history remains intact.

Optional local policy: create root-managed `/etc/aiticket-agent/policy.json` with `{"services":{"web":"nginx.service"},"logs":false}`. Only those service aliases are accepted. Logs require an explicit local opt-in and existing unprivileged journal access; do not grant broad root or journal permissions automatically. Policy changes are reloaded each heartbeat.

## Credential rotation

Select “Rotate via new enrollment” on Hosts & checks. This immediately revokes the current credential, expires queued diagnostics and invalidates other unused enrollment tokens for the machine. The replacement token expires in ten minutes. Stop the agent service, deliberately remove `/var/lib/aiticket-agent/identity.json`, then run the enrollment command above with that token and restart the service. Do this promptly to avoid a missing-heartbeat incident. The server preserves the agent UUID, machine links and historical records; no agent IP is needed. If the token expires, generate another enrollment token for the same machine.

## Optional service recovery

Recovery is disabled by default. Read [the broker guide](action-broker.md) before enabling it. A local policy may include:

```json
{"services":{"web":"nginx.service"},"logs":false,"recovery":{"enabled":false,"validated":false,"services":["web"]}}
```

Keep both recovery flags false until live validation is completed. Configure the exact service alias on the application Recovery policy page, explicitly classify the machine as an application target, and issue a separate action credential. Stop the agent and enter that credential at the hidden prompt:

```sh
sudo -u aiticket-agent python3 /opt/aiticket-agent/agent.py recovery-credential
sudo systemctl start aiticket-agent
```

The credential is stored in the existing mode-0600 identity file. Monitoring credential revocation or re-enrollment invalidates application-side action authority; issue a new separate credential afterward. Recovery execution identities remain in the durable ledger and are never evicted automatically.

The agent runs unprivileged and installs no privilege grant. An administrator must separately configure and validate narrowly scoped operating-system permission for the exact service. Do not grant broad root, sudo or unrestricted service-management access. The supplied systemd hardening remains in place. No actual service restart has been performed during development.

For metric host workspaces, Proxmox guest status, optional manual power controls and the matching agent upgrade, see [the host dashboard guide](host-dashboard.md).
