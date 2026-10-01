# Linux agent installation

Requires Linux `/proc`, Python 3.11+, and verified HTTPS. The unprivileged agent has no listener or shell execution. Read-only process/service diagnostics use a local allowlist and durable execution ledger. It never self-reboots or updates automatically.

Deliver reviewed files through an authenticated trusted channel and verify the artifact digest. Do not pipe unauthenticated LAN downloads into a shell.

On the intended guest after securely copying files:

```sh
sudo useradd --system --home /var/lib/aiticket-agent --shell /usr/sbin/nologin aiticket-agent
sudo install -d -m 0755 /opt/aiticket-agent
sudo install -m 0644 agent/agent.py /opt/aiticket-agent/agent.py
sudo install -m 0644 agent/diagnostics.py /opt/aiticket-agent/diagnostics.py
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

Optional local policy: create root-managed `/etc/aiticket-agent/policy.json` with `{"services":{"web":"nginx.service"},"logs":false}`. Only those service aliases are accepted. Logs require an explicit local opt-in and existing unprivileged journal access; do not grant broad root or journal permissions automatically. Policy changes require a service restart.
