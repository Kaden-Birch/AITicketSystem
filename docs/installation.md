# Install the application VM and a monitored Linux host

For direct HTTP without local TLS/Nginx, use the [HTTP installation guide](installation-http.md). This page covers the default HTTPS deployment; TLS can also terminate on your existing reverse proxy.

This guide installs the main application on Ubuntu Server 24.04 using the supplied Docker Compose configuration, and the outbound Python agent on an Ubuntu/Debian Linux host. Run each section on the machine named in its heading. The agent monitors the OS in which it runs: install inside a guest to monitor that guest. Installing on a Proxmox node monitors that node's Linux OS, not all its guests.

The commands have been checked against the repository. Live Ubuntu deployment remains unvalidated. Leave AI and recovery disabled during initial installation. Hermes is optional for monitoring and has a separate [installation contract](hermes-contract.md).

## Before starting

Prepare:

- The main VM's static IP. Examples below use `192.0.2.10`; replace it everywhere.
- An optional browser DNS name. Examples use `tickets.example.internal`.
- A server TLS certificate and matching private key. The certificate must include the application IP as an **IP Subject Alternative Name**, and the browser DNS name as a DNS SAN if used. A DNS-only certificate will not work for IP-based agent connections.
- The issuing CA certificate/chain, trusted by browsers and monitored hosts. For an internal CA, distribute its public CA certificate through a trusted channel. Do not distribute the server's private key to agents.
- Sudo access and outbound access for downloading packages/source. LAN/VPN reachability from monitored hosts to the main VM on TCP 443.

The application adds no CIDR allowlist. Keep your existing router/VLAN firewall policy. Agents need no fixed IP or inbound port. Do not expose the development HTTP server for agent enrollment.

## A. Main Ubuntu VM

### 1. Install prerequisites

```sh
sudo apt update
sudo apt install -y git nginx ca-certificates curl
```

Install Docker Engine and the Compose plugin using [Docker's official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository), following the apt-repository method. If Docker is already installed, verify the existing installation rather than replacing its packages blindly.

```sh
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

The remaining commands use `sudo docker`, so Docker group membership is unnecessary.

### 2. Get the application

```sh
sudo install -d -o "$USER" -g "$(id -gn)" /opt/aiticket
cd /opt/aiticket
git clone https://github.com/Kaden-Birch/AITicketSystem.git .
git rev-parse HEAD
sha256sum -c SHA256SUMS
```

For a private repository, authenticate Git using your normal GitHub credentials/SSH setup. Do not embed an access token in the clone URL. Record the commit ID you deploy. If using the supplied ZIP instead, extract its contents into `/opt/aiticket` and run the checksum command from there.

### 3. Build and initialize

```sh
cd /opt/aiticket
sudo docker compose build
sudo docker compose run --rm app python -m aiticket init
```

Enter and confirm a new administrator password at the hidden prompt; use at least 12 characters. Initialization creates the database, encryption key and session secret. There is one administrator account; login asks only for the password. Run initialization once. It refuses to overwrite an existing administrator.

```sh
sudo docker compose up -d
sudo docker compose ps
curl --fail http://127.0.0.1:8080/health
```

The health response should contain `"status":"ok"`. Compose binds port 8080 to VM loopback only. The `serve` command already starts monitoring and AI queue workers; do not start an additional worker container.

Compose stores the database and key in separate named volumes. Preserve both. Never use `docker compose down -v` for a routine restart or upgrade: it deletes those volumes.

### 4. Configure HTTPS on the VM

Securely copy your existing certificate chain, private key and public CA certificate to the VM. In the commands below, replace `/path/to/...` with their actual source paths:

```sh
sudo install -d -m 0755 /etc/nginx/aiticket
sudo install -m 0644 /path/to/server-fullchain.pem /etc/nginx/aiticket/server-fullchain.pem
sudo install -m 0600 /path/to/server-key.pem /etc/nginx/aiticket/server-key.pem
sudo install -m 0644 /path/to/issuing-ca.pem /etc/nginx/aiticket/issuing-ca.pem
sudo nano /etc/nginx/sites-available/aiticket
```

Paste this configuration, replacing the example IP and DNS name. If you have no DNS name, list only the IP in `server_name`.

```nginx
server {
    listen 443 ssl;
    server_name 192.0.2.10 tickets.example.internal;

    ssl_certificate /etc/nginx/aiticket/server-fullchain.pem;
    ssl_certificate_key /etc/nginx/aiticket/server-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
```

Enable the site once:

```sh
sudo ln -s /etc/nginx/sites-available/aiticket /etc/nginx/sites-enabled/aiticket
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
curl --fail --cacert /etc/nginx/aiticket/issuing-ca.pem https://192.0.2.10/health
```

If the symlink already exists, skip the `ln` command. Resolve any conflicting existing HTTPS site configuration before reloading Nginx. The public CA file must contain the CA material needed to verify your chain; use your system trust instead of `--cacert` if already configured. Never bypass certificate verification.

Open `https://tickets.example.internal` or `https://192.0.2.10` in a browser that trusts the issuing CA. Login with the password from initialization. Production cookies require HTTPS; do not enable `AITICKET_LOCAL_HTTP` for this deployment.

The application currently records the reverse proxy's observed connection address rather than trusting forwarded headers as agent identity. Agent UUIDs and credentials establish identity.

### 5. Configure the first monitored machine

1. Open **Hosts → Add host** and add a machine with a recognizable name.
2. Open the host and use **Add check** for HTTP/TCP checks if needed.
3. Open **Host settings** and generate its short-lived enrollment token, then install the agent in section B.
4. Leave **Hermes & usage** and **Recovery policy** disabled. AI is unnecessary for telemetry, incidents, diagnostics and notifications.
5. For Proxmox API monitoring, use **Proxmox** to add a read-only connection, test it, discover resources and explicitly link the correct resource to the correct machine. Discovery alone does not enable monitoring. If using a private Proxmox CA, mount its public CA file into the app container through a Compose override and use the container path in the GUI; host paths are not automatically visible inside the container. Example mount: `/etc/aiticket/proxmox-ca.pem:/certs/proxmox-ca.pem:ro`.

## B. Agent on the monitored Linux host

Create an enrollment token under **Hosts → your host → Host settings**, then run the one-command installer on the monitored Ubuntu/Debian host:

```bash
curl -fsSL https://raw.githubusercontent.com/Kaden-Birch/AITicketSystem/main/agent/install.sh -o /tmp/aiticket-agent-install.sh && sudo bash /tmp/aiticket-agent-install.sh --server https://YOUR_APPLICATION_IP --ca /absolute/path/to/trusted-ca.pem
```

Use your actual endpoint and CA file already copied onto this host. Omit `--ca` when the certificate is trusted by the system. For HTTP, use an `http://` endpoint; the installer saves HTTP opt-in automatically.

Enter the token at the hidden prompt. Installation, local root command access, enrollment, service enablement and restart are automatic. Upgrades preserve enrollment without a new token. The main application's Host settings control read-only, approval-required or Full access permissions.

See [the agent guide](agent.md) for verification and credential rotation. No manual account creation or agent-file copying is required.

## C. Verify and troubleshoot

- **Main app:** `cd /opt/aiticket` then `sudo docker compose logs --tail=100 app`. Local `/health` checks the web process, not every monitoring integration.
- **Nginx:** `sudo nginx -t` and `sudo journalctl -u nginx -n 50 --no-pager`.
- **Agent:** `sudo journalctl -u aiticket-agent -n 50 --no-pager`.
- **Certificate verification failure:** check the IP SAN, CA chain, clock and readability of the stored CA path. Enrollment success requires valid TLS; do not disable verification.
- **Timeout/refused connection:** check VM static IP, Nginx listener and your LAN/VPN firewall path to TCP 443. No inbound agent port is needed.
- **Enrollment refused:** regenerate an expired token; ensure it belongs to the correct machine. If a lost enrollment response left an orphan credential, revoke it in the GUI before reenrolling.
- **Agent absent after start:** confirm the identity file is owned by `aiticket-agent`, the CA path exists and the service is running. Retry delay grows to five minutes during outages.
- **Service diagnostics unavailable:** confirm the local policy is valid and wait for the next capability heartbeat.

Once installed, check that heartbeat and resource telemetry belong to the intended machine. Add CPU/memory/disk/inode alert rules through **Resources**; receiving telemetry alone does not create all resource threshold rules. Test incident and recovery behavior on a disposable check before enabling AI or recovery. Automated development tests do not establish live deployment readiness.

## D. Restart and upgrade

Routine main-app restart:

```sh
cd /opt/aiticket
sudo docker compose restart app
```

Before upgrading, stop the application and preserve a matched database/encryption-key backup using your existing backup procedure; see [recovery instructions](recovery.md). Record the old Git commit. Then:

```sh
cd /opt/aiticket
sudo docker compose stop app
git pull --ff-only origin main
sha256sum -c SHA256SUMS
sudo docker compose build
sudo docker compose up -d
```

Startup applies transactional database migrations. If an upgrade fails, older code may reject a newer database: rollback requires the corresponding pre-upgrade database and key, not just a Git checkout. Keep the same Compose directory/project name so existing named volumes remain attached. Do not initialize again or delete volumes.

For an agent upgrade, rerun the installer in section B. It replaces all modules and restarts the service while preserving identity and execution ledgers; no reenrollment is needed.

For metric host workspaces, Proxmox guest status, optional manual power controls and the matching agent upgrade, see [the host dashboard guide](host-dashboard.md).

The agent installer verifies effective root service permissions, runtime capabilities and local shell policy after restart. A failed check exits with an explanation; inspect conflicting drop-ins as described in [agent permission verification](agent.md#permission-verification). Main application access modes remain under Host settings.

Configure optional resource alerts under **Agent health**. New defaults are disabled; hosts inherit enabled defaults unless overridden under **Host settings → Agent health**. See [health preferences](resource-diagnostics.md). Existing host rules are preserved during upgrade.
