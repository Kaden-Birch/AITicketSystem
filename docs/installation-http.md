# Install using HTTP: application VM and monitored hosts

This is the explicit HTTP option for your setup. No certificate, local Nginx or reverse proxy is required. Your existing reverse proxy can still provide optional HTTPS browser access to the same HTTP backend.

HTTP sends administrator passwords, agent tokens, diagnostics and integration credentials without transport encryption. On a WAN, they can be intercepted or altered. Login, CSRF checks, agent credentials, action approval, signatures and encrypted storage remain enabled, but do not provide transport confidentiality. This mode is opt-in; HTTPS remains the default.

Replace `192.0.2.10` below with the main VM's static IP. Agent host IPs are never configured.

## 1. Main Ubuntu 24.04 VM

Install Git and Docker Engine with the Compose plugin. Use [Docker's official Ubuntu apt-repository installation](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository) if Docker is not already installed.

```sh
sudo apt update
sudo apt install -y git
sudo systemctl enable --now docker
sudo docker compose version
sudo install -d -o "$USER" -g "$(id -gn)" /opt/aiticket
cd /opt/aiticket
git clone https://github.com/Kaden-Birch/AITicketSystem.git .
sha256sum -c SHA256SUMS
cp .env.http.example .env
```

For an existing installation, pull the updated source rather than cloning again. If `.env` already exists, edit it instead of overwriting it. Set:

```dotenv
AITICKET_ALLOW_INSECURE_HTTP=1
AITICKET_BIND_ADDRESS=0.0.0.0
```

The first setting permits HTTP login and HTTP URLs for internal integrations. The second exposes container port 8080 on all VM interfaces. Your router/VLAN firewall controls reachability; there is no application CIDR allowlist.

For a new installation:

```sh
sudo docker compose build
sudo docker compose run --rm app python -m aiticket init
sudo docker compose up -d
```

Initialization prompts for the administrator password twice; use at least 12 characters. Existing installations should skip `init`, build the updated image and run `sudo docker compose up -d` to recreate the container with the changed environment/port binding. Preserve existing data/key volumes and review the [upgrade procedure](installation.md#d-restart-and-upgrade) before updating an existing database.

Open **http://192.0.2.10:8080** and log in. Check:

```sh
curl --fail http://192.0.2.10:8080/health
sudo docker compose ps
sudo docker compose logs --tail=100 app
```

Add the machine under **Hosts & checks**. Leave AI and recovery disabled for initial monitoring. The application starts its monitoring workers automatically. Never use `docker compose down -v` for a normal restart/upgrade.

## 2. Monitored Ubuntu/Debian Linux host

The agent monitors the Linux OS where it is installed. Install inside a guest to monitor that guest.

```sh
sudo apt update
sudo apt install -y python3 git
python3 --version
git clone https://github.com/Kaden-Birch/AITicketSystem.git aiticket-agent-source
cd aiticket-agent-source
sha256sum -c SHA256SUMS
```

Python 3.11+ is required; no pip dependencies are needed. Use matching application/agent releases, or securely copy their reviewed files. Create the account once; skip `useradd` if it already exists:

```sh
sudo useradd --system --home /var/lib/aiticket-agent --shell /usr/sbin/nologin aiticket-agent
sudo install -d -m 0755 /opt/aiticket-agent
sudo install -m 0644 agent/agent.py /opt/aiticket-agent/agent.py
sudo install -m 0644 agent/diagnostics.py /opt/aiticket-agent/diagnostics.py
sudo install -m 0644 agent/actions.py /opt/aiticket-agent/actions.py
sudo install -d -o aiticket-agent -g aiticket-agent -m 0700 /var/lib/aiticket-agent
sudo install -m 0644 agent/aiticket-agent.service /etc/systemd/system/aiticket-agent.service
```

In **Hosts & checks**, generate an enrollment token for the exact machine. Within ten minutes, run on the monitored host:

```sh
sudo -u aiticket-agent python3 /opt/aiticket-agent/agent.py enroll --server http://192.0.2.10:8080 --allow-http
```

Paste the token at the hidden prompt. No CA file is needed. `--allow-http` is saved with the endpoint in the mode-0600 identity file, so the installed systemd service can use HTTP on subsequent starts without extra flags.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now aiticket-agent
sudo systemctl status aiticket-agent --no-pager
sudo journalctl -u aiticket-agent -n 50 --no-pager
```

Allow about 30–60 seconds for the agent to report. Monitoring thresholds may need additional samples. Add resource threshold checks through **Resources**. DHCP changes need no configuration update; keep the identity file across restarts and upgrades.

Optional read-only service policy and credential rotation are described in [the agent guide](agent.md). Recovery remains a separate disabled-by-default capability with explicit approval.

## 3. Existing HTTPS agent installations

To retain current enrollment and execution ledgers while changing to HTTP, stop the agent and edit the existing identity file locally:

```sh
sudo systemctl stop aiticket-agent
sudo nano /var/lib/aiticket-agent/identity.json
```

Change only `server` to `http://192.0.2.10:8080`, set `allow_http` to JSON `true`, and set `ca` to JSON `null`. Preserve all other fields, including credentials and diagnostic/action ledgers. Keep ownership `aiticket-agent:aiticket-agent` and mode 0600, then restart:

```sh
sudo chown aiticket-agent:aiticket-agent /var/lib/aiticket-agent/identity.json
sudo chmod 0600 /var/lib/aiticket-agent/identity.json
sudo systemctl start aiticket-agent
```

Update all three agent Python files to this release first. No reenrollment is needed just to change transport.

## 4. Optional existing reverse proxy and Hermes

Your reverse proxy may forward HTTPS requests to `http://192.0.2.10:8080`. Direct HTTP remains usable in this mode. HTTPS endpoints still verify certificates even when HTTP is permitted; the option never disables certificate verification for HTTPS URLs.

For HTTP communication with the Hermes companion, set `AITICKET_ALLOW_INSECURE_HTTP=1` in both the main app and companion service environment, restart them, and configure the companion's `--gateway` as `http://192.0.2.10:8080`. Set its HTTP address in **Hermes & usage**, leave CA paths empty for HTTP endpoints, rerun compatibility validation and follow the existing provider/budget activation workflow. The updated companion passes the transport opt-in into its isolated adapter. Signing and budget admission remain enforced. External providers/Discord can continue using their normal HTTPS URLs.

To return to HTTPS-only application mode, set `AITICKET_ALLOW_INSECURE_HTTP=0`, choose the desired bind address, recreate the application container and switch agents back to verified HTTPS endpoints with `allow_http:false`. Initial installation does not enable AI or recovery in either mode.

For metric host workspaces, Proxmox guest status, optional manual power controls and the matching agent upgrade, see [the host dashboard guide](host-dashboard.md).

## Hermes with a Codex account

To use your Codex subscription without an API key, follow [Hermes Codex setup](hermes-codex.md). The bridge-to-application connection can use HTTP with the same explicit transport opt-in. Codex itself connects to its HTTPS provider endpoint.
