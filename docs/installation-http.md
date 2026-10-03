# Install using HTTP: application VM and monitored hosts

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

Create a host under **Hosts → Add host**, then open **Host settings** and generate its enrollment token. On the monitored host, run:

```bash
curl -fsSL https://raw.githubusercontent.com/Kaden-Birch/AITicketSystem/main/agent/install.sh -o /tmp/aiticket-agent-install.sh && sudo bash /tmp/aiticket-agent-install.sh --server http://10.128.2.203:8080
```

Replace the server IP if needed. Enter the token at the hidden prompt. The installer installs all files, enables local root command execution, enrolls and restarts automatically. Existing installations retain enrollment and require no new token. Configure Read only, Ask permission or Full access in the main application's Host settings; no separate local shell policy edit is needed. Allow one reporting interval for the host to update.

See [the agent guide](agent.md) for verification, upgrades and credential rotation. No manual `useradd`, file-copy or service-start steps are required.

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

Run the agent installer above to update all agent files first. No reenrollment is needed just to change transport.

## 4. Optional existing reverse proxy and Hermes

Your reverse proxy may forward HTTPS requests to `http://192.0.2.10:8080`. Direct HTTP remains usable in this mode. HTTPS endpoints still verify certificates even when HTTP is permitted; the option never disables certificate verification for HTTPS URLs.

For HTTP communication with the Hermes companion, set `AITICKET_ALLOW_INSECURE_HTTP=1` in both the main app and companion service environment, restart them, and configure the companion's `--gateway` as `http://192.0.2.10:8080`. Set its HTTP address in **Hermes & usage**, leave CA paths empty for HTTP endpoints, rerun compatibility validation and follow the existing provider/budget activation workflow. The updated companion passes the transport opt-in into its isolated adapter. Signing and budget admission remain enforced. External providers/Discord can continue using their normal HTTPS URLs.

To return to HTTPS-only application mode, set `AITICKET_ALLOW_INSECURE_HTTP=0`, choose the desired bind address, recreate the application container and switch agents back to verified HTTPS endpoints with `allow_http:false`. Initial installation does not enable AI or recovery in either mode.

For metric host workspaces, Proxmox guest status, optional manual power controls and the matching agent upgrade, see [the host dashboard guide](host-dashboard.md).

## Hermes with a Codex account

To use your Codex subscription without an API key, follow [Hermes Codex setup](hermes-codex.md). The bridge-to-application connection can use HTTP with the same explicit transport opt-in. Codex itself connects to its HTTPS provider endpoint.

General command execution is an explicit opt-in. Follow [remote command setup](remote-commands.md) for agent OS permissions, host policy and operational/independent Hermes tools.

The agent installer verifies effective root service permissions, runtime capabilities and local shell policy after restart. A failed check exits with an explanation; inspect conflicting drop-ins as described in [agent permission verification](agent.md#permission-verification). Main application access modes remain under Host settings.
