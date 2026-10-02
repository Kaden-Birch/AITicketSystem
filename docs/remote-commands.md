# General remote command access for Hermes

This milestone implements arbitrary shell commands through the outbound Linux agent. It is not an allowlist of restart actions. Commands execute as the agent service's OS account, with optional locally configured sudo or root service privileges. The host policy chooses immediate execution or exact-command approval. All command access defaults disabled; updating software alone does not grant execution permissions.

The application supplies a durable command queue and audit trail. A compact `aiticket_host` tool is available to ticket investigations and to independent Hermes sessions through a stdio MCP server. Independent sessions need no ticket, active incident or enabled ticket AI. The application/agent channel remains necessary to reach DHCP hosts; Hermes does not need an inbound agent IP or SSH port.

## 1. Update the main application

Back up the matched database/encryption key. On the main VM:

```sh
cd /opt/aiticket
sudo docker compose stop app
git pull --ff-only origin main
sha256sum -c SHA256SUMS
sudo docker compose build
sudo docker compose up -d
```

Schema 20 adds immutable command identities, per-host policies and the AI tool-permission snapshot. Existing monitoring/enrollments/tickets remain intact.

## 2. Update each agent that should execute commands

On the monitored host, using its existing source checkout:

```sh
cd ~/aiticket-agent-source
git pull --ff-only origin main
sudo systemctl stop aiticket-agent
sudo install -m 0644 agent/agent.py /opt/aiticket-agent/agent.py
sudo install -m 0644 agent/diagnostics.py /opt/aiticket-agent/diagnostics.py
sudo install -m 0644 agent/actions.py /opt/aiticket-agent/actions.py
sudo install -m 0644 agent/commands.py /opt/aiticket-agent/commands.py
```

Enable the local general-command capability while retaining existing diagnostics/recovery policy:

```sh
sudo python3 - <<'PY'
import grp,json,os
from pathlib import Path
p=Path('/etc/aiticket-agent/policy.json')
p.parent.mkdir(parents=True,exist_ok=True)
policy=json.loads(p.read_text()) if p.exists() else {}
policy['commands']={'enabled':True,'timeout':120,'output_limit':8192,'sudo':False}
p.write_text(json.dumps(policy,indent=2)+'\n')
os.chown(p,0,grp.getgrnam('aiticket-agent').gr_gid)
p.chmod(0o640)
PY
sudo systemctl start aiticket-agent
sudo systemctl status aiticket-agent --no-pager
```

An enabled command policy and its containing directory must be root-owned and not group/world writable; neither may be a symlink. The agent advertises `shell_commands: true` on its next heartbeat. Local and application time/output limits both apply; the smaller value wins. Default local limit is 120 seconds and 8192 combined output bytes. Local/application ranges support commands lasting up to one hour and output buffers up to 65536 bytes. The main agent continues heartbeats while a command runs in a worker thread.

### OS account and privileges

Initially, commands run as `aiticket-agent`, under the existing systemd hardening. This supports ordinary readable diagnostics but does not grant privileged changes, home-directory access or writes to protected system locations. No password is requested interactively; stdin is closed. Working directory is `/`, with a minimal PATH/environment. A command can use `cd` and any shell syntax.

If you intend broad root operations, explicitly change the service's local execution identity with `sudo systemctl edit aiticket-agent`:

```ini
[Service]
User=root
Group=root
ProtectSystem=off
ProtectHome=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=false
RestrictSUIDSGID=false
PrivateTmp=false
KillMode=control-group
MemoryMax=512M
CPUQuota=100%
```

Then run `sudo systemctl daemon-reload` and `sudo systemctl restart aiticket-agent`. Keep local `sudo: false` when the service itself runs as root. This grants the agent and authorized remote commands root access; it can modify its own service and the host. Alternatively keep the service unprivileged, configure the necessary OS sudo permissions yourself, and set local `sudo: true`; the runner then invokes `sudo -n -- /bin/sh -c <command>`. Existing `NoNewPrivileges=true` prevents sudo elevation; a sudo deployment needs an explicit `NoNewPrivileges=false` override plus appropriate writable paths/hardening. Neither path is enabled automatically.

For Proxmox `qm`/`pct` administration, install and enable a suitably privileged agent on the Proxmox node and authorize that node as a command target. Guest-agent commands run inside the guest, not on its hypervisor. Proxmox API power controls remain separately available for linked VMs.

## 3. Configure a host in the GUI

Open its host workspace → **Remote commands → Configure remote command access**:

- Enable remote commands.
- Enable **Allow ticket Hermes investigations** if the ticket agent may execute commands.
- Enable **Allow independent Hermes/MCP sessions** if ordinary Hermes sessions may access this host.
- Choose **Require approval of each exact command** or **Execute immediately under this host permission**.
- Set elapsed-time and output limits, then confirm and save.

The first submitted command should be harmless, such as `id; uptime; df -h`. The host workspace shows exact command text, UUID, fingerprint, state, exit code, stdout/stderr, truncation and approvals. Choose **Approve exact command** if required. Optional ticket tagging connects command queue/results to its immutable timeline. Independent operations are recorded in host history and audit without fabricating a ticket.

Configuration changes fence outstanding jobs. Approval-required AI proposals can remain for the administrator to review after an AI run finishes; approval independently rechecks current host policy and ticket state. Immediate AI work is tied to the investigation permission and stops when that execution ends, is cancelled, loses ownership or expires.

## 4. Enable commands in ticket Hermes investigations

On the Hermes VM:

```sh
sudo systemctl stop aiticket-hermes-bridge
sudo git -C /opt/aiticket-hermes pull --ff-only origin main
sudo nano /etc/systemd/system/aiticket-hermes-bridge.service
```

Append `--command-tools` to the existing `ExecStart` line. Keep `--execution-mode codex`, the dedicated OAuth profile, interpreter and gateway arguments. Then:

```sh
sudo systemctl daemon-reload
sudo systemctl start aiticket-hermes-bridge
sudo systemctl status aiticket-hermes-bridge --no-pager
```

On **Hermes & usage**, select Codex mode, `gpt-6.1-sol`, reasoning `low`, and enable **operational host command tools**. Save, rerun the signed compatibility check, and enable AI. The runtime must expose exactly the `aiticket_host` tool and no other tool. The installed Hermes registry/constructor must pass compatibility checks; live installed-version/tool execution validation remains required.

Open a manual ticket tied to the host, describe your intended operation, then choose **Queue AI investigation**. This mode supports up to 12 model iterations per run, rather than the previous single tool-free turn. The Codex queued-run allowance and existing 15–180-second investigation timeout still apply; they are not token/cost caps. Start with `Run id and uptime on this machine and report the results` before a real change. The tool binds ticket requests to that exact machine; it cannot select another host via a forged machine ID. Use an independent session for long operations that should outlive a ticket AI run.

## 5. Connect ordinary Hermes outside the ticket system

The repository includes a stdio MCP server. Hermes supports `mcp_servers` in its normal config, as described in [the Hermes MCP documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp/). Add this entry to the existing `/home/assistant/.hermes/config.yaml`; merge it with any existing `mcp_servers` block rather than replacing the profile:

```yaml
mcp_servers:
  aiticket-hosts:
    command: /opt/aiticket-hermes-venv/bin/python
    args:
      - -m
      - aiticket.command_tools
      - --server
      - http://10.128.2.203:8080
      - --secret-file
      - /home/assistant/.hermes/aiticket-operations.secret
      - --allow-http
    env:
      PYTHONPATH: /opt/aiticket-hermes
```

The MCP process needs the application/bridge shared secret in a private file readable by the normal Hermes OS user. For the user's existing installation:

```sh
sudo install -o assistant -g assistant -m 0600 \
  /etc/aiticket-hermes-bridge/secret \
  /home/assistant/.hermes/aiticket-operations.secret
```

Do not paste the secret into a model prompt or chat. Update this private copy when rotating the shared secret. Restart normal Hermes (or reload MCP if supported by the installed version). It should discover `aiticket_host`.

Ask it to list authorized targets, then execute a harmless command on the exact machine ID. `targets` lists only hosts explicitly enabled for independent operations. `run` returns a stable command UUID; `status` returns state/exit/output, with bounded polling inside the tool; `cancel` denies further execution and stops local running work on the next permission check. Neither normal Hermes model/provider configuration nor the Codex OAuth profile is copied or replaced by this MCP entry. These independent model sessions use their own configured model/account limits, not the ticket application's AI-run limits. Disable external access in the host policy to revoke it; disabling ticket AI alone does not revoke independent MCP operations.

## Execution semantics and overhead

There is one compact tool schema. Results return up to 2048 characters per output stream; `offset` fetches further chunks without another command. The host UI retains the bounded result. `status` may poll the queue for up to 20 seconds inside one tool call, avoiding many model turns for routine waiting. Tool definitions, command text, returned output and reasoning consume model tokens; executing the shell itself does not. No measured live overhead estimate is claimed.

Commands are encrypted at rest and associated with an immutable target/command fingerprint. The broker commits dispatch once before delivery; it never re-delivers an ambiguous dispatch. The agent persists command identity before starting and never repeats a recorded identity. A restart while running produces an unknown result. Unknown outcomes lock further operations until an administrator independently checks the process/effects and records reconciliation. Previously queued jobs that never arrived can consequently require a new reviewed request after reconciliation.

Cancellation kills the local process group, denies further tool requests and fences later dispatch. It cannot undo changes already made, stop commands intentionally detached into another process/service/remote machine, or guarantee capture of output after a reboot. Background children in the original group are terminated at the job boundary. A reboot, network disruption or agent failure can have an unknown result even when the requested change succeeded; verification must use fresh post-operation evidence.

Encryption-key rotation re-encrypts command text while preserving immutable fingerprints. Inventory import does not restore execution permissions: affected policies are disabled, queued commands cancelled, and active/unknown commands must be completed or reconciled first. Ticket archives include command identity/status/result metadata without exporting encrypted credentials.

One outstanding command per agent is permitted. Existing power/service-recovery jobs and shell commands are mutually fenced at proposal admission. Approval-required policies remain available; immediate policy intentionally allows arbitrary changes without per-command confirmation. The permission is as broad as the chosen OS account. Live root, reboot, Proxmox and installed-Hermes operational tests remain deployment validation tasks; automated tests run only harmless local shell fixtures and mocked provider/tool calls.
