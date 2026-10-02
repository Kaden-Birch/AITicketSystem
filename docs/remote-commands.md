# General remote command access for Hermes

This milestone implements arbitrary shell commands through the outbound Linux agent. It is not an allowlist of restart actions. Commands execute as the agent service's OS account, with optional locally configured sudo or root service privileges. The host settings page offers read-only, approval for potentially dangerous commands, or full access. All command access defaults disabled; updating software alone does not grant execution permissions.

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
sudo install -m 0644 agent/monitoring.py /opt/aiticket-agent/monitoring.py
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

Open the host and select **Host settings**. Choose one mode and save:

- **Read only commands**: recognized diagnostics and Proxmox GET requests run automatically; changes are blocked.
- **Ask before potentially dangerous commands**: recognized diagnostics run automatically; changes and unrecognized shell commands require exact approval.
- **Full access**: arbitrary shell commands and all token-permitted Proxmox API operations execute without per-command approval.

Saving enables the chosen mode for ticket AI and independent authenticated Hermes/MCP sessions. No additional host permission checkboxes are needed. OS privileges and the agent's locally enabled shell capability still determine what can execute; the settings page reports missing capability or stale enrollment.

Read classification is deliberately conservative: known diagnostic executables and syntax are recognized. Scripts, substitutions, redirections and unknown commands require approval in the middle mode and are blocked in read-only mode. Full access does not use this classifier. Shell and Proxmox results remain in host history with UUID, state and output. Approval and unknown-outcome reconciliation remain available there when applicable.

Changing modes cancels old queued requests instead of approving them retrospectively. Submit a fresh request under the new mode. Preapproved commands can finish after a successful AI session; takeover, cancellation, expiry and permission changes still fence execution. Existing legacy policies are retained on upgrade and identified in settings; they are replaced when you save one of the three modes.

The settings page also holds host details, Proxmox association and optional manual power-button configuration. Monitoring and notification configuration links are collected there.

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

Ask it to list authorized targets, then execute a harmless command on the exact machine ID. `targets` lists only hosts explicitly enabled for independent operations. `run` returns a stable command UUID; `status` returns state/exit/output, with bounded polling inside the tool; `cancel` denies further execution and stops local running work on the next permission check. Neither normal Hermes model/provider configuration nor the Codex OAuth profile is copied or replaced by this MCP entry. These independent model sessions use their own configured model/account limits, not the ticket application's AI-run limits. Use read-only mode to restrict changes, or the legacy administration interface to revoke independent host access entirely; disabling ticket AI alone does not revoke independent MCP operations.

## Execution semantics and overhead

There is one compact tool schema. Results return up to 2048 characters per output stream; `offset` fetches further chunks without another command. The host UI retains the bounded result. `status` may poll the queue for up to 20 seconds inside one tool call, avoiding many model turns for routine waiting. Tool definitions, command text, returned output and reasoning consume model tokens; executing the shell itself does not. No measured live overhead estimate is claimed.

Commands are encrypted at rest and associated with an immutable target/command fingerprint. The broker commits dispatch once before delivery; it never re-delivers an ambiguous dispatch. The agent persists command identity before starting and never repeats a recorded identity. A restart while running produces an unknown result. Unknown outcomes lock further operations until an administrator independently checks the process/effects and records reconciliation. Previously queued jobs that never arrived can consequently require a new reviewed request after reconciliation.

Cancellation kills the local process group, denies further tool requests and fences later dispatch. It cannot undo changes already made, stop commands intentionally detached into another process/service/remote machine, or guarantee capture of output after a reboot. Background children in the original group are terminated at the job boundary. A reboot, network disruption or agent failure can have an unknown result even when the requested change succeeded; verification must use fresh post-operation evidence.

Encryption-key rotation re-encrypts command text while preserving immutable fingerprints. Inventory import does not restore execution permissions: affected policies are disabled, queued commands cancelled, and active/unknown commands must be completed or reconciled first. Ticket archives include command identity/status/result metadata without exporting encrypted credentials.

One outstanding command per agent is permitted. Existing power/service-recovery jobs and shell commands are mutually fenced at proposal admission. Approval-required policies remain available; immediate policy intentionally allows arbitrary changes without per-command confirmation. The permission is as broad as the chosen OS account. Live root, reboot, Proxmox and installed-Hermes operational tests remain deployment validation tasks; automated tests run only harmless local shell fixtures and mocked provider/tool calls.

### Hermes deferred-tool compatibility

The bridge temporary profile sets `tools.tool_search.enabled: "off"` so Hermes v0.20.0 exposes the single registered `aiticket_host` schema directly rather than `tool_search`, `tool_describe` and `tool_call`. Exact single-tool runtime validation remains enforced. This does not change your normal Hermes profile or OAuth credentials. After updating the bridge repository, restart the bridge, rerun compatibility and queue a new investigation; failed jobs are never replayed.

## Current tasks and general Proxmox API operations

Update both the main application (pull, rebuild, restart) and the Hermes bridge (pull, restart), then rerun compatibility and queue a new investigation. Schema 21 adds the Proxmox request ledger. No agent update is required for this addition. Existing host/guest links and enrollment credentials remain intact.

Operational jobs explicitly carry the current administrator question as `administrator_task`. Resuming a checkpoint makes its saved question the current task for the newly requested run; historical outputs remain evidence. Manual-ticket triage uses the administrator's original description. Ordinary automated monitoring requests authorize investigation only, not arbitrary changes.

The same compact `aiticket_host` tool now supports `proxmox` and `proxmox_status`. `targets` includes linked resource IDs, cluster namespaces, observed node/state and connection IDs. These remain available when the guest agent is offline. Inventory state is potentially stale: query current Proxmox state before changing a resource and follow migrations by resource identity.

A Proxmox request specifies `connection_id`, `method` (GET, POST, PUT or DELETE), a relative `path` under `/api2/json`, scalar `params`, and a stable UUID `id`. There is no API operation allowlist; the configured connection's actual API token determines access, including operations beyond VM power. The connection must belong to the host's linked namespace. Credentials stay on the application server and are never supplied to Hermes. An inventory-only token will still deny write requests; replace the connection token through Proxmox settings with the permissions you intend to grant.

Host operational permissions also govern Proxmox requests. Approval-required hosts queue exact requests—including reads—for review in **Proxmox API request history** on the host page. Immediate hosts dispatch requests directly. API access does not require a live guest agent or root access inside that guest. Independent MCP sessions can use this API when the host allows independent operations.

Example: ask Hermes to inspect the current state of the linked VM and, if stopped, start it and verify recovery. It can query `/cluster/resources` to confirm node/VM identity, request `/nodes/NODE/qemu/VMID/status/start`, then inspect the returned task UPID and fresh VM state. Substitute the live identity, never guess node or VMID. HTTP success is only API acceptance; task success, guest reachability and application health require separate checks. An approval-required proposal may outlive the AI run; approve in the host page and start a new investigation to verify it.

Proxmox requests persist dispatch before delivery and never automatically replay. Network ambiguity, server errors or oversized responses lock that host's API operations as unknown until independent reconciliation. Cancelling an awaiting request prevents delivery; cancelling or undoing an already accepted Proxmox task is a separate token-authorized API operation. Policy changes, unlinking or migrations invalidate queued request bindings; do not replay the old request. Key rotation re-encrypts payloads; inventory imports disable permission and refuse unresolved dispatched operations.

Local tests use mocked Proxmox responses. No live Proxmox mutation or model request has been performed by these checks.

### Resuming older checkpoints

The incident page now shows an editable **Current task for this resumed investigation** above the resume button. For an old checkpoint containing a generic read-only review task, replace that text with the action you currently authorize before resuming. New checkpoints preserve the actual operational task, including manual-ticket triage tasks. Resuming creates a new execution with that visible task; historical checkpoint outputs do not authorize replay of previously dispatched commands. Update/rebuild the main application for this field; the bridge does not need another update for this correction.

## Automatic investigations and verified incident resolution

Update/rebuild the main app and update/restart the Hermes bridge for this milestone. Schema 22 adds a per-investigation resolution request. Enable **Automatically queue one investigation per eligible active incident, including manual tickets** in **Hermes & usage**, save, and choose the minimum severity. AI must also be enabled and compatible, with run allowances available. This setting remains opt-in. New eligible monitoring and manual tickets receive one automatic run. A failed/cancelled prior run is not replayed. Administrator ownership blocks automatic admission. Configuration/admission blockers appear in the incident timeline; one blocked incident no longer prevents other eligible incidents from queuing.

Operational Hermes can call `resolve` with a brief repair summary once its requested task is complete. This records a request, schedules fresh host checks and returns `verification_pending`; it does not immediately close a ticket. After a successful AI run, the server requires fresh healthy observations from every enabled host check, recovery of all attached incident sources, and no unresolved command/Proxmox/power/service jobs. Missing checks, stale data, failures and unknown outcomes keep the ticket open. Manual tickets can then resolve automatically using independent host monitoring. Automatic monitoring incidents continue to resolve as soon as all attached sources independently recover.

Verified recovery sets the ticket to **Resolved**, records its closed timestamp, retains history and queues one recovery event. Discord messages include a brief recovery description. AI repair explanations are labeled unverified separately from observed healthy checks; root cause is not inferred from an AI claim. Administrator manual resolution also queues a notification labeled as administrator resolution. The existing global/machine/group Discord notification policy still applies: configure the webhook, enable notifications and recovery messages, select an appropriate severity threshold, and check maintenance/silence settings.

If application health matters, configure an HTTP/TCP/service monitor for it. A healthy VM and agent heartbeat alone cannot establish that the application is functioning.

## Agent reporting and live pages

**Settings → Agent reporting** now selects an interval from 20 to 300 seconds (default 30). The main app returns this interval on accepted and duplicate heartbeats. Updated agents sample metrics and poll queued jobs at that cadence; network failures still use bounded backoff. Saving also updates agent heartbeat/metric monitoring checks. Proxmox discovery retains its separate refresh schedule.

Update/rebuild the main application, then update the agent on each monitored host to apply the reporting setting:

```sh
# On the monitored host, such as cit-01 (not the main application VM):
cd ~/aiticket-agent-source
git pull --ff-only origin main
sudo install -m 0644 agent/agent.py /opt/aiticket-agent/agent.py
sudo systemctl restart aiticket-agent
```

Dashboard, host workspaces, incident pages, Proxmox inventory and history/queue/audit/Hermes views refresh displayed information every five seconds without navigation or a full browser reload. Metric values change when new agent samples or Proxmox refreshes arrive, not every UI poll. New AI results, timeline entries, command results and ticket status appear automatically. Unsaved/active forms and expanded disclosures are preserved. Hidden tabs pause polling; connection failures retry and expired sessions stop polling. Polling never queues AI or executes commands. The screen organization remains unchanged.

## Ticket workspace and blocker requests

The operational tool also supports `block` with a brief `summary` when human input is needed. The ticket shows a blocker banner, stops its work session, and can notify Discord with a configured public ticket URL. See [ticket workspace](ticket-workspace.md) for appearance, session tracking and upgrading both the application and bridge.

## Machine addresses and unavailable shell access

Operational ticket context and `targets` include the tagged machine even if shell execution is unavailable. They report the monitoring agent connection peer address, observation time/freshness, and a specific shell availability reason. A connection peer may reflect NAT or a proxy; it is not a complete list of guest interface addresses. Stale addresses are last-known evidence. Direct guest interface queries still require an enrolled, fresh agent advertising shell capability and the existing host/local permissions. Proxmox QEMU network-interface queries additionally require the guest agent inside the VM. HTTP rejections now retain bounded error details; Proxmox network exceptions retain their error type in request history without exposing credentials or replaying an uncertain request. Update both the main application and Hermes bridge for this improvement.

## Resumed investigation request history

A current authorized AI execution can use `status` and `proxmox_status` to read requests from earlier runs on the same ticket and machine. It cannot inspect other tickets or use this read access to cancel an earlier run’s commands. Approvals remain administrator actions in the host workspace. A missing shell UUID returns `not_recorded`; failed transport during a status lookup returns `lookup_failed` with a safe exception type, rather than claiming command delivery was unknown. Update both the main app and Hermes bridge, then resume the existing ticket.

## Process, SMB and ping monitoring

In **Hosts → Add check**, select the machine and one of:

- **Process / systemd service:** enter an exact Linux process name (the `/proc/PID/comm` name, usually limited to 15 characters), or a systemd unit such as `immich.service`. A service must report active; a process must have a matching name.
- **Mounted SMB share:** enter the directory used by the application, for example `/mnt/photos`. The agent checks that the covering mount is CIFS/SMB3 and that directory listing and filesystem information succeed. An unmounted directory fails, even if the directory still exists. This verifies access from the application host rather than only a server's TCP port. It does not prove writes, every file, or application health; cached reads may still succeed during a transient disconnect. Combine with application health checks where available.
- **Ping:** enter a reachable IP or hostname. The main server sends one ICMP echo per attempt, with a one-second reply timeout. Interval can be **1–86400 seconds**; actual timing can be longer when probes timeout or other checks occupy the worker. ICMP being blocked produces a failure even if the host is otherwise healthy.

Set consecutive failures and recovery successes. Host pages display green **Up**, yellow **Retrying** before the failure threshold, red **Down** after it, or gray **Awaiting result / Disabled**. Click a check to expand its timestamps, evidence and thresholds. These entries update with the existing five-second live page refresh.

Process and SMB checks need an enrolled agent. Their minimum configured interval is 20 seconds and execution follows the agent reporting cadence (set **Settings → Agent reporting interval** to 20 seconds for the fastest cadence). Checks do not require shell command access: they perform fixed read-only inspections. Restarting services is a separate AI command and uses the saved host access mode and the agent's OS permissions.

Failures create normal incidents. To invoke recovery automatically, enable AI and **Automatically queue one triage per eligible active incident**, and ensure the check severity meets the configured AI minimum. In **Full access**, the AI can investigate and restart the relevant service without another command approval. Read-only mode cannot restart; guarded mode requests approval for a restart. Recovery is confirmed by subsequent checks; an AI statement alone does not close the incident. SMB failures require diagnosing the mount/dependency; blindly restarting an application may not fix storage access.

### Upgrade monitored agents

Update and rebuild the main application first (`sudo git -C /opt/aiticket pull --ff-only origin main`, then `sudo docker compose up -d --build` in `/opt/aiticket`). The Docker image installs `iputils-ping`; non-Docker main installations need that package too.

On **each monitored host**, not the main application VM:

```sh
cd ~/aiticket-agent-source
git pull --ff-only origin main
sudo systemctl stop aiticket-agent
sudo install -m 0644 agent/agent.py agent/monitoring.py /opt/aiticket-agent/
sudo systemctl start aiticket-agent
sudo systemctl status aiticket-agent --no-pager
```

Agent version is `0.6.1`. Existing credentials and local permissions are retained. Hermes does not need an update for these checks.

### Heartbeats stopped after the process/SMB update

Agent 0.6.0 incorrectly let an optional check import or HTTP failure prevent the primary heartbeat. Agent 0.6.1 sends its heartbeat first and isolates optional check failures. Install both `agent.py` and `monitoring.py` using the monitored-host upgrade above. Optional check errors are logged separately, including HTTP status, while heartbeats continue. Each cycle evaluates at most two checks in oldest-due order, bounding the time spent on slow SMB mounts.

Verify on the monitored host:

```sh
sudo journalctl -u aiticket-agent --since "5 minutes ago" --no-pager -n 50
```

A `ModuleNotFoundError` in the optional-check log indicates `monitoring.py` was not copied beside `agent.py`. HTTP 404 indicates the main application must be updated/rebuilt to provide `/api/agent/checks`. These errors no longer suppress heartbeats. Healthy heartbeat checks recover existing incidents using their configured success threshold.
