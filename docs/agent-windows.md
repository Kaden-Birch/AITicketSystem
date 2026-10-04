# Windows agent

## Install or upgrade

Supported: **64-bit Windows 10/11 and Windows Server 2019 or later**, with Windows PowerShell 5.1, Task Scheduler and outbound access to the application, GitHub, python.org and PyPI. Windows on ARM and domain-controller account management are not supported by this installer.

Create an enrollment token in **Hosts → your host → Host settings**. Open **64-bit PowerShell as Administrator**, then paste:

```powershell
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/Kaden-Birch/AITicketSystem/main/agent/windows/install.ps1' -OutFile "$env:TEMP\aiticket-agent-install.ps1"; & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\aiticket-agent-install.ps1" -Server 'http://10.128.2.203:8080'
```

Replace the server URL with your application endpoint. Enter the token at the hidden prompt. HTTPS with a private CA can add `-CA 'C:\Certificates\application-ca.pem'`; the certificate must exist and remain readable by SYSTEM. Publicly trusted HTTPS needs no CA argument. Execution-policy bypass applies only to this installer process; it does not change machine policy.

The installer downloads a dedicated embeddable Python runtime and verifies its pinned official checksum when a dedicated runtime is missing (without changing existing Python installations, registrations or PATH), verifies agent file checksums, protects installation/state directories, enrolls the machine, enables local commands, registers two SYSTEM tasks, and starts the agent automatically. Rerunning the same command upgrades while preserving credentials, policy and execution ledgers; no new enrollment token is required. An existing trusted Python 3.11+ x64 can be supplied with `-PythonExe 'C:\Path\python.exe'`. Installation checks validate SYSTEM task identity, task startup, exclusive administrative directory permissions, and command configuration, then wait up to 60 seconds for a fresh authenticated heartbeat from the background agent. A running task alone is not reported as a connected installation; if the heartbeat is unavailable, enrollment is preserved and the installer points to the agent log.

The agent runs as **LocalSystem**, with administrative machine access. **Host settings → Access mode** remains authoritative: read-only commands, approval before potentially dangerous commands, or Full access. Full access sends arbitrary PowerShell without a second local approval. The agent opens no incoming port. Commands run in Windows PowerShell 5.1 without profiles, with timeout/output limits, cancellation and process-tree termination. Requests survive restarts in the same durable ledger; uncertain operations are reported and never replayed automatically. AI troubleshooting context identifies Windows and its PowerShell interpreter.

## Monitoring and diagnostics

- CPU utilization/cores, physical memory, system-drive capacity/free space and uptime feed the existing host history graphs and health preferences.
- Hostname, Windows version/architecture, adapter MAC addresses/IPs/link state and virtualization information feed host inventory and AI topology context. Switch-port matching retains the existing confidence rules; Windows does not invent LLDP neighbors.
- **Process checks:** exact process name, such as `notepad` or `notepad.exe`; names are case-insensitive. **Service checks:** `service:Spooler`, using the service's internal name, not its display name. Services can be inspected with `Get-Service`.
- **Docker checks:** container name or ID, plus the same running/health/restart/OOM evidence as Linux. Requires a Docker CLI and daemon accessible to SYSTEM. A Docker Desktop daemon tied to your signed-in user session may be unavailable; that is reported as unknown rather than falsely down. The installer does not install Docker.
- **SMB checks:** UNC paths such as `\\nas\photos`. Mapped drive letters belong to user sessions and are not supported. The check verifies directory access as SYSTEM, which may authenticate as the machine account on a domain and lacks your personal NAS login. Configure appropriate share access separately. Missing paths are failed checks; denied/unavailable inspection is unknown. No SMB passwords are collected or stored by the monitoring check.
- HTTP, TCP, ping and linked Proxmox checks still execute from the main application, including one-second ping intervals. Agent-side checks follow the configured reporting interval, starting at 20 seconds.
- Process summaries, locally allowed service status and bounded Service Control Manager Event Log diagnostics use the existing diagnostic broker. Service start recovery and host restart/shutdown use its existing explicit recovery policy/credential flow. Full-access PowerShell can use native `Restart-Service`, `Restart-Computer` and other commands directly under central host policy.

Linux-only load averages, inode counts and memory PSI are unavailable on Windows and are not reported as zero. Their health preferences are disabled for Windows hosts, so Linux fleet defaults cannot create misleading alerts or block recovery. Storage metrics currently cover the Windows system drive, matching Linux's single root filesystem scope.

Optional service diagnostic policy resides in `C:\ProgramData\AITicketAgent\config\policy.json`. Preserve the installer-created `commands` entry. Service aliases map to Windows service names; for example, `"services": {"print": "Spooler"}`. SYSTEM installations advertise manual restart/shutdown automatically using the existing enrollment identity; no extra power setup is needed. Explicit local power restrictions are still honored. Optional `logs` and `recovery` sections follow the [broker guide](action-broker.md), with Windows service names instead of `.service` units. Restart the agent task after changing these settings. Recovery starts only the exact allowed **Stopped** service after fresh independent status evidence; it does not treat a stopped service as proof of an application outage.

## Automatic updates and maintenance

`AITicketAgent` is the monitoring task; `AITicketAgentUpdater` is a separate SYSTEM task running every five minutes. The independent updater imports no monitoring code and retrieves its signed Windows release directly from GitHub, even if the agent cannot contact the application. It verifies the pinned Ed25519 key, archive digest, permitted files, syntax/imports and a fresh authenticated heartbeat before accepting an update. It defers while work is active, staggers rollout and restores the previous bundle after failed/interrupted probation. The same failed release is not retried; a newer corrective release remains eligible. The main application must be reachable for the probation heartbeat.

**Host settings → Agent updates** shows installed/available versions, last contact and progress. **Update now** requests the next independent cycle without rollout delay; signature checks, work deferral and rollback still apply. Automatic updates default on. Set `automatic` to `false` in `C:\ProgramData\AITicketAgent\config\updater.json` to pause automatic installation while retaining availability checks and manual requests.

```powershell
Get-ScheduledTask -TaskName AITicketAgent,AITicketAgentUpdater
Get-Content 'C:\ProgramData\AITicketAgent\state\agent.log' -Tail 50
Stop-ScheduledTask -TaskName AITicketAgent
Start-ScheduledTask -TaskName AITicketAgent
Start-ScheduledTask -TaskName AITicketAgentUpdater
Get-Content 'C:\ProgramData\AITicketAgent\state\update-status.json'
```

Rerun the installer to upgrade the stable launcher/updater or trust anchor. They intentionally remain outside automatically swapped agent bundles. The five-megabyte agent log retains one previous file; release folders remain available for rollback. A stopped host, blocked GitHub access or broken Python/Task Scheduler still requires infrastructure recovery.

For credential rotation, revoke the enrollment in the application, stop both tasks, deliberately remove `state\identity.json`, and rerun the installer with a new token. Never remove enrollment during a normal upgrade. For uninstall, revoke in the application, stop/unregister both tasks, then remove `C:\ProgramData\AITicketAgent`; this deletes local credentials and execution history. Central ticket history remains.

For Windows fleet account, SSH key and package tasks, see [Fleet](fleet.md#windows-hosts). Windows OpenSSH's shared administrator key file is excluded from per-user key jobs; standard-account keys are supported.

## Container and process discovery

Agent 0.11.0+ reports process working sets and CPU deltas, plus Docker inventory when the CLI/daemon are accessible to LocalSystem. Expand **Containers & processes** on the host and select **Monitor** to add an exact-name check. Docker Desktop scoped to a signed-in user might not be available to LocalSystem. See [storage and service monitoring](storage-services.md).
