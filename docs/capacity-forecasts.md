# Capacity forecasts

The **Filesystem capacity forecasts** section on each host page shows actual disk usage reported by its agent, with a separate card for each reported local filesystem. Existing agents provide the Linux root filesystem or Windows system drive. Agent 0.13.0 adds supported local persistent Linux mounts and fixed local Windows drives, with up to 64 distinct filesystems; duplicate bind mounts, removable Windows drives and additional network shares are excluded. An agent is required for VM filesystem forecasts: Proxmox disk allocation is not filesystem free space.

Each TrueNAS and UniFi NAS storage pool shows a capacity trend below its usage bar. The Collected evidence storage section on Telemetry history and Settings → Network logs also shows forecasts for local records and SMB archives. Expand **View usage trend** for the daily graph and exact readings. Storage figures use decimal MB and GB.

Forecasts are read-only planning information. They do not create tickets, change monitoring thresholds or authorize AI remediation.

## When a forecast appears

The collector keeps the latest valid capacity reading per hour for 90 days. Forecasts use up to the last 30 days, summarized into daily median readings. At least seven distinct days spanning six days are required, with no gaps longer than two days and a fresh current reading. Pool freshness follows the connection's reporting interval; archive measurements must be no older than 15 minutes.

A robust median of pairwise growth rates estimates daily growth. An increasing trend must explain at least 70% of the variation and its lower growth bound must also be positive. The displayed time range uses the 10th and 90th percentiles of observed growth rates. This describes variation in historical growth, rather than a statistical confidence interval or guaranteed capacity date.

Stable, decreasing, inconsistent, incomplete and stale readings show an explanation without a time-to-capacity prediction. A capacity change over 1%, or a cleanup exceeding 5% of capacity between readings, starts a new learning period. A local budget change also hides the previous forecast immediately until readings reflect the new budget.

## What the limit means

- **Storage pools:** reported used space plus available space; each pool is forecast separately. Historical percentages alone are insufficient to reconstruct past capacity.
- **Local records:** the configured **Event storage budget (MB)**, using unique retained SIEM and telemetry payloads. This is a budget forecast, not a forecast for the whole local disk. Existing retention and pending-upload enforcement remain unchanged. Local collection continues while SMB is unavailable.
- **SMB archives:** growth in completed compressed archive files for this installation against space currently available to the archive account. Other users, files, quotas or reservations on the share can change the available space independently and fill it sooner. Incomplete file scans do not produce a forecast.

Retention can flatten growth or reduce usage. The forecast assumes the observed pattern continues; it cannot anticipate future workload changes or a retention cleanup that has not yet occurred.

## Existing history

The archive worker gradually seeds pool trends from retained local integration snapshots containing actual used and total capacity values. It ignores snapshots predating the latest connection save because those may belong to a different endpoint. Historical percentage-only metrics are not guessed using today's capacity. No bulk SMB history download is performed. New hourly measurements accumulate automatically after updating; log storage may need its first week of measurements before a forecast appears.

## Host history and identity

Accepted heartbeats collect hourly filesystem trends independently of SMB availability. When archiving is enabled, complete filesystem readings are also preserved with agent telemetry. The archive worker gradually seeds older trends from retained agent snapshots containing actual disk total/free values, and only for the same active enrollment. Existing percentage-only metrics cannot seed a forecast. Different hosts, enrollments and volume identities have separate histories. Newly identified volumes learn their own trend after an agent upgrade or replacement; historical system-drive readings without a volume identity are not guessed onto a new identified disk.

Usage is total space minus space available to the agent, so reservations or account restrictions can be included in unavailable space. The host forecast is independent of the local log storage budget and includes all files on that filesystem. Removed mounts are not displayed. Stale or revoked agent readings never produce a current prediction.

Secondary filesystem collection runs in one background probe per agent and preserves its capture timestamp. A stalled probe cannot block subsequent heartbeats or make older disk readings look fresh.
