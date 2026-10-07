# Capacity forecasts

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
