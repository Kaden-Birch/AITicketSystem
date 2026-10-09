# UniFi Network and NAS monitoring

Upgrade the main application with `git pull --ff-only origin main` and `sudo docker compose up -d --build`. No agent or Hermes upgrade is required for this integration. Database migration 29 is automatic.

## Setup

1. Open **Network Devices → Connection settings / Add connection**. No existing host or monitoring agent is needed.
2. Select Network or Drive and enter a name, console IP URL and API key. Saving creates an independent UniFi monitoring record. Network and NAS may require separate console addresses/keys.
3. Use a trusted CA when available, or explicitly enable the per-connection self-signed certificate option. HTTP console URLs are accepted if your console supports them; UniFi normally serves HTTPS. Enter only the origin, without an API path.
4. Save and click **Test / refresh telemetry**. Each endpoint shows readable information or a sanitized error. Keys are encrypted and never rendered back; blank key during editing retains the previous key.
5. For Network, initially leave the site ID blank to list sites. Copy the desired site's ID, save again, and refresh. Devices, connected clients, networks, and bounded device details/statistics will then be collected.
6. Polling defaults to 60 seconds (minimum 20). The connection's integration check uses the existing retry, ticket, automatic AI eligibility and resolution mechanisms. Set severity/failure thresholds on the UniFi connection form. Automatic AI still requires enabled automatic triage and an eligible minimum severity.

## Available readings and limits

Network uses the official local `/proxy/network/integration/v1` API: sites, devices, clients, networks, device details and statistics. Collections are paginated; detail requests rotate across discovered devices and clients within the collection budget (see complete response retention below). Missing fields are not inferred. Deferred detail coverage is reported for larger installations. This milestone does not promise complete firewall, routing or port-profile configuration visibility, automatic VLAN diagnosis, or packet-level traffic history.

Drive is **experimental**, using API-key telemetry reads at:

- `/proxy/drive/api/v2/storage` — pools, disks and available health/capacity fields.
- `/proxy/drive/api/v2/systems/device-info` — system and interface information.
- `/proxy/drive/api/v2/systems/network-io` — throughput.

These internal interfaces can change by firmware/version. There is no session-login fallback. Shares, users, files, logs, backup controls and snapshot controls are not queried. A working API-key field does not guarantee every Drive endpoint accepts the key. `401`, `403`, `404`, `500`, TLS errors and non-JSON/redirect responses remain explicit visibility errors; successful readings from other endpoints are retained.

The check opens attention tickets after consecutive collection failures, offline network device states, non-operational storage pools, non-optimal disks, or storage pool usage of at least 90%. Endpoint errors mean **monitoring visibility is impaired**, not a verified service outage. Device collection and individual requests have time/size limits. The displayed collection timestamp describes the snapshot, not a continuously observed state. SMB availability must still be checked from the consuming application's host: NAS health alone does not prove its mounted share is usable.

## AI and permissions

The connection's AI investigations automatically receive a bounded, timestamped, credential-free snapshot. Optionally check **Include this Network site's observations in other hosts' AI investigations** to provide site context to other tickets. Leave this off for unrelated sites. Oversized readings are explicitly omitted from AI context; the complete bounded collection remains on the appliance detail page.

AI gets stored facts, not a UniFi API key, arbitrary API paths or configuration tools. Only a fixed allowlist of GET telemetry reads is implemented; redirects are not followed. Host Full access never enables UniFi writes. Raw error bodies and credential fields and unknown text fields are discarded; additional numeric telemetry is retained. UniFi strings remain untrusted evidence, not instructions. Analysis must acknowledge stale or incomplete data and distinguish suspected VLAN problems from established causes.

Keep the collector credentials on the main application's protected storage. If an AI-controlled root shell is separately granted on the main application host, that root account can read application secrets; the read-only API tool boundary cannot protect against root access to the collector itself.

## Test on your equipment

Start with manual refresh and inspect endpoint results before relying on automatic alerts. Verify a Network site lists the expected router, switch and known client addresses/VLANs; verify Drive pool capacity and disk states match its UI. Do not induce a network outage to test this integration. Unsupported endpoints should produce clear errors while other readings remain visible. This release is tested with HTTP fixtures; your console/version compatibility remains to be confirmed.

References: [official UniFi Network documentation](https://developer.ui.com/), [community implementation's Drive API reference](https://github.com/LayerTM/unifi-unas-ha/blob/main/docs/API.md). The Drive reference is not an official Ubiquiti support contract.

UniFi connections and their managed checks are excluded from the existing inventory export/import format. Recreate them after inventory transfer; full database backups retain them. Offline encryption-key rotation includes UniFi keys.

Existing connections are automatically detached from their previously selected host during migration 27. Connection/check IDs, keys, snapshots, observations and ticket IDs are retained; UniFi tickets move to the independent record. Other checks, agents and tickets on the previously selected host remain there. Monitoring records also appear in the existing overview; Network device inventory remains on the UniFi page.
Any in-flight AI investigations on the old UniFi association are cancelled on migration, so they cannot continue operating against the previously associated host. Start a new investigation on the retained ticket after updating.

If an older build repeatedly appended connection forms during live updates, update the main application and reload the UniFi page once to load the corrected script and clear duplicated markup. No agent or Hermes update is needed.


## Network Devices and appliance pages

Network Devices lists console/NAS connections and automatically discovered Network appliances separately from Hosts. Select a NAS to see storage pools, RAID, disks, temperatures, SMART counters, CPU/memory and interface observations. Select the Dream Machine or switch to see identity, reported port identifiers/link speeds, available network assignments, current statistics and all retained facts. Network console pages list devices, networks/VLANs and connected clients. Missing API fields are labelled rather than invented. Configuration is on the separate connection-settings page.

Each collection retains numeric telemetry for seven days, with 1h/6h/24h/7d chart windows. Histories begin after this upgrade; no historical values are fabricated. Gaps remain gaps. Useful numeric series such as utilization, temperature, throughput, uptime and reported error counters have graphs; the complete retained values are in the expandable observations table. NAS raw vendor-specific SMART counters alone do not establish failure.

Discovered Network appliances receive independent device-availability checks and their own tickets. Only ONLINE establishes an up result; OFFLINE/DISCONNECTED establish failures, and stale/missing/unknown states are unknown. Repeated polling of the same collection timestamp does not advance retry or recovery counters. NAS storage and visibility alerts remain attached to the NAS connection. Existing ticket, Discord and automatic AI severity/enablement settings apply. Network access remains read-only regardless of host shell modes.

Discovered-device checks inherit the connection polling interval, severity and failure/recovery thresholds. Saving connection settings updates these inherited values.

## Delete a device

Open Network Devices, select the appliance, then Device settings → Delete device. Discovered devices are removed from monitoring and excluded from later discovery; existing observations and tickets are preserved. To remove a NAS or an entire console connection, its Device settings page offers Delete connection. This disables its checks and child-device checks and clears the stored API key. Open tickets are paused rather than falsely resolved, and pending notifications are superseded. These operations affect only AITicketSystem, never the UniFi appliance or network configuration.

## Statistics compatibility

Network device statistics use `GET /proxy/network/integration/v1/sites/{siteId}/devices/{deviceId}/statistics/latest`, as specified in the [official Network OpenAPI specification](https://developer.ui.com/network/v10.1.84/openapi.json). Earlier builds omitted `/latest`, producing HTTP 404 responses. Update the main application and refresh the connection to retry the corrected route.

Unavailable optional statistics remain visible in the snapshot and check evidence as `optional_telemetry_errors`; they alone do not mark the network down. Required inventory/API failures and actual device or NAS health failures still affect their checks. A previous statistics-only incident can recover after the configured number of successful check samples. This does not establish application or end-to-end network health.

### NAS workspace

Open **Network Devices → your UniFi Drive connection** for the visual NAS overview.
Drive bays follow reported slot labels; explicitly reported bay counts can reveal
missing readings. Unknown models use the same flexible layout without a model list.
An unreported bay is unknown, never assumed empty or healthy. Select a bay to open
its details. Multiple storage pools appear separately with their reported RAID type.

CPU usage, CPU temperature (when reported) and RAM usage have compact bars.
Colors are presentation guidance only: CPU 70/90%, RAM 75/90%, CPU temperature
70/85 °C mark elevated/high ranges. Temperature is displayed on a 20–100 °C scale.
These colors do not change monitoring thresholds, ticket creation or recovery logic.
Stale or missing readings are unavailable rather than green.

Network history has 10-minute, 30-minute, 1-hour, 6-hour, 24-hour, week and month
views. **Read** means incoming network traffic; **Write** means outgoing traffic.
They do not represent disk I/O. Hover, tap or use arrow keys for the nearest exact
recorded sample and timestamp. Gaps are preserved. Retention remains seven days,
so the month view displays only available history. Additional performance history,
monitoring checks, tickets, settings and retained diagnostics remain accessible.

### Network equipment workspace

Discovered switches, routers and access points use a visual workspace: compact CPU/RAM/temperature cards, reported Ethernet and fiber ports as rounded status tiles, port detail drawers, an at-a-glance status panel, and device uplink history. Port counts follow telemetry rather than a product catalog. Gray DOWN ports are unused/disconnected, not automatically faults. Blue uplink tiles require an explicitly reported port association. Missing or stale measurements remain unavailable. Resource colors are presentation thresholds and do not change check or ticket decisions.

History offers 10 minutes through one month, with exact retained samples on hover/tap or keyboard. Retention remains seven days; longer views show available history. Cumulative port counters are shown in port details and are not plotted as rates. Network rates follow the existing `rxRateBps`/`txRateBps` byte-rate convention; no inferred traffic or invented PoE wattage is displayed.

When a network device reports its own storage disks or slot count, NVR bays appear inside the equipment illustration and open the same drive detail drawer as the NAS workspace. The documented [Network API](https://developer.ui.com/network/v10.0.162/openapi.json) does not guarantee Protect/NVR storage telemetry. The workspace does not invent bay counts from model names or fetch undocumented Protect endpoints. A separate supported Protect telemetry integration is needed where disk information is absent.

Settings, manual refresh, monitoring checks, ticket creation/history, network/client observations and retained diagnostic readings remain available.

## Network log collection

For independent CEF/syslog ingestion, event search, host associations and AI evidence, see [Network events setup](network-logs.md). Log collection supplements the API and does not change ticket thresholds.

### Network interface and radio readings

Device details and latest statistics are complementary responses. Statistics may
contain an empty `interfaces` object and uplink traffic without a parent ID. The
presentation joins these with device details, preserving physical port states,
negotiated speeds, radio channels, channel widths, wireless standards and uplink
parent identity. Dashboard tiles and port drawers use the same normalized port
readings. An UP port with an unavailable speed stays connected; unavailable or
stale readings are not treated as disconnected. A parent device ID alone does
not identify an uplink port. PoE state, enabled status, standard and type are
shown when reported.

The [UniFi Network Integration API schema](https://developer.ui.com/network/v10.3.58/openapi.json)
reports per-band transmit retries (`txRetriesPct`), but does not document airtime
utilization. Retries are never converted to airtime. AP cards show retries when
no explicit airtime reading is available; device pages show band configuration,
current readings and bounded API history with exact-value mouse, touch and
keyboard inspection. Radios are matched by frequency, not array position;
ambiguous duplicate bands are not assigned another radio's measurements.
Explicit valid airtime/utilization percentages can be displayed if a response
includes them. Event-time airtime received through network logs remains in the
separate Wi-Fi observations section, with its own source and coverage.

API radio history uses existing seven-day metric retention and the selected
Network activity time range. It does not reconstruct past readings. Existing
retained per-band retry samples are supported even if array order changed.
Collection remains read-only and bounded by the existing endpoint, device-count,
response-size and time limits; this does not change monitoring or ticket rules.

## Complete response retention

UniFi collection now preserves every operational field in each accepted JSON response, including unrecognized fields, long strings and complete nested lists. Credential-valued fields remain excluded/redacted. The UI is a projection of retained data rather than the boundary of what can be stored.

When telemetry capture or SMB archiving is enabled, every response is recorded separately as `unifi_api_response` under the UniFi telemetry kind, with connection ID, endpoint, pagination parameters, HTTP status and collection time. Device responses are assigned to the linked device host when available; initial discovery and console-wide responses belong to the connection host. JSON error responses are also retained. Existing local/SMB retention and storage budgets apply. No request headers or API keys are archived.

Network collection includes site inventory, devices, connected clients, network definitions, each network's detail, each device's detail/statistics and each client's detail. Protect information, camera inventory and individual camera details are queried automatically on the same console. Separate Protect consoles still require a connection capability; this does not discover or authenticate arbitrary consoles. Drive retains the complete storage/device/network-I/O responses already queried. Unsupported Protect/network-detail endpoints are optional collection errors, not proof the network is down.

There is no longer a first-eight-device or first-sixteen-client cutoff. Detail requests rotate with a persisted cursor when the 20-second collection budget is exhausted, with a visible deferred count. Inventory is paginated beyond the former 300-item limit. Transport limits (2 MB per response, request timeout, collection budget and a pagination safety ceiling) still apply; rejected responses and incomplete inventory are disclosed rather than represented as complete data. No unlimited dump of every possible UniFi endpoint, write endpoint, video stream or WebSocket feed is performed. New endpoints require explicit integration support, but new fields on supported endpoints do not need a collector update.

Individual full-response archive records allow up to 4 MiB after redaction/serialization, avoiding the ordinary 1 MiB aggregate-snapshot limit. Archive budget/storage failures are reported in collection warnings. SMB outages use the existing local buffer and retry mechanism; finite storage cannot guarantee unlimited retention after an extended outage.

AI receives compact evidence only. `archive_search` retrieves scoped local or SMB history explicitly. `archive_record` can then read a chosen record, select a JSON-pointer subtree (for example `/response/ipv4Configuration`), or page through its JSON text using `offset` and returned `next_offset`. Pages contain at most 3,000 characters. SMB record reads require the original search's run/host grant. Stored telemetry is observed, untrusted evidence, never authorization to change configuration.
