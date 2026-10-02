# UniFi Network and NAS monitoring

Upgrade the main application with `git pull --ff-only origin main` and `sudo docker compose up -d --build`. No agent or Hermes upgrade is required for this integration. Database migration 26 is automatic.

## Setup

1. Add a host representing your router/controller or NAS under **Hosts & checks**. An agent is not needed on UniFi appliances.
2. Open **UniFi** in the navigation. Select Network or Drive, associate the host, enter the console IP URL and API key. Network and NAS may require separate console addresses/keys.
3. Use a trusted CA when available, or explicitly enable the per-connection self-signed certificate option. HTTP console URLs are accepted if your console supports them; UniFi normally serves HTTPS. Enter only the origin, without an API path.
4. Save and click **Test / refresh telemetry**. Each endpoint shows readable information or a sanitized error. Keys are encrypted and never rendered back; blank key during editing retains the previous key.
5. For Network, initially leave the site ID blank to list sites. Copy the desired site's ID, save again, and refresh. Devices, connected clients, networks, and bounded device details/statistics will then be collected.
6. Polling defaults to 60 seconds (minimum 20). The host's integration check uses the existing retry, ticket, automatic AI eligibility and resolution mechanisms. Set severity/failure thresholds on the UniFi connection form. Automatic AI still requires enabled automatic triage and an eligible minimum severity.

## Available readings and limits

Network uses the official local `/proxy/network/integration/v1` API: sites, devices, clients, networks, device details and statistics. Collections use bounded pagination (300 entries per collection); detailed statistics cover the first eight devices. Missing fields are not inferred. Larger installations will need expanded collection coverage. This milestone does not promise complete firewall, routing or port-profile configuration visibility, automatic VLAN diagnosis, or historical UniFi traffic graphs.

Drive is **experimental**, using API-key telemetry reads at:

- `/proxy/drive/api/v2/storage` — pools, disks and available health/capacity fields.
- `/proxy/drive/api/v2/systems/device-info` — system and interface information.
- `/proxy/drive/api/v2/systems/network-io` — throughput.

These internal interfaces can change by firmware/version. There is no session-login fallback. Shares, users, files, logs, backup controls and snapshot controls are not queried. A working API-key field does not guarantee every Drive endpoint accepts the key. `401`, `403`, `404`, `500`, TLS errors and non-JSON/redirect responses remain explicit visibility errors; successful readings from other endpoints are retained.

The check opens attention tickets after consecutive collection failures, offline network device states, non-operational storage pools, non-optimal disks, or storage pool usage of at least 90%. Endpoint errors mean **monitoring visibility is impaired**, not a verified service outage. Device collection and individual requests have time/size limits. The displayed collection timestamp describes the snapshot, not a continuously observed state. SMB availability must still be checked from the consuming application's host: NAS health alone does not prove its mounted share is usable.

## AI and permissions

The associated host's AI investigations automatically receive a bounded, timestamped, credential-free snapshot. Optionally check **Include this Network site's observations in other hosts' AI investigations** to provide site context to other tickets. Leave this off for unrelated sites. Oversized readings are explicitly omitted from AI context; the complete bounded collection remains on the UniFi page.

AI gets stored facts, not a UniFi API key, arbitrary API paths or configuration tools. Only a fixed allowlist of GET telemetry reads is implemented; redirects are not followed. Host Full access never enables UniFi writes. Raw error bodies and unknown response fields are discarded. UniFi strings remain untrusted evidence, not instructions. Analysis must acknowledge stale or incomplete data and distinguish suspected VLAN problems from established causes.

Keep the collector credentials on the main application's protected storage. If an AI-controlled root shell is separately granted on the main application host, that root account can read application secrets; the read-only API tool boundary cannot protect against root access to the collector itself.

## Test on your equipment

Start with manual refresh and inspect endpoint results before relying on automatic alerts. Verify a Network site lists the expected router, switch and known client addresses/VLANs; verify Drive pool capacity and disk states match its UI. Do not induce a network outage to test this integration. Unsupported endpoints should produce clear errors while other readings remain visible. This release is tested with HTTP fixtures; your console/version compatibility remains to be confirmed.

References: [official UniFi Network documentation](https://developer.ui.com/), [community implementation's Drive API reference](https://github.com/LayerTM/unifi-unas-ha/blob/main/docs/API.md). The Drive reference is not an official Ubiquiti support contract.

UniFi connections and their managed checks are excluded from the existing inventory export/import format. Recreate them after inventory transfer; full database backups retain them. Offline encryption-key rotation includes UniFi keys.
