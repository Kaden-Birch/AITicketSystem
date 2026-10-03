# Host network topology

Host pages show compact, colored tags for physical machines, virtual machines, containers, their Proxmox host, and confirmed/discovered switch ports. Unknown machine types remain unknown. An unlinked machine is not assumed to be physical. A VM inherits its linked Proxmox node's known uplinks rather than being described as physically plugged into a switch.

## Enable collection

1. Update/rebuild the main application.
2. Update/restart the Hermes bridge from this repository so its operational tool includes the read-only `network` action. Rerun the signed compatibility check.
3. Rerun the [agent installer](agent.md) on Linux machines, including Proxmox nodes with an enrolled agent. Existing enrollment is retained. Agent 0.8.0 adds `network.py`; copying only `agent.py` is insufficient.
4. Refresh your UniFi Network connection with its site selected. Device details must expose ports to populate the selector. Up to 16 client details are collected within the existing collection time budget; unavailable optional client-detail routes do not mark the network down. Client attachment fields vary with the installed Network version; absent fields stay unknown rather than being guessed.

The installer includes `iproute2`. Interface discovery reads names, MAC/IP addresses, carrier/operational state, bridge membership, bond members/mode/active slave, and virtualization type. Existing `lldpcli` neighbor data is collected when available. LLDP installation/configuration is optional and is not changed by the installer. Discovery failures omit optional information without stopping heartbeats. Older agents continue reporting successfully.

## Confirm connections

Open **Host settings → Network connections**. Enter/select the interface and choose the discovered switch/router port, then **Confirm connection**. Repeat for every uplink, including links to different switches or consoles. Remove an incorrect link and add the corrected one. Multiple associations per host and interface are supported; membership does not grant command privileges or UniFi write access.

An exact client MAC match yields a **Possible connection** in settings, not a confirmed physical tag. A learned MAC can be behind a bridge, VM host, bond or unmanaged switch. Shared MACs cannot identify a physical slave and are not automatically mapped. LLDP matching requires the chassis MAC and an exact port identifier also exposed by UniFi; numeric-looking labels are not guessed as port numbers. A saved association is administrator-confirmed, not proof that a cable has not subsequently moved. If a reported interface MAC changes, its saved association is labelled **Needs verification**.

**Refresh network observations** performs fixed read-only UniFi collection and reads linked Proxmox node interface configuration with `GET /nodes/{node}/network`. This can supply bridge/bond configuration without a node agent. Active Proxmox interface configuration does not establish physical carrier state; agent observations are preferred. Proxmox reads try up to three endpoints in the existing cluster using the existing shared token and CA verification. Failed reads retain their original observation times. UniFi operations remain exclusively GET; no network configuration, credentials, privileges or TLS policy are changed.

## AI troubleshooting

Every new ticket investigation receives bounded, credential-free topology facts, even when shell access is unavailable: machine type, current Proxmox placement/power observation, physical-host uplinks, interface/bridge/bond relationships, link state and recent transitions, mapping confidence, timestamps/freshness, and related guests or hosts on shared confirmed paths. Existing jobs retain their original snapshot; queue/resume a new investigation after updating.

`aiticket_host.targets` returns current cached topology for the server-bound target. In operational Codex mode, `aiticket_host` action **network** refreshes up to three relevant/shared UniFi connections and the linked Proxmox node configuration without needing an online guest agent. UniFi connections explicitly associated through a saved link, discovered target/path, or enabled shared AI context are eligible. Caller-supplied machine IDs do not redirect a ticket investigation to another machine. Cancellation/takeover fences the tool using the existing incident execution authorization. API gateway/tool-free mode receives cached facts only.

Interface/port history retains recent state transitions and the latest observation of unchanged states, rather than one row per polling sample. Unobserved transitions cannot be reconstructed. The AI is instructed to correlate observation windows, host power and all redundant uplinks. A powered-off host also drops link; a VM can still have VLAN, bridge or shared-uplink failures. Missing data, stale inventory and correlated timing alone do not prove root cause. The UI keeps the raw topology out of the normal host view.

Topology records are retained in full database backups. They are not part of the inventory configuration export. No new port-down checks or automatic network changes are enabled by this feature; it enriches existing monitoring and incident investigations.
