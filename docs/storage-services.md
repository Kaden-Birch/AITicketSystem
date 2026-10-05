# TrueNAS, HexOS, Plex and host discovery

## Add TrueNAS or HexOS

Go to **Hosts → Add host**, select **TrueNAS · SCALE or HexOS**, and enter a name, the HTTPS address, the API key owner and their API key. **Test connection** previews pool/application counts without adding a host. Validation stays on the form and preserves your entries. Save adds the host, its read-only API connection and a general health check. Connection settings live in **Host settings**.

This uses TrueNAS middleware JSON-RPC 2.0 over WebSocket at `/api/current`, available in TrueNAS SCALE 25.04 and 25.10. HexOS uses that same underlying API. No agent, packages, developer mode or persistent changes to the NAS OS are needed. 25.04.2.6 does not need an upgrade to try this integration. Hardware-specific and permission-dependent readings can be unavailable; test against your own installed release before relying on them.

Create a dedicated account with the **Read-Only Administrator** role and an API key owned by that account. Supported reads are `system.info`, `pool.query`, `pool.dataset.query`, `app.query`, `alert.list` and `service.query`, with `reporting.realtime` and `app.stats` subscriptions. These need the corresponding read roles, including REPORTING_READ and APPS_READ. Authentication uses `auth.login_ex` with API_KEY_PLAIN over HTTPS. Certificate verification is enabled by default. The collector contains an explicit method allowlist; it cannot start/stop apps or modify NAS configuration, even if supplied a more powerful key.

Use a certificate whose hostname/IP matches the address, trusted by the application. For a private CA, place the public CA file in the application container, readable by its user, and enter that container path. **Skip certificate verification** is available when adding a TrueNAS host and in its **Host settings → TrueNAS connection**. Enable it for a self-signed NAS certificate without copying a CA file; then select **Test connection** and **Save changes** (or **Add host**). The option applies only to that TrueNAS connection, including automatic polling. A saved CA path is ignored while it is enabled. HTTPS remains encrypted, but the server identity is not verified. Turn it off to restore verification using the saved CA path or system trust. TrueNAS 25.04 requires HTTPS for API-key authentication and revokes keys submitted over HTTP; this option does not switch to HTTP. API keys are encrypted with the existing application key, never included in AI context or shown again in settings. Blank replacement-key fields retain the saved key.

## Host workspace

TrueNAS appears in **Hosts** with CPU, memory, storage and uptime when reported. The page shows multiple pool cards, free/used space, RAID/vdev arrangement, searchable datasets, discovered apps, contained workloads, mounts, alerts, services and network interfaces. Performance graphs retain seven days of samples. Additional graphs are tucked behind a disclosure to keep the page compact.

**Monitor pool** and **Monitor application** create dedicated checks; discovering an app does not automatically monitor every container. Check editing in host settings retains the source and permits interval, failure/recovery threshold and severity changes. The general TrueNAS check watches pool health and serious NAS alerts. Applications deploying/initializing and absent/denied readings remain unverified rather than being counted as verified failures. A stopped monitored app, missing target or unhealthy pool can open a ticket using the existing incident and AI policies.

Reads are bounded to 100 pools, 300 datasets and 100 apps, with up to 50 containers/mounts per app. Dataset queries are limited and the AI context marks coverage limits; this is not an unlimited inventory. Statistics unsupported by a particular release/account remain unavailable. API connection or permission failures appear in Monitoring health rather than falsely proving that the NAS is down. Polling runs separately from the main check/command queues so waiting for NAS events does not delay one-second ping checks.

## Plex on any host

Use **Applications → Add Plex**, or **Add Plex** on a host. Select the host that runs Plex, enter its direct server address and Plex token, and test the connection. Plex connections have their own page under Applications; existing application grouping and dependencies remain available.

The server-response check is added when saving. Active-stream and transcoding counts and response time have history graphs. Viewing titles, users, client addresses and tokens are not retained in diagnostics. To retrieve your own Plex token, follow [Plex’s token instructions](https://support.plex.tv/articles/204059436-finding-an-authentication-token-x-plex-token/). Prefer HTTPS where available; HTTP is supported for existing local Plex servers and sends the token unencrypted across that network.

After testing, choose a library, save, then select **Monitor media access**. This asks Plex for a sample media part and confirms a one-byte HTTP range read through Plex’s own file-serving API. It tests the storage access used by Plex, including SMB-mounted media on TrueNAS, without installing an agent on the NAS. It does not prove the mount is SMB, that every file is readable, or that playback/transcoding succeeds. Empty libraries, denied reads, unsupported range responses and redirects leave access unverified. An explicit failed sample read can open a separate media-access ticket even while Plex remains running.

Plex’s method/path allowlist permits only server identity, library listing, session counts, sample selection and bounded file reads. No library refreshes, deletes, playback controls or settings changes are sent. Removing a Plex connection disables its checks and preserves ticket history.

## Docker and process discovery

Linux and Windows agent **0.11.0+** send a bounded inventory with each heartbeat. On the host, expand **Containers & processes** to search Docker containers or processes and select **Monitor** for a one-click check. Checks use container names and process names rather than short-lived PIDs. Multiple processes with the same name share a name-based check. Resource counters are informational; unknown/first-sample counters show a dash. Process CPU is measured per logical core and can exceed 100%.

Docker requires its CLI and daemon access in the agent’s OS account (root on Linux, LocalSystem on Windows). Windows Docker installations scoped to an interactive user may not be visible to LocalSystem. Process inventories include up to 200 entries and Docker up to 100 containers. Linux prioritizes resource use; Windows lists the largest working sets. Command arguments, environment variables and Docker secrets are not collected. Stale/revoked inventories cannot create new discovery checks. Existing agents without this feature remain compatible; the independent signed updater supplies the newer agent.

## AI access and backups

Freshness, host metrics, pool/app state, storage mount metadata, Plex media-access results and bounded discovery are included in the existing host diagnostic context available through the AI target tools. Large snapshots may be omitted from initial ticket context to preserve incident evidence; the AI can retrieve the current host context through targets. API credentials are never supplied to the AI and there is no arbitrary TrueNAS/Plex write tool.

Full application/database backups retain encrypted connections (and require the original encryption key). Portable nonsecret inventory export deliberately omits TrueNAS/Plex connection checks because their credentials and live connections are not exported; re-add these integrations after a portable import.

## API references

- [TrueNAS API overview](https://www.truenas.com/docs/scale/api/)
- [TrueNAS app inventory](https://api.truenas.com/v25.04.2/api_methods_app.query.html)
- [TrueNAS app statistics](https://api.truenas.com/v25.04.2/api_events_app.stats.html)
- [TrueNAS real-time host statistics](https://api.truenas.com/v25.04.2/api_events_reporting.realtime.html)
- [Plex Media Server API](https://developer.plex.tv/pms/)

Updated agents also report Docker restart/exit/health details. **Details** in host container inventory includes resource trends and **Collect recent logs**. NAS app and server-version transitions are recorded under host **Recent changes**. Host/service **Knowledge** links organize reusable guides and fixes. See [Settings and knowledge](settings-and-knowledge.md).
