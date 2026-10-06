# UniFi network events and AI evidence

AITicketSystem includes an independent syslog collector and a searchable **Network events** workspace. Migration 41 adds source settings and manual MAC associations. The separate `network-logs` Docker volume contains the event archive; it is mounted read-only by the main application. No log message creates a ticket or authorizes remediation. Existing maintenance and host permission checks are unchanged. Manual troubleshooting remains available during maintenance.

## Connect a console

1. Update the application:
   ```sh
   cd /opt/aiticket
   git pull --ff-only origin main
   sudo docker compose up -d --build
   ```
2. In `/opt/aiticket/.env`, set `AITICKET_SYSLOG_BIND_ADDRESS` to **the AITicketSystem server's LAN IP**, then run `sudo docker compose up -d --build` again. The default is loopback. The new `log-receiver` service publishes UDP and TCP port **5514**; the application HTTP port is unchanged.
3. Open **Settings → Network logs**, add the actual sending console IP, and select its saved UniFi connection. Each sender IP is unique. Disabled or unknown sources are dropped. Changes apply within five seconds.
4. In UniFi Network, open **Integration → System Logging / SIEM**, select **SIEM Server**, choose event categories, and enter the AITicketSystem server's LAN IP and **5514**. Allow that port from the sender through your server firewall. No API key or certificate setup is needed for this syslog receiver.
5. Generate a client connection/disconnection event. The source's **Last received** time should update; open **Network events** to inspect it. If the sender arrives through NAT, use the actual source IP visible to the receiver. UDP/TCP source-IP allowlisting does not authenticate content. Collection is for trusted LAN senders; there is no TLS syslog endpoint in this release.

Ubiquiti's [System Logs & SIEM Integration documentation](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration) describes its CEF export and event fields. Exact events and available fields depend on UniFi version and selected categories. Old unstructured syslog is retained as generic messages, with coverage shown in Settings.

## Search and association

Search by host, source, severity, event time range, event/message, client IP or MAC. Pages hold 25 events, with at most 10,000 offset rows; narrow a large search to continue. Event details preserve a redacted source message and structured fields. Reported Wi-Fi airtime, interference, signal and channel have compact readouts, explicitly marked **at event time**. These are historical observations, not a continuous airtime measurement or verified current port topology. Source event severity is displayed, not converted into ticket thresholds.

A unique client MAC match in host interface inventory associates the event with that host. Duplicate MAC matches remain unassigned. Without a MAC, an IP match requires a unique interface address observed within three minutes of the event, a usable reported timestamp, and event time within three minutes of receipt. Delayed IP-only events cannot inherit today's address owner. An absent/unusable timestamp uses receipt time with an explicit label; classic syslog's missing year/timezone is not guessed. The CEF `UNIFIutcTime` field is used when it supplies an ISO timestamp and the envelope does not. ISO timestamps outside 31 days of receipt also fall back to receipt time.

A device MAC match is restricted to the source's selected UniFi connection and associates the affected AP/switch independently. The sending console is also recorded. An admin can associate a client MAC from an event's detail page; this mapping overrides automatic client matches for that source and applies immediately to retained history. Select **Use automatic matching** to remove it. It does not alter host interface configuration or confirmed network links. Bindings use MAC identity, so random/private MAC changes need a new association.

Host and UniFi device pages show the latest four associated events and a link to the full timeline. Event time is compared with currently configured maintenance schedules to show a maintenance badge; this is contextual evidence, not an immutable audit of historical policy edits.

## AI usage

Initial investigation snapshots include a small event extract around the ticket's latest failure observation, prioritizing its host, grouped targets, explicitly linked upstream network devices and related hosts (at most eight hosts / five events, about 2,600 characters of event data). Missing logs never establish health or causality.

Hermes can request `aiticket_host` with `action: evidence`, `source: network_logs`, an allowed affected `machine_id`, `offset` and `limit`. This reuses existing target authorization and read-only evidence policies. Results exclude the duplicate raw message, are redacted and bounded to 50 records / 50,000 item characters, and include pagination and maintenance context. Update/restart the Hermes companion to advertise the new source; tool-free mode receives the initial snapshot. External log text is explicitly untrusted and cannot override instructions, host permissions or maintenance controls.

This release provides collection and troubleshooting evidence. Automated incident correlation, security detections and remediation rules are deferred until actual feeds can be assessed.

## Collector limits and operation

The receiver supports newline-delimited TCP and RFC6587 octet-counted frames, plus UDP datagrams. It caps each message at 16 KiB, TCP connections at 32, idle TCP lifetime at 30 seconds, sources at 32, and ingestion at 100 messages/second per source with a 200-message burst. Batches are bounded to 500 messages. Rate-limited, oversized, unauthorized and storage-failed events are dropped rather than retrying indefinitely; counters and last receipt times are visible in Settings. These counters describe the current process run.

Default retention is seven days, 100,000 events and an estimated 200 MB event/index budget. The first limit reached removes oldest records. Configure 1–30 days, 1,000–1,000,000 events and 10–2,000 MB in Settings. Database allocation can differ from estimated event bytes; incremental vacuum reclaims deleted pages. Two-second batch commits use the separate archive; read queries have a short busy timeout and a 250 ms SQLite progress budget. The app reports unavailable evidence if the archive is missing or busy.

`sudo docker compose logs --tail=50 log-receiver` shows listener/storage status without printing received messages or secrets. Docker reports unhealthy if the collector heartbeat stops. Include the event volume in backups if retaining history matters; existing operational backups do not automatically contain it. Standalone installations can run `python -m aiticket log-receiver --host 0.0.0.0 --port 5514`; `AITICKET_LOG_DATA` sets the archive path, otherwise it is next to `app.db`.
