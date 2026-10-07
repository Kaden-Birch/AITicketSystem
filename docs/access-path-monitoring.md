# Certificate, DNS and application access monitoring

Find results in **Applications → Application access paths**, or the monitored
host's **Application access paths** section. Configure an existing HTTP check
using **Configure paths**, or add **Application access path**, **Certificate
expiry**, or **DNS resolution** through the host's **Add check** page.

Existing HTTP checks automatically gain DNS, verified TLS and certificate-expiry
evidence after upgrading the application. Their existing intervals, expected HTTP
statuses, failure/recovery thresholds, severity and maintenance policies remain
in effect. A verified HTTPS certificate with 30 days or less remaining counts as
a failed observation by default, giving advance warning through the usual ticket
thresholds. Change the warning period to 1–365 days in the check editor. HTTP
checks on plain HTTP do not perform a certificate check.

For existing Plex and TrueNAS connections, Applications offers prefilled server
addresses under **Add access monitoring**. Enable a check after choosing an
appropriate credential-free page/health endpoint and its expected response.
Authentication-required endpoints can use an expected 401/403, but that only
establishes the access path, not authenticated application functionality. API keys
and Plex tokens are never reused. Existing checks prevent duplicate address
suggestions. No external domain is guessed from an IP address.

## Paired checks

Optionally enter a **Public URL** and its independently expected HTTP status.
DNS, transport, certificate and HTTP results are retained separately for each
path, in one observation and one monitored check. DNS success can be compared
against an optional exact set of up to 16 expected IPv4/IPv6 addresses for the
primary path. Leave this blank for automatic resolution checks, particularly for
rotating DNS/CDN answers. Literal IP addresses are labeled separately; they do
not establish DNS health. DNS checks use the application server's configured
resolver and inspect address records, not authoritative propagation or MX/TXT.

Both paths are tested from the **AITicketSystem server**. The public check may
traverse NAT loopback or split DNS; it does not establish Internet reachability.
Internal success with a public failure is a troubleshooting lead for the failing
layer, not proof of a reverse-proxy or routing fault. Both failures also do not
prove the application is down. Inspect the individual DNS/TLS/HTTP evidence.

TLS always verifies trust and hostname using SNI. Private certificates can use an
optional readable **trusted CA file** inside the application container; those
certificates augment normal system roots. No insecure TLS bypass is provided.
Expired, not-yet-valid and hostname-mismatched certificates are distinguished
when the TLS library supplies a verification code. Failed validation cannot
provide a verified expiry date. Redirects are not followed; configure a stable
endpoint and the desired status (including a redirect status when intentional).
Response bodies, headers, redirect destinations and request paths are not logged.

## Reliability and evidence

Each endpoint runs in a separate subprocess with a hard 12-second deadline,
including DNS resolution, connection, TLS handshake and HTTP response headers.
Connections try resolved addresses within a four-second connection budget,
retain the selected address, and preserve the original HTTP Host and TLS SNI.
A paired check runs the endpoints sequentially and takes at most approximately
24 seconds. No body downloads or API authentication requests are performed.
A collector/process failure is unknown, not an application failure. Timeout and
network failures are failed observations, debounced by the normal thresholds.

Results use existing observations and telemetry archival. AI can request these
check results using its existing host evidence tools, and historical check
telemetry using bounded local/SMB searches. Logs are not automatically added to
AI prompts. Check and host maintenance suppress the usual ticket/notification
and automatic remediation behavior; manual troubleshooting remains available.
Stale/disabled results are labeled **Awaiting current result** in the access view.
There are no new agents, credentials or external dependencies to install.
