# Operations and recovery

Initialization creates a password hash, random session secret and Fernet key. `AITICKET_KEY_FILE` identifies the separately managed key. Protect it with application-only permissions and preserve it separately from the database. Initialization refuses to reset existing administrator credentials.

Password recovery and key rotation commands are not yet implemented. Do not regenerate the key: saved credentials become unreadable. An audited recovery command is required before production deployment.

Normal restart retains committed observations, incidents, notes and delivery jobs. Abandoned leases recover after expiry; stale worker results are rejected. Expired/failed delivery jobs remain visible for review. Delivery may duplicate if Discord accepted a request but the reply was lost. No unsafe action replay is possible because actions are not implemented.

For application migration, stop the app and preserve its database plus any remaining WAL sidecars and the separately managed key. Preserve ownership/permissions. Start the same version and verify health, inventory and queue before upgrading. No existing Proxmox backup system is accessed.

Use one application worker in this milestone. `/health` can be checked by another device. Application downtime is not proof that all monitored hosts failed.

Troubleshooting: verify agent service/heartbeat age, endpoint routing and TLS trust before assuming OS failure. Proxmox errors are sanitized; separate reachability/authentication/capability testing is pending. Discord jobs wait until a webhook is configured; inspect the queue for next attempt/errors. Production login requires HTTPS; local HTTP is loopback-development only.
