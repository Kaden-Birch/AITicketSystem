# Operations and recovery

Initialization creates a password hash, random session secret and Fernet key. `AITICKET_KEY_FILE` identifies the separately managed key. Protect it with application-only permissions and preserve it separately from the database. Initialization refuses to reset existing administrator credentials.

## Administrator access

The Administration page changes the password after checking the current password and confirmation. Passwords require 12–1024 characters. All administrator sessions are invalidated immediately through a persisted authentication generation.

For forgotten passwords, use the application account on the Ubuntu console (or the stopped container's application environment), with the same data directory and key configuration:

```sh
AITICKET_KEY_FILE=/keys/encryption.key python -m aiticket reset-password --data /data
```

The hidden prompts keep passwords out of shell history. This records a metadata-only audit entry and clears login throttles. Console access to the database remains the recovery authority.

## Offline encryption-key rotation

Stop the server and every worker. Preserve a matched database/key backup first. Rotation changes encrypted session material, Discord credentials, legacy Proxmox check credentials, discovery connection credentials, AI provider/bridge settings and per-execution AI credentials atomically in SQLite:

```sh
AITICKET_KEY_FILE=/keys/encryption.key python -m aiticket rotate-key --data /data --new-key /keys/encryption-next.key
```

The destination must not exist; the new file is created mode 0600 and flushed before the database transaction. The old file is retained. After successful completion set `AITICKET_KEY_FILE=/keys/encryption-next.key` in the service/container configuration, then restart. Do not restart with the old key after the transaction commits. Verify login and credential decryption using local fixtures before deployment.

If rotation fails before commit, the database remains encrypted under the old key; the unused destination file may remain. If interrupted after commit, inspect a stopped database copy with each candidate key to establish which decrypts the stored session secret. Keep both files until this is resolved. There is no automatic cross-file switch. Old database backups require their original key; keep them together and retire them together. A lost key cannot be recovered from a password.

## Retention and preference transfer

Administration configures 1–3650 days of routine observation retention (default 90). Hourly cleanup deletes at most 1,000 unattached observations and 1,000 heartbeat deduplication entries per pass; heartbeat entries retain 30 days. Expired enrollment tokens are cleared after one day. Attached incident observations, timelines, audit, incidents, diagnostic results and delivery history are retained indefinitely. This is partial retention rather than a total database size cap. After 30 days, an old heartbeat event ID can be ingested again; resource sample freshness still uses its original sample timestamp.

Download/paste the versioned preferences JSON through Administration. Import validates the whole document before one audited transaction. Only AI allowances, Discord severity/recovery, global reminder/escalation and routine retention are transferred. Credentials, session keys, accounts, machines, checks, discovery links and maintenance windows are excluded. Use a matched database/key backup for complete migration; a preferences file is not a backup. Preference import does not transfer connection credentials or activation/verification controls.

Normal restart retains committed observations, incidents, notes and delivery jobs. Abandoned leases recover after expiry; stale worker results are rejected. Expired/failed delivery jobs remain visible for review. Delivery may duplicate if Discord accepted a request but the reply was lost. No unsafe action replay is possible because actions are not implemented.

For application migration, stop the app and preserve its database plus any remaining WAL sidecars and the separately managed key. Preserve ownership/permissions. Start the same version and verify health, inventory and queue before upgrading. No existing Proxmox backup system is accessed.

Use one application worker in this milestone. `/health` can be checked by another device. Application downtime is not proof that all monitored hosts failed.

Troubleshooting: verify agent service/heartbeat age, endpoint routing and TLS trust before assuming OS failure. Proxmox errors are sanitized; use the Proxmox page’s separate reachability/authentication/capability tests. Discord jobs wait until a webhook is configured; inspect the queue for next attempt/errors. Production login requires HTTPS; local HTTP is loopback-development only.

Schema 2 automatically upgrades the initial milestone database transactionally. Verify with a disposable copy before upgrading production. Failed migration leaves version 1 and its records intact. Never downgrade an upgraded database: older application versions cannot safely interpret newer schemas. Immutable audit/timeline rows cannot be silently edited or deleted. History filters use explicit UTC date boundaries.

For AI recovery, retain both bridge ledger/key and the application database/key. Started bridge executions never replay after restart; unknown provider usage remains held. Cancel stale executions and reconcile only verified terminated-provider usage on Hermes & usage. See hermes-contract.md. Switching bridge credentials can make existing execution status unavailable because jobs retain their original credential snapshot; cancel/fence those jobs deliberately rather than replaying them.
