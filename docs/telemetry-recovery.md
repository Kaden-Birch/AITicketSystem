# Offline recovery of a damaged telemetry table

Do not infer a hardware cause from SQLite corruption alone. SQLite 3.46.1 is in
the upstream range affected by the WAL-reset race, though vendor builds may carry
backports and this does not establish the cause of a particular damaged file.
The container now builds SQLite 3.54.0 from the official, SHA3-256-verified source.
The Python runtime is checked at build and startup. It includes a recovery shell.

1. Stop all Compose services. Logs arriving while the receiver is stopped may be
   lost at the sender. Keep the application, keys and log volumes intact.
2. Preserve byte-for-byte copies of `app.db` and any `-wal`, `-shm` and `-journal`
   sidecars together, without opening the protected original using SQLite. Keep a
   disposable working copy in a different directory.
3. Pull the application update and run `docker compose build`. **Do not run `up`**
   yet. Building images does not recover or replace data and does not start writers.
4. Run the new image against the disposable working copy:

   ```sh
   sudo docker compose run --rm --no-deps -T app python -m aiticket.telemetry_recovery \
     --source /data/recovery-TIMESTAMP/working/app.db \
     --output /data/recovery-TIMESTAMP/recovered.db
   ```

The recovery tool requires enough free space, refuses live/protected source paths
and existing candidates, and creates its files with private permissions. SQLite's
`.recover --ignore-freelist` writes a separate salvage file. Original configuration,
hosts, credentials, tickets, workflows and other non-telemetry tables are copied
from normal reads of the working source, **not** from salvaged SQL. Their rowids,
row contents and schema are verified. Any failure to read/copy them aborts recovery.
Only telemetry rows are imported from the salvage file, with field/JSON validation.
Rejected or duplicate records are counted; lost-and-found rows are disclosed and
not silently imported. The salvage file is kept for further inspection.

The candidate rebuilds indexes and restores the original triggers. It recalculates
the pending-byte counter and resets the uploader batch checkpoint. Record keys
and uploaded flags are preserved; SMB files are not removed. The report includes
integrity/foreign-key checks, rejected/recovered telemetry counts and protected
non-telemetry table hashes. The tool **never installs the candidate**, restarts
services or overwrites the live/protected database. A successful report still
requires review before an explicit replacement of the live database and sidecars.

Recovery cannot reconstruct records that were dropped before storage or overwritten
at the filesystem level. Archive transfer success is now tracked separately for
SIEM and telemetry, and detected SQLite corruption halts archive retries with a
specific diagnostic instead of repeatedly retrying a corrupt queue.

Sources: <https://www.sqlite.org/recovery.html>,
<https://www.sqlite.org/wal.html#walreset>, <https://www.sqlite.org/download.html>.
