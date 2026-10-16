# Archive transfer health and read-back verification

Network log settings, Log coverage and Telemetry history show independent SIEM
and telemetry transfer cards: pending records, queued upload MB/GB, buffer usage,
oldest pending receipt time, last verified upload and net backlog change. Records
waiting outside the upload buffer count towards pending work. Net change includes
new arrivals; it is not an upload-throughput measurement. A stale worker snapshot
cannot establish current queue state. A quiet stream with no backlog is not a
failure. Each stream can be queued, uploading, catching up, stalled or unavailable.

In **Network events → Coverage & health**, select the application server host and
enable collection-health tickets. Existing host selection and opt-in settings are
preserved. Persistent failure defaults to 15 minutes; buffer warning defaults to
90% and uses the same persistence interval. Collection health never chooses an
arbitrary host or overrides notification/remediation policies.

One archive-health check consolidates stalled streams, sustained SMB errors,
worker unavailability, sustained buffer pressure and failed SMB read-back checks.
Detected SQLite corruption is actionable immediately. Repeated observations update
the same open incident; two fresh healthy observations resolve it. Maintenance,
notification settings, incident silence and existing AI remediation permissions
continue to apply. Errors must clear; a smaller queue alone is not recovery.
Receiver and local-write failures retain their existing separate checks. If the
application database itself is unreadable/unwritable, in-app incident creation may
also be unavailable; external infrastructure monitoring remains necessary.

After a stream's historical backlog clears (zero pending, or only a small batch
within the normal five-minute batching window), the archiver automatically verifies one known
uploaded batch and repeats daily. **Verify SMB read-back now** requests the same
bounded check without waiting for the backlog. A sample from the early catch-up
uploads is retained, so verification need not be limited to the newest telemetry.
If retention legitimately expires that sample, a newer retained sample is used;
otherwise verification waits for a new upload rather than reporting a false failure.
The worker catalogs SMB history, reads/decompresses/checksums the selected batch,
searches for that record and validates the normal human search cache/reference.
It also runs the existing bounded host-scoped AI evidence adapter. Each stream
reads at most one batch (16 MB compressed, 32 MB expanded), scans at most 10,000
records and returns at most two matches; there is no local-data fallback. A missing
host association yields partial verification, never a false AI pass. An incomplete
scan yields an inconclusive result rather than proof of absent history.

Verification creates no AI run and consumes no model tokens. It does not grant an
AI job access to its search cache. Real AI requests still require the existing
run/incident/host authorization and search budgets. Completed sample links use the
existing authenticated search/detail pages and 24-hour result-cache lifecycle.
Passing verifies a sample and the evidence adapter, not a live model invocation,
complete archive coverage or recovery of records previously dropped. A destination
change clears displayed verification/progress for the previous share.
