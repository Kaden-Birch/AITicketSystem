# Hermes validation gate

User-reported installation: Hermes Agent v0.20.0 (2026.8.3), Python 3.11.15. Its runtime/files have not been inspected. Latest online documentation is not proof of installed compatibility.

Official reference reviewed 2026-10-01:
https://hermes-agent.nousresearch.com/docs/user-guide/messaging/webhooks

Generic V2 uses `X-Webhook-Signature-V2` and `X-Webhook-Timestamp`, signing exact bytes `<timestamp>.<body>` with HMAC-SHA256 hex. Stable `X-Request-ID` preserves event identity. Documented timestamp validity is ±300 seconds. The implemented signing helper is tested; delayed retries sign a fresh timestamp. Upstream deduplication has a limited lifetime, so application state must persist independently.

## Installed-version spike still required

Use a disposable restricted route with an explicitly bounded test allowance. Verify triggering, completion/failure, usage including failed/retried calls, input/output/turn limits, pause/cancel semantics, restricted tool access, authenticated callbacks, duplicate handling and offline recovery. Do not print secrets or change Hermes core.

A webhook acceptance is not completion. Determine whether a supported bridge can return durable execution status and intercept every model request for admission/metering. Prompt-only budget instructions cannot guarantee limits. Unknown acceptance must be queried without blindly starting another run.

## Proposed contract — not implemented

Admission: schema version, execution/incident UUIDs, bounded untrusted evidence, policy reference, allowed diagnostics, token reservations, remaining incident/global ceilings, max calls/turns and expiry.

Completion: authenticated timestamped envelope with callback event UUID, same execution UUID, terminal result, bounded findings, provider input/output/cached usage and actual diagnostic execution references. Duplicates are no-ops. Unknown usage retains reservation pending reconciliation.

Restrict tools deliberately in administrator configuration. Budget approval never authorizes mutation. Until the installed interface proves enforceable admission and completion, AI remains disabled; GUI values are clearly labeled saved preferences.
