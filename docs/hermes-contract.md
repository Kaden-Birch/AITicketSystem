# Hermes bridge and budget gateway

Milestone 8 implements a durable application queue, a companion service on the Hermes VM, a restricted Hermes Python adapter, per-model-call admission and metering, GUI activation/usage controls, and fixture tests. **The user-reported Hermes v0.20.0 installation has not been inspected or run. Live validation remains deferred. AI defaults to disabled.**

## Why a companion bridge

[Official webhooks](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/webhooks) document timestamped Generic V2 HMAC authentication. A webhook acceptance does not establish completion or intercept each underlying model request. The [official API server](https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server) describes an agent endpoint with tools. The implementation therefore uses a separate restricted bridge rather than assuming those endpoints enforce application budgets.

The adapter uses the published [`AIAgent` Python constructor and `run_conversation`](https://github.com/NousResearch/hermes-agent/blob/main/run_agent.py). It passes an empty toolset, disables context-file/memory/background-review loading, and points its model client at a credential scoped to one application execution. It checks that no tools were loaded and that the client routes to that execution's budget gateway before starting a conversation. Missing constructor options, unexpected tools/routing or incompatible completion schemas fail closed. No Hermes core file is patched. Current upstream source is a reference, not proof of compatibility with v0.20.0.

Only tool-free incident triage is supported here. It produces hypotheses and a read-only plan from a bounded deterministic report snapshot. It cannot fetch more diagnostics, execute actions, change incident health, resolve incidents, chat, take over or mirror Telegram sessions. Those capabilities remain later work.

## Deployment on the Hermes VM

Use one dedicated unprivileged account and a clean, separately reviewed Hermes installation with the intended pinned revision and dependencies. Do not reuse the normal assistant profile or copy its credentials. The source directory must not contain a project `.env`; the runner refuses it. Each execution receives an isolated temporary `HOME`/`HERMES_HOME`, no inherited provider keys, and a minimal configuration with streaming disabled. Keep this account away from infrastructure credentials, privileged groups and shell integrations. The application holds the sole model-provider credential used by this integration.

Install this repository's package/dependencies in the bridge environment and make its Python package available to the dedicated Hermes interpreter. The subprocess includes the repository root and configured Hermes source directory in `PYTHONPATH`. Do not point it at a remote executable or an unreviewed installation.

Create a shared secret through a secure local process; store the bridge copy in an account-readable mode-0600 file. Enter the same secret in the application's Hermes page. It is encrypted at rest and not redisplayed. Example **documentation IPs must be replaced**:

```sh
python -m aiticket.hermes_bridge \
  --data /var/lib/aiticket-hermes-bridge \
  --secret-file /etc/aiticket-hermes-bridge/secret \
  --hermes-source /opt/hermes-restricted \
  --hermes-python /opt/hermes-restricted/.venv/bin/python \
  --gateway https://192.0.2.10 \
  --ca /etc/aiticket-hermes-bridge/app-ca.pem \
  --host 127.0.0.1 --port 8090
```

Expose the loopback service through the VM's HTTPS reverse proxy with a certificate covering its static IP SAN. The application bridge URL must be HTTPS; optional CA paths are local files on the application VM. The gateway IP must be the main application's static address. No agent IP is configured. This adds no application IP-range ACL; signed requests and execution credentials authenticate identities independently of router/VLAN policy.

The bridge uses a SQLite WAL ledger and separate encryption key. Preserve both with restrictive permissions. A process lock permits only one bridge per state directory. Do not launch multiple instances against copied ledgers. Supervisor termination should stop the whole process group. A child is killed as a group after 180 seconds or the earlier job expiry; provider work already in flight might continue and remains reserved.

The startup compatibility check imports the isolated installed interface and inspects required constructor arguments without constructing an agent or making a model call. It is deliberately narrower than live validation. The UI's signed compatibility check does not spend a model allowance.

## Protocol and durable states

All bridge HTTP requests and responses use `X-Webhook-Timestamp` and `X-Webhook-Signature-V2`, HMAC-SHA256 over exact `<timestamp>.<body>` bytes. Clocks must agree within 300 seconds. JSON responses use sorted keys and compact separators; the application verifies the canonical bytes. Requests carry stable `X-Request-ID` execution UUIDs; delayed polls have fresh signatures.

- `GET /v1/capabilities`: version 1, toolset `[]`, `model_gateway: true`, constructor compatibility flag.
- `POST /v1/executions`: version, execution UUID, fixed model, bounded untrusted evidence, execution-only credential, maximum model calls and expiry. Credentials are encrypted in both ledgers.
- `GET /v1/executions/<uuid>`: signed execution UUID, state (`accepted`, `running`, `completed`, `failed`, `interrupted` or `not_found`) and bounded findings.
- The runner calls the application's `/api/hermes/<uuid>/v1/models` and `/chat/completions` using the scoped bearer credential. Models listing makes no provider request; completion goes through admission.

Acceptance is committed before replying. Identical POSTs return the stored state; a changed payload under the same UUID is rejected. Accepted jobs survive a bridge restart. Jobs marked running at restart become interrupted and are never automatically restarted. Terminal results survive status polling; duplicates append no extra timeline entries.

The application sends POST only once after durable transition to dispatching. After an ambiguous reply or application crash it queries that UUID; it never blindly POSTs again. A signed `not_found` fences the execution as failed, preventing a delayed earlier POST from consuming model budget. A network outage before acceptance can consequently require the administrator to queue a new execution once the old one is fenced. This favors preventing duplicate paid runs. Uncertain executions serialize subsequent dispatch until terminal state, cancellation or the one-hour application expiry. Ten jobs can be queued; one execution is dispatched at a time.

Cancellation/disable/incident resolution/expiry denies subsequent model requests. It cannot undo an already admitted provider request. Cancellation and expiry retain unknown usage. Notes never queue AI. Automatic mode is opt-in, uses its own severity filter, and queues at most one initial triage per active incident, including existing eligible incidents when enabled. Explicit requests may queue subsequent triages within the total incident allowance. Discord remains independent.

## Budget semantics

Admission uses `BEGIN IMMEDIATE` to check and reserve before each outbound provider call. The gateway fixes the job model, strips uncontrolled request options, rejects tools, streaming, images and non-text messages, limits context JSON to 32 KB, caps all chargeable output using `max_completion_tokens`, and forwards one request without automatic HTTP retries or redirects. TLS verifies by system trust or the configured CA file.

Reservations include UTF-8 bytes of the complete serialized messages plus the configured framing overhead as an input token upper bound, and the capped output tokens. **This bound is supported only after verifying a byte-based tokenizer, a bound on hidden provider framing and enforcement of output caps including reasoning.** Unverified providers/models cannot be enabled. Changing the model requires revalidating its provider bound. This implementation is not a universal tokenizer or a guarantee for arbitrary OpenAI-compatible servers.

The same transaction enforces triage allowance, cumulative incident tokens, UTC daily/monthly tokens, configured-price UTC daily/monthly cost and maximum calls per run. A successful or chargeable retry is another call. Cached tokens are included in input, displayed in the ledger and charged at the full input rate. Costs use conservative configured USD-per-million prices, integer microdollars and upward rounding; they do not impose a cap on a provider invoice or charges outside this integration. Positive token/cost allowances and prices are required; zero prohibits dispatch.

Usage and reservations count together. Numeric provider input/output/cached usage reconciles a reservation using the call's saved prices. Missing, malformed, failed, timed-out or ambiguous provider results retain the full reservation and block new calls globally, including across UTC resets. Calls are attributed to their UTC admission date. A reported input/output bound violation records actual usage and disables provider verification; the provider contract must be repaired before reactivation. An external provider violating its claimed cap can already have charged beyond a reservation; this is why live verification is required.

After a call is at least 60 seconds old and its job is terminal/unknown, the administrator can record verified provider usage and an evidence reference. Do so only after confirming termination; zero usage requires evidence of no charge. Reconciliation is audited. Never free a reservation merely because a process died. Held records, results and job histories are retained indefinitely. Per-call cached/input/output usage and price snapshots are stored in `ai_calls`; GUI meters show cumulative tokens and reservations.

If a conservative reservation exceeds a limit, no request is sent. The default 4,000-token triage allowance can be too small for Hermes's context plus the default 8,192 framing overhead. Set an allowance sufficient for the verified worst case; reducing overhead to guess at a fit defeats the bound. The failure is retained in the execution timeline and deterministic monitoring remains available.

## Deferred installed-version validation

Keep runtime/provider verification unchecked and AI disabled until a deliberately bounded live test validates v0.20.0 constructor compatibility, no loaded or dynamically added tools, exact application model routing, completion shape, all usage including failures/retries, tokenizer/framing/output bounds, isolated profile, cancellation/timeout behavior and restart handling. This conversation made no live Hermes or model request. Fixture tests prove local state/admission behavior, not the installed runtime or provider contract.
