# Hermes with Codex sign-in

Use **Hermes Codex login · subscription run limits** on Hermes & usage when you authenticate Hermes using a Codex/ChatGPT account rather than a provider API key. This integration uses Hermes's native `openai-codex` / `codex_responses` route. It does not start the unrestricted Codex app-server, mirror your chat sessions or enable tools/plugins. The chosen model ID is preserved exactly; model availability is established only by a successful live inference, not by the compatibility check.

The signed bridge, immutable execution IDs, bounded evidence, ownership/handoff, local timeout/cancellation and prohibition on automatically replaying ambiguous jobs still apply. Codex mode requests one tool-free Hermes turn per execution, disables SDK retries and suppresses background review. Hermes may have other internal retry/auxiliary behavior: this is not a hard per-model-call cap. Queued runs, including failed/cancelled/ambiguous runs, count against incident, UTC-day and UTC-month limits. Counts are reserved transactionally before queueing and retained across restarts. Existing API gateway token/dollar settings and meters do not apply to these runs. Account allowance is shared with other Codex use; this app cannot report remaining allowance or guarantee a token/cost ceiling. Cancellation stops the local subprocess when permission is next checked; inference already sent to the provider may continue.

No Codex token is entered in the main application. The bridge holds a private, dedicated Hermes OAuth profile for the same account. A separate sign-in avoids copying a rotating refresh token out of your regular assistant profile. The normal Hermes installation, configuration, history and login are unchanged. Each investigation receives an isolated temporary HOME/Hermes configuration; credential resolution temporarily uses the dedicated OAuth profile. Only the exact native Codex HTTPS route is permitted; there is no API/provider fallback.

## Update both applications

Back up your matched main-app database and key before upgrading. On the main VM:

```sh
cd /opt/aiticket
sudo docker compose stop app
git pull --ff-only origin main
sha256sum -c SHA256SUMS
sudo docker compose build
sudo docker compose up -d
```

On the Hermes VM (existing bridge deployment):

```sh
sudo systemctl stop aiticket-hermes-bridge
sudo git -C /opt/aiticket-hermes pull --ff-only origin main
```

Keep separate environments: `/opt/aiticket-hermes-venv` for the bridge and `/opt/hermes-restricted/venv` for Hermes. Install the application's requirements only in the former, and the pinned Hermes package only in the latter. Their dependency pins can conflict if installed together.

## Dedicated account sign-in

These commands assume the bridge service account `aiticket-hermes` and existing secret already exist from initial installation. On the Hermes VM:

```sh
sudo install -d -o aiticket-hermes -g aiticket-hermes -m 0700 \
  /var/lib/aiticket-hermes-bridge/codex-home

sudo -u aiticket-hermes env \
  HOME=/var/lib/aiticket-hermes-bridge \
  HERMES_HOME=/var/lib/aiticket-hermes-bridge/codex-home \
  /opt/hermes-restricted/venv/bin/hermes auth add openai-codex
```

Follow the login instructions yourself. Do not paste access/refresh tokens into chat. This is an authentication operation, not a model call. If the installed CLI rejects this syntax, preserve the error and inspect its `auth --help` instead of changing normal Hermes credentials.

After sign-in, write the dedicated minimal configuration (this replaces only the new bridge profile's config):

```sh
sudo -u aiticket-hermes python3 - <<'PY'
from pathlib import Path
p=Path('/var/lib/aiticket-hermes-bridge/codex-home/config.yaml')
p.write_text('model:\n  provider: openai-codex\n  default: gpt-6.1-sol\n  api_mode: codex_responses\n  streaming: false\n')
p.chmod(0o600)
PY
```

Keep that profile directory mode 0700 and its `auth.json` mode 0600. The resolver requires an installed `resolve_runtime_provider(requested=..., target_model=...)` interface. The constructor must expose provider, API mode, reasoning configuration and fallback controls alongside the restricted options already checked by the adapter. Unknown interfaces/routes fail before a conversation.

## Switch the service to Codex

Edit `/etc/systemd/system/aiticket-hermes-bridge.service`, retaining the existing account, shared secret, state directory and hardening. Add these arguments to the existing `ExecStart` line:

```text
--execution-mode codex --codex-home /var/lib/aiticket-hermes-bridge/codex-home
```

Keep `--hermes-python /opt/hermes-restricted/venv/bin/python`. For the user's HTTP deployment, the gateway remains `http://10.128.2.203:8080`, bind address `0.0.0.0`, port `8090`, and environment `AITICKET_ALLOW_INSECURE_HTTP=1`. Then:

```sh
sudo systemctl daemon-reload
sudo systemctl start aiticket-hermes-bridge
sudo systemctl status aiticket-hermes-bridge --no-pager
```

The service advertises only its configured execution mode. Gateway-mode jobs cannot run on a Codex bridge, and Codex credentials cannot call the main application's paid API gateway. Previously accepted jobs of another mode fail without a model call; do not change mode with a live investigation outstanding.

## Main application settings

On **Hermes & usage**, choose **Hermes Codex login · subscription run limits**. For this deployment:

- Bridge URL: `http://10.128.2.39:8090`
- Bridge CA: blank for HTTP
- Shared secret: the existing bridge secret; blank retains a saved secret
- Exact model ID: `gpt-6.1-sol`
- Reasoning effort: `low`
- Initial trial limits: 1 run per incident/day/month, 90 seconds elapsed
- Automatic triage: unchecked for the first trial
- API provider URL/key/verification and prices: unused in Codex mode

Save while keeping AI disabled. Run **Check bridge compatibility**: it imports/checks the installed interfaces without resolving OAuth credentials or invoking inference. A signed success proves matching mode and interface only; it does not prove login, model entitlement, completion behavior or remaining account allowance.

When ready for a deliberately bounded live trial, review the isolated deployment and explicitly acknowledge the configured Codex trial controls using the runtime checkbox. Save, rerun the signed check, then enable. Queue one read-only triage on a noncritical active incident. Confirm model/reasoning, successful tool-free findings, no background review and normal takeover/timeout behavior before enabling routine or automatic investigations and raising limits. Do not enable API provider verification for this trial. A failed or cancelled trial still consumes the queued-run allowance; increase a limit explicitly if another reviewed trial is needed. No automatic retry is offered.

Automated tests use fake authentication resolvers and agents; development has made no live Codex login, inference or infrastructure action. Installed-version and model entitlement validation remains a deployment step.
