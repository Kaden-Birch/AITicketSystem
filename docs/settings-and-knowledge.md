# Settings, knowledge and service diagnostics

Global configuration now lives under **Settings** in the left navigation. The top sections are General, AI & Hermes, Notifications, Telegram, AI budgets, Policies, Agent health, Recovery and Administration. Existing URLs continue to work. Host-specific settings stay on each host.

## Simpler AI and Hermes setup

Open **Settings → AI & Hermes → Connection**. Choose Codex subscription or API mode, enter your existing companion address and shared secret, and click **Save & connect**. The application checks the signed companion interface automatically; no model request is made. **Enable AI** repeats that check and activates the saved limits. Connection checks renew automatically while AI is enabled, with a five-minute backoff on failure.

Compatibility verifies connectivity and the adapter contract. It cannot prove a model login or entitlement. **Try an investigation** performs one bounded read-only investigation on a selected host and opens its ticket. No manual “runtime verified” checkbox is needed. Model/run limits, host command tools, custom certificate paths and API-provider accounting controls remain available. API-mode bounds still require operator verification because an interface check cannot prove provider billing semantics.

Usage and recent runs have separate views. Connection errors stay on the settings page; previously entered non-secret fields remain visible. Updating the companion is still necessary when its interface is incompatible; the application cannot update a remote VM without an administrative connection.

### Ask normal Hermes for status

Enable **Allow read-only status queries** on the connection page. Update the companion repository, then run the setup helper as the account that owns your normal Hermes profile. It adds one MCP entry, preserves other settings, backs up an existing configuration, and never writes your connection secret into YAML.

Example paths below assume the existing bridge layout. Replace `HERMES_PYTHON` with the interpreter for your normal Hermes installation and `APPLICATION_URL` with the application address:

```sh
cd /opt/aiticket-hermes
PYTHONPATH=/opt/aiticket-hermes HERMES_PYTHON -m aiticket.hermes_status_setup \
  --server APPLICATION_URL \
  --secret-file /path/to/private-connection-secret \
  --python /opt/aiticket-hermes-venv/bin/python
```

The secret file must contain the same connection secret, be readable by your Hermes account, and have mode 0600. Set `--config` if the normal profile lives elsewhere, `--ca` for a private CA, or `--allow-http` for the explicitly configured local HTTP deployment. The main application must also have its existing HTTP opt-in enabled. Do not point this helper at the isolated investigation profile.

Start a new Hermes session or use `/reload-mcp`. Ask “What is Voyager’s status?” or “Give me a system status report.” The tool retrieves monitoring evidence and ticket status without starting a ticket, running commands or spending an AITicketSystem investigation allowance. Your normal Hermes conversation uses its own model allowance. Global reports are bounded to 50 hosts/tickets and indicate truncation. The server-side query toggle can revoke this feature.

MCP configuration/reload behavior follows [Hermes’s official MCP documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp/).

## Knowledge Base

Open **Knowledge Base** from the left navigation. Hosts, Services, Troubleshooting and Drafts separate reusable information. Every monitored host appears on the Hosts tab, with a link to its host page. **Knowledge** on a host or Plex service opens its folder. Subfolders organize service relationships, operating notes and issue-specific fixes. Search and 25-article pages keep the workspace manageable.

Admins can create, edit, publish or archive articles. Revision history preserves previous text, and concurrent edits cannot silently overwrite newer versions. Optional source tickets connect a guide to the investigation that produced it. Article text supports headings, lists, emphasis and code blocks; HTML is escaped. Recognizable inline credentials are redacted, but articles should not contain secrets.

**Create AI draft** takes a title, folder and short brief. A host/service folder supplies the host; a general troubleshooting folder requires a source ticket. This creates a read-only writing investigation using the configured AI allowance. Its completed response becomes a draft, linked back to the source ticket. Review and publish it when ready.

Operational AI investigations can search published articles, retrieve prior tickets for affected hosts, inspect observed changes, and optionally save a sourced article in an appropriate folder. AI-authored articles are visibly labeled and published for future reuse. This is optional: no article is created merely because a ticket exists or resolves. Saved advice is historical evidence, not permission to run a fix. AI must check current versions, prerequisites and readings. AI operational retrieval/writing requires the existing Codex host-tool mode; tool-free API mode receives a bounded summary of applicable knowledge and recent changes.

## Docker and change-aware troubleshooting

Updated Linux and Windows agents add container restart counts, exit status, out-of-memory state, image identity, startup time and Docker health status to discovery. Host inventory keeps these under **Details**, alongside CPU/memory history. **Collect recent logs** opens a paused diagnostic ticket and requests at most 50 lines from the last 15 minutes. Agent output is limited to 16 KB with a five-second Linux deadline and the Windows command runner’s bounded deadline. Container names must match current discovery; local diagnostic policy can disable log collection with `container_logs: false`. Logs are not collected on every heartbeat.

AI can request the same fixed diagnostics and poll their results. Logs may contain application data; credential-pattern redaction is best effort. Current per-host permissions still apply to arbitrary shell/API commands.

**Recent changes** on a host records observed agent versions, container image/restart/startup/health changes, NAS app states/versions and NAS/Plex server versions. The first observation is a baseline, not a change. Events retain 30 days; metric history retains seven days. Changes help correlate symptoms with events, but do not prove causation. This does not capture every package/configuration change or arbitrary administrator action.

## Telegram

Open **Settings → Telegram**. Create a dedicated bot with [BotFather](https://core.telegram.org/bots/tutorial), enter its token and allowed numeric chat/user IDs, then save and enable. Both allowlists are required. Send the bot a message first. To identify your own IDs without exposing the bot token to another bot, the admin page provides a **Find my chat** action after the token is saved; send a message and select your own conversation. You can also retrieve them through the official `getUpdates` API.

The worker uses outbound polling; no incoming webhook is needed. Do not use the same bot with another poller or a configured webhook. Tokens are encrypted in the application database and never redisplayed. **Check connection** calls `getMe` and sends no message.

Commands:

- `/status [host name]` — current monitoring status, no AI run.
- `/ticket TICKET-ID` — host/ticket status and linked investigation context.
- `/reply TICKET-ID note` — append a human note to an open ticket.
- `/ask TICKET-ID question` — request a read-only AI investigation and send its findings when available. Existing ticket ownership and AI allowances still apply.

Alerts, recovery updates and requests for human help respect severity/notification policies, grouping, maintenance, check maintenance and incident silence. Maintenance pauses automated alerts; explicit status questions remain available. Incoming updates and outgoing notifications use durable identities. Ambiguous sends are marked unknown and are not automatically replayed. Delivery outcomes are visible under Telegram’s delivery details.

Polling and send semantics follow the [official Telegram Bot API](https://core.telegram.org/bots/api). Docker inspection fields follow the [official Docker inspection reference](https://docs.docker.com/reference/cli/docker/inspect/).

## Upgrade

Back up the matched database and encryption key first. Update the main application using your normal Docker Compose workflow. Update `/opt/aiticket-hermes` and restart `aiticket-hermes-bridge` for the expanded tool schema. Signed Linux/Windows releases supply deeper discovery and log capability through the existing automatic updater; older agents keep their previous capabilities until updated. Schema 39 adds knowledge, change and Telegram state and the read-only investigation flag.


## Reusable Knowledge Base workflows

Open an article and choose **Reusable workflow**. Fill in **Before you begin**, **Find the problem**, **Apply the fix** and **Verify recovery**, then save. Publish the article and enable the procedure to make it available to AI. A host/service procedure remains scoped to its host; a troubleshooting procedure can be reused across hosts. Changing the source article pauses new reuse until an administrator reviews and saves the procedure. Changing or disabling a procedure also blocks further changes from a run of the old version.

**Start troubleshooting** opens a manual ticket and starts your configured AI with that procedure. AI host tools must be enabled (update and restart the Hermes companion checkout as well so it loads the new workflow tool schema); configuration/admission failures leave a paused ticket with a clear notice. Existing AI allowances, host access modes, approvals, OS privileges and maintenance gates remain in force. Saved text is guidance, never an executable script or additional permission. During automatic investigations AI can discover approved procedures through knowledge context/search and begin a run using the `workflow` action with the article ID.

AI records each phase with a concise explanation of current evidence and a passed/failed/blocked result. Fixed read-only diagnostics remain available, but writes are blocked until prerequisites and diagnostics have passed. Failed/blocked runs stop further changes; unknown operations are never replayed automatically. A completed phase is an **AI-reported result**, not independent proof. A run is marked **Verified** only after all phases are recorded, its AI job completes and requests resolution, and independent monitoring closes the ticket through the existing recovery verifier. Monitoring verifies configured health checks, not arbitrary claims in procedure text; include appropriate checks for the intended result. Without that verification, the run stays awaiting verification.

The procedure page shows the latest verified run and host, latest unsuccessful phase, and twenty recent runs with timestamps, immutable procedure versions, step notes and ticket links. Interruptions, expiry and cancellation are distinct from success. Older immutable run plans remain in the database when a procedure changes. Articles/workflows are optional; no routine article generation or automatic script execution is introduced.
