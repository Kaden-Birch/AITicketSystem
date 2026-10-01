# Scheduled maintenance and notification escalation

Schema 6 adds maintenance windows, incident notification silence and a persisted severity floor.

## Maintenance

Policies supports one-time windows (maximum 31 days) and weekly windows. Scope can be global or a machine and its explicitly configured descendants. Windows use an IANA timezone; the application bundles tzdata 2026.4 for consistent rules in its minimal container. Update that dependency deliberately when timezone rules change.

The clock-change tests use historical transitions, and current rules reflect Alberta's permanent UTC−6 transition in November 2026. Reference: https://www.alberta.ca/albertas-new-time-system-abt . Weekly schedules follow local wall time; in a repeated clock hour a weekly window covers both occurrences. One-time ambiguous times choose the first occurrence. Nonexistent local times are rejected. Overnight weekly windows must be split into two same-day windows; multiple windows can overlap.

Windows are start-inclusive/end-exclusive. Checks and evidence gathering continue, but new incidents are suppressed and queued notifications are paused. Existing incidents are not marked resolved. Disable a window to stop applying it; window changes are audited. Temporary check snooze remains supported. A persisted incident silence pauses notifications independently of monitoring; zero minutes resumes delivery.

## Notifications

Reminders and persistence escalation default disabled. Configure global intervals under Policies; enabled intervals are at least 60 seconds. Scope-specific reminder/escalation overrides remain future work.

Reminder identity combines incident UUID and elapsed interval slot. Missed slots are not replayed: scheduling uses the current slot and supersedes older pending/leased reminder jobs. Stable deduplication survives restarts. Reminder pacing uses incident first-failure age, including elapsed maintenance/silence time, but scheduling requires fresh failure evidence after the pause ends. Stale or detached sources cannot justify a new reminder or escalation. Manually resolved incidents do not schedule them.

Escalation raises severity to the configured level once persistence reaches the threshold. A stored severity floor prevents subsequent observations from silently reducing it. It does not authorize actions or AI. The original observations remain unchanged; the incident timeline records escalation. Existing Discord severity filtering applies at enqueue and is rechecked before delivery.

Queued non-recovery notifications become obsolete after resolution. Recovery settings are rechecked before delivery. Disabling reminders supersedes queued reminder messages at dispatch. Ownership tokens are rechecked before sending so cancelled/coalesced jobs do not dispatch using a stale lease. External Discord acceptance remains at-least-once: lost replies may still cause duplicate notifications.

Monitoring outages, Docker execution and real notification endpoints remain untested in the deployment environment. Local tests cover schedules, timezone behavior, suppression, silence, coalescing, escalation floors and filter revalidation. No live infrastructure or model calls were made.

## Scoped notification policies

Policies can define one notification group per machine and complete overrides for groups or individual machines. Machine overrides take precedence over group overrides, then global defaults. The GUI displays effective settings. Removing an override restores inheritance. Groups are independent of dependency parents and maintenance scope.

Each override configures enabled state, severity minimum, recovery messages, reminders and persistence escalation. Disabled policies suppress notification enqueueing and escalation; delivery rechecks current effective settings, including already queued events. Reminder evaluation honors overrides even when global reminders are disabled. Machine monitoring and incident evidence continue. Policy changes never authorize recovery or increase AI budgets.
