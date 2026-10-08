# Host I/O history and event correlation

Open a general **Hosts → host** page. Its approved four-graph layout now contains CPU, RAM, network received/sent and disk read/write throughput. Hover, tap or use arrow keys in one graph to move all four cursors together. The two activity series use decimal MB/s; captions show interval averages at the same timestamp. Missing readings remain gaps.

## Automatic collection

Update the main application first. Signed agent **0.14.0** requires update compatibility protocol 2, so independent updaters keep the existing agent when the application cannot accept the new telemetry. Protocol 1 agents remain supported. No additional host permissions, packages or configuration are required. Linux reads kernel counters; Windows uses fixed, read-only, output/time-bounded native queries. Optional provider failures never remove the basic CPU/RAM/capacity heartbeat.

Rates begin with the second valid counter sample. Agent process restarts, reset counters, changed device membership, non-increasing sample clocks and gaps over 15 minutes produce a missing rate, not a spike or invented zero. Agent state retains bounded previous counters. Actual idle periods produce zero rates.

Linux network totals exclude loopback, known local container/tunnel interfaces, and interfaces belonging to a bond/bridge master. Windows uses hardware adapters when available, otherwise non-local virtual adapters. These are host-level aggregates, not an application traffic measurement. Interface link speed, receive/send errors and discarded packets are shown under **Network & access → View access checks** when supplied by the driver. Interface counters there are cumulative, not counts for the graph window. Guest-reported link speed is not proof of a physical NIC's speed.

Linux disk totals include whole leaf block devices, excluding partitions, loop/RAM devices and stacked devices whose backing disks are already represented. Read/write rates use 512-byte kernel sectors. **Storage & capacity → Forecast details** shows busiest sampled-device utilization and average completed read/write I/O latency, plus their histories. Windows uses corresponding physical-disk counters where available. No timed operations means unavailable latency, not zero latency. Utilization means time busy, not remaining capacity or a bottleneck diagnosis. Containers can expose host-wide kernel counters; guest/host scope must be considered before attributing I/O.

## Event markers

Dots appear at the same time positions in all four host plots. Clicking a dot opens observed evidence, the actual event timestamp, the associated host and a source-record link. Multiple events in the same chart interval share a marker. **View events** opens the selected window's list; the existing full troubleshooting chronology remains available.

Events include retained container image/restart/health changes, inferred reboots from fresh decreasing uptime, observed interface state/carrier/speed changes, check-result transitions, tickets, shell-command dispatch/results, power actions, service-remediation actions, and associated SIEM network events. Confirmed/corroborated network dependencies can contribute events, explicitly labeled with their own host. Shell commands and raw command outputs are not repeated in marker summaries. Execution acceptance/result never proves recovery.

Changes are dated when first observed; a reboot record separately retains its estimated boot time. SIEM evidence retains reported versus received timestamp metadata. Temporal proximity is a clue, not proof of causation. Quiet initial healthy readings are omitted. Up to 200 events and four network-related hosts are represented per window; bounded scans/truncation are disclosed. No SMB searches are launched automatically by loading or hovering over graphs.

## Retention and AI

I/O metrics join the existing seven-day, source-separated local metric history. Agent readings, interface snapshots, normalized metrics and change events also use the existing telemetry capture/SMB pipeline and configured retention when enabled. Numeric readings are available in the AI's current scoped host evidence. Historical searches remain explicit and bounded through the existing local/SMB archive tools; no history is injected into every AI request. Existing alert, maintenance and remediation policies are unchanged.

Sources: [Linux I/O statistics](https://www.kernel.org/doc/html/latest/admin-guide/iostats.html), [Windows physical-disk counters](https://learn.microsoft.com/en-us/previous-versions/aa394308(v=vs.85)). Native Windows collection is checked in the signed-release Windows workflow; local fixture tests do not establish a specific deployed driver's counter coverage.
