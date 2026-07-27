# Detection Observability Boundary

NetSentinel exposes a read-only, process-local snapshot for duplicate-alert suppression and bounded port-scan detector state. The boundary is designed for dashboards, health surfaces, and future APIs without exposing suppression keys, IP addresses, destination ports, alert descriptions, or mutable detector state.

## Snapshot fields

`DetectionEngine.metrics_snapshot()` returns:

- `generated_at`: timezone-aware snapshot timestamp.
- `suppression.emitted`: alerts allowed through suppression.
- `suppression.suppressed`: duplicate alerts blocked during cooldown.
- `suppression.expired`: retained keys removed after expiry.
- `suppression.evicted`: retained keys removed to enforce capacity.
- `suppression.tracked_entries`: current bounded suppression-state cardinality.
- `port_scan_state.tracked_keys`: active source/destination scan windows.
- `port_scan_state.tracked_events`: events currently retained across all windows.
- `port_scan_state.expired_events`: stale events removed by window expiry.
- `port_scan_state.evicted_keys`: least-recently-used windows removed at capacity.
- `port_scan_state.dropped_events`: events removed by key or per-key bounds.
- `derived.total_decisions`: emitted plus suppressed decisions.
- `derived.suppression_ratio`: suppressed decisions divided by all decisions.

`port_scan_state` is `null` when a consumer constructs the observability boundary without a detector snapshot provider. The ratio is `0.0` when no suppression decisions have been evaluated.

## Safety properties

- Snapshots are immutable values, not references to internal dictionaries or deques.
- Serialization contains aggregate counters only.
- Suppression keys, IP addresses, destination ports, and packet payloads are never included.
- Timestamps must be timezone-aware.
- Reading a snapshot does not expire, evict, or otherwise mutate suppression or event-window state.
- Metrics are cumulative for the lifetime of one detection process.

## Operational interpretation

A rising suppression ratio can indicate a noisy rule, repeated traffic, or an intentionally effective cooldown. It should not be interpreted as proof of malicious behavior. Compare it with emitted alert volume, traffic context, and analyst outcomes.

`port_scan_state.tracked_keys` and `tracked_events` show current detector pressure. Non-zero `evicted_keys` or rapidly growing `dropped_events` indicate that the configured bounds are actively protecting memory and that traffic partitioning, threshold tuning, or capacity should be reviewed. These counters do not identify which hosts caused pressure by design.

## Current limitations

The snapshot is process-local. Multiple workers expose independent counters and detector state. Aggregating metrics across workers requires a future service boundary or metrics backend. Counters reset on process restart. The current implementation intentionally does not add an unauthenticated HTTP endpoint or high-cardinality per-source labels.

## Next steps

1. Add a versioned, authenticated read-only API or metrics exporter.
2. Add per-rule aggregate counters without high-cardinality labels.
3. Add reviewed detector policy configuration and narrowly scoped allowlisting.
4. Add queue, parse-failure, rule-latency, and persistence metrics.
