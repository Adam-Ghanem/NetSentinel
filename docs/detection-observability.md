# Detection Observability Boundary

NetSentinel exposes a read-only, process-local snapshot for duplicate-alert suppression and bounded stateful detector pressure. The boundary is designed for dashboards, health surfaces, and future APIs without exposing suppression keys, IP addresses, destination ports, alert descriptions, raw timestamps, or mutable detector state.

## Snapshot fields

`DetectionEngine.metrics_snapshot()` returns:

- `generated_at`: timezone-aware snapshot timestamp.
- `suppression.emitted`: alerts allowed through suppression.
- `suppression.suppressed`: duplicate alerts blocked during cooldown.
- `suppression.expired`: retained keys removed after expiry.
- `suppression.evicted`: retained keys removed to enforce capacity.
- `suppression.tracked_entries`: current bounded suppression-state cardinality.
- `port_scan_state`: aggregate bounded-state counters for unique destination-port scan detection.
- `syn_flood_state`: aggregate bounded-state counters for TCP SYN-flood detection.
- `beacon_state`: aggregate bounded-state counters for periodic network beacon detection.
- `derived.total_decisions`: emitted plus suppressed decisions.
- `derived.suppression_ratio`: suppressed decisions divided by all decisions.

Each detector state uses the same sanitized `WindowSnapshot` fields:

- `tracked_keys`: active detector windows/flows.
- `tracked_events`: events currently retained across all windows.
- `expired_events`: stale events removed by time-window expiry.
- `evicted_keys`: least-recently-used keys removed at capacity.
- `dropped_events`: events removed by key or per-key bounds.
- `cardinality_limited_events`: values rejected when per-key value cardinality limits apply.

A detector state is `null` only when a consumer constructs `DetectionObservability` without that detector's snapshot provider. `DetectionEngine` wires all three stateful detectors by default. The suppression ratio is `0.0` when no suppression decisions have been evaluated.

## Safety properties

- Snapshots are immutable values, not references to internal dictionaries or deques.
- Serialization contains aggregate counters only.
- Suppression keys, IP addresses, destination ports, raw event timestamps, and packet payloads are never included.
- Timestamps must be timezone-aware.
- Reading a snapshot does not expire, evict, or otherwise mutate suppression or event-window state.
- Metrics are process-local and reset on restart.
- The boundary does not introduce high-cardinality per-source labels.

## Operational interpretation

A rising suppression ratio can indicate a noisy rule, repeated traffic, or an intentionally effective cooldown. It should not be interpreted as proof of malicious behavior. Compare it with emitted alert volume, traffic context, and analyst outcomes.

For each detector, `tracked_keys` and `tracked_events` show current in-memory pressure. Non-zero `evicted_keys`, `dropped_events`, or `cardinality_limited_events` indicate that configured safety bounds are actively constraining state. Operators should review traffic partitioning, detector policy, and capacity rather than simply increasing limits.

These counters intentionally do not identify which hosts or destination services caused pressure.

## Current limitations

The snapshot is process-local. Multiple workers expose independent counters and detector state. Aggregating metrics across workers requires a future service boundary or metrics backend. Counters reset on process restart. The current implementation intentionally does not add an unauthenticated HTTP endpoint.

## Next steps

1. Add a versioned, authenticated read-only API or metrics exporter.
2. Add per-rule aggregate counters without high-cardinality labels.
3. Add reviewed policy loading and narrowly scoped operational allowlisting where evidence justifies it.
4. Add queue, parse-failure, rule-latency, persistence, and enrichment metrics.
