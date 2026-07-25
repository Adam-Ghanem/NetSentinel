# Detection Observability Boundary

NetSentinel exposes a read-only, process-local snapshot for duplicate-alert suppression metrics. The boundary is designed for dashboards, health surfaces, and future APIs without exposing suppression keys, IP addresses, alert descriptions, or mutable detector state.

## Snapshot fields

`DetectionEngine.metrics_snapshot()` returns:

- `generated_at`: timezone-aware snapshot timestamp.
- `suppression.emitted`: alerts allowed through suppression.
- `suppression.suppressed`: duplicate alerts blocked during cooldown.
- `suppression.expired`: retained keys removed after expiry.
- `suppression.evicted`: retained keys removed to enforce capacity.
- `suppression.tracked_entries`: current bounded state cardinality.
- `derived.total_decisions`: emitted plus suppressed decisions.
- `derived.suppression_ratio`: suppressed decisions divided by all decisions.

The ratio is `0.0` when no decisions have been evaluated.

## Safety properties

- Snapshots are immutable values, not references to internal dictionaries.
- Serialization contains aggregate counters only.
- Suppression keys and network indicators are never included.
- Timestamps must be timezone-aware.
- Reading a snapshot does not expire, evict, or otherwise mutate suppression state.
- Metrics are cumulative for the lifetime of one detection process.

## Operational interpretation

A rising suppression ratio can indicate a noisy rule, repeated traffic, or an intentionally effective cooldown. It should not be interpreted as proof of malicious behavior. Compare it with emitted alert volume, rule identity, traffic context, and analyst outcomes.

`tracked_entries` should remain below the configured suppressor capacity. `evicted` indicates that cardinality reached the bound; sustained growth should trigger rule and deployment review.

## Current limitations

The snapshot is process-local. Multiple workers expose independent counters and suppression state. Aggregating metrics across workers requires a future service boundary or metrics backend. The current change intentionally does not add an unauthenticated HTTP endpoint.

## Next steps

1. Add a versioned, authenticated read-only API or metrics exporter.
2. Add per-rule aggregate counters without high-cardinality labels.
3. Implement bounded event windows for scan, flood, and beaconing rules.
4. Add queue, parse-failure, rule-latency, and persistence metrics.
