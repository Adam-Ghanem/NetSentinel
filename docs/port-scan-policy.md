# Port-scan Detection Policy

NetSentinel configures the bounded unique-port scan detector through the immutable `PortScanPolicy` contract.

## Fields

- `threshold`: unique destination ports required for one source/destination pair to match. Minimum `2`.
- `window_seconds`: sliding observation window. Must be greater than zero and no more than 24 hours.
- `max_sources`: maximum number of active source/destination keys retained in memory.
- `max_events_per_source`: maximum retained events for one key and must be at least `threshold`.

Unknown fields are rejected. Policies are frozen after validation so runtime code cannot silently mutate detector limits.

## Safe construction

Prefer passing one reviewed policy object:

```python
policy = PortScanPolicy(
    threshold=12,
    window_seconds=30,
    max_sources=20_000,
    max_events_per_source=500,
)
detector = UniquePortScanDetector(policy=policy)
```

Legacy keyword configuration remains supported for compatibility, but it is converted immediately into the same validated policy. Supplying both a policy and individual overrides is rejected because the effective configuration would be ambiguous.

## Tuning guidance

Start with observed administrative and vulnerability-scanner traffic. Increase the threshold or shorten the window only after reviewing false positives and missed detections. Capacity limits protect process memory; they are not detection thresholds. Sustained `evicted_keys` or `dropped_events` metrics indicate pressure and should trigger traffic-partitioning or capacity review.

## Current limits

- Policy is constructed in process and is not yet loaded from a signed or versioned deployment configuration.
- Detector state remains process-local and resets on restart.
- Approved-scanner allowlisting is intentionally excluded until a narrow, audited policy is designed.
- Multi-worker deployments do not share scan windows.
