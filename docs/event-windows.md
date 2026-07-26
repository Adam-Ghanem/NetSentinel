# Bounded Detection Event Windows

NetSentinel uses `BoundedEventWindows` as the state primitive for future scan, flood, and beaconing detections. The component is intentionally independent from rule evaluation so its memory, expiry, and privacy behavior can be verified before stateful detections depend on it.

## Safety properties

- A monotonic clock is used by default so wall-clock changes do not extend or shorten windows.
- Every window has an explicit duration.
- The number of tracked keys is bounded.
- The number of events retained per key is bounded.
- Least-recently-used keys are evicted when key capacity is reached.
- Oldest events are dropped when a per-key window reaches capacity.
- Metrics expose aggregate counts only; keys and event payloads are never included.
- Reads return immutable tuples rather than internal deques.

## Operational semantics

`add()` expires stale state before storing a new event. Events whose timestamp is older than `now - window_seconds` are removed. An event exactly on the cutoff remains valid until the next instant, which makes threshold behavior deterministic at the boundary.

Accessing a key marks it as recently used. When `max_keys` is reached, the least-recently-used key and all events associated with it are removed. This protects the process from source-cardinality attacks while preserving active detector state.

The snapshot counters distinguish normal expiry from capacity pressure:

- `expired_events`: events removed because their time window elapsed.
- `evicted_keys`: keys removed because the key limit was reached.
- `dropped_events`: events removed due to either key eviction or the per-key event limit.
- `tracked_keys` and `tracked_events`: current in-memory state without identifiers.

## Integration guidance

Stateful rules should create separate window instances when their keys, durations, or cardinality budgets differ. Detector keys should be minimal immutable tuples, such as `(rule_id, source_ip)`, and event payloads should contain only fields required for the threshold calculation.

Before adding a stateful rule:

1. Define the exact key and threshold semantics.
2. Set a reviewed window duration.
3. Set conservative key and event limits.
4. Add deterministic clock-based tests for the threshold boundary.
5. Test expiration, key eviction, and event dropping.
6. Decide how an eviction affects alert confidence and observability.

## Limitations

The state is process-local and resets on restart. Multiple workers do not share windows. Distributed detection requires an external state service with equivalent expiry, cardinality, privacy, and failure semantics; a shared store must not be introduced merely to increase feature count.
