# Alert Suppression

NetSentinel suppresses repeated alerts that have the same alert type, source IP, destination IP, and MITRE ATT&CK technique during a bounded cooldown period.

## Operational behavior

- The first matching alert is persisted.
- Repeated matches inside the cooldown are not persisted.
- The same rule firing for a different source or destination remains independent.
- Entries expire after the cooldown and may alert again.
- The in-memory state has a fixed maximum capacity and evicts the oldest retained key first.
- Suppression decisions use a monotonic clock so wall-clock corrections do not extend or shorten cooldowns unexpectedly.

The default cooldown is 60 seconds and the default maximum state size is 10,000 keys. These defaults protect the database and dashboard from packet-by-packet duplicate alerts while keeping memory growth bounded.

## Failure and restart semantics

Suppression state is process-local and intentionally ephemeral. Restarting a worker clears the cooldown state. This avoids hidden persistence and keeps the first implementation deterministic, but multiple workers do not yet share suppression decisions.

The persistence boundary remains authoritative: suppression happens before an `AlertRecord` is created and inserted. Database insertion failures are logged and do not silently modify the cooldown key structure outside the normal emission decision.

## Testing policy

Tests use an injected deterministic clock and verify:

- cooldown boundaries,
- bounded capacity,
- expiration,
- distinct source handling,
- duplicate persistence prevention,
- deterministic alert timestamps.

## Next step

A later stateful-detection milestone should add per-rule event windows, explicit suppression settings in validated rule contracts, metrics for emitted and suppressed alerts, and a shared backend when horizontal workers are introduced.
