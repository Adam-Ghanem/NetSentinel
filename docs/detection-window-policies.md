# Stateful detector window policies

NetSentinel keeps stateful detection bounded by assigning explicit budgets to the three detector families planned for stateful evaluation:

| Detector | Window | Max keys | Events/key | Distinct values/key |
| --- | ---: | ---: | ---: | ---: |
| Scan | 60 s | 2,000 | 256 | 128 |
| Flood | 10 s | 4,000 | 512 | 64 |
| Beacon | 300 s | 2,000 | 128 | 32 |

These are defensive resource limits, not detection thresholds. A detector can still apply stricter semantic thresholds when its implementation is added.

## Safety properties

- Every budget is positive and validated at construction time.
- `max_events_per_key` bounds retained event volume.
- `max_distinct_values_per_key` bounds unique values retained for a detector key.
- `max_keys` bounds the number of simultaneously tracked detector identities.
- Expiry remains deterministic through the existing injected clock.
- Window snapshots expose aggregate counters only; policy state never contains secrets or packet payloads.

## Detector-specific semantics

The policy layer deliberately does not decide whether traffic is malicious. It only supplies a bounded state budget. Scan, flood, and beaconing detection logic can therefore evolve independently while sharing the same memory-safety contract.

## Operational guidance

If production traffic demonstrates that a budget is too low, change the policy with a focused review that includes expected event rates, memory impact, and false-negative analysis. Do not remove a bound to accommodate a detector implementation.
