# Alert Suppression Policy

NetSentinel suppresses duplicate alerts before database persistence to reduce repeated SOC noise while keeping memory bounded. Suppression is an alert-delivery policy; it does not change whether a detection rule matched.

## Rule configuration

A validated YAML rule may define:

```yaml
suppression_seconds: 300
```

The accepted range is 1 through 86,400 seconds. When the field is omitted, the process-wide suppressor default is used. Invalid values fail rule validation and the rule is skipped.

Choose a cooldown that reflects investigation value:

- short windows for high-volume denial-of-service or scan detections;
- longer windows for beaconing or repeated external-destination alerts;
- no arbitrary multi-day suppression, because it can hide materially changed activity.

The duplicate key includes alert type, source IP, destination IP, and MITRE ATT&CK technique. A change to any component creates an independent alert decision.

## Runtime semantics

`AlertSuppressor` uses a monotonic clock and stores only bounded process-local state. Each retained key carries its own expiry, allowing rules with different cooldowns to coexist safely.

The suppressor exposes cumulative sanitized metrics:

- `emitted`: alerts allowed through the suppression boundary;
- `suppressed`: duplicates blocked within their cooldown;
- `expired`: retained keys removed after expiry;
- `evicted`: oldest keys removed because capacity was reached;
- `tracked_entries`: current in-memory key count.

Metrics never include alert keys, addresses, or descriptions.

## Operational interpretation

A rising suppressed count usually indicates a noisy repeated condition, not necessarily a healthy system. Review the corresponding rule, traffic source, and threshold before increasing its cooldown. A rising eviction count means the configured state capacity is too small for current alert cardinality or the alert key is too granular.

Suppression state is process-local and resets on restart. Multiple workers do not coordinate decisions. Deployments that require cross-worker consistency need an external bounded state backend with atomic expiry semantics.

The persistence boundary remains authoritative: suppression happens before an `AlertRecord` is created and inserted. Database insertion failures are logged and do not expose suppression keys.

## Verification

```bash
python -m ruff check app/alert_suppression.py app/contracts.py app/detection_engine.py tests/test_alert_suppression.py tests/test_detection_contracts.py tests/test_rules_engine_contracts.py
python -m pytest tests/test_alert_suppression.py tests/test_detection_contracts.py tests/test_rules_engine_contracts.py
```

## Current limitations

- Metrics are available programmatically but are not yet exported through an observability endpoint.
- Cooldown changes apply to future evaluations; existing in-memory entries retain the expiry selected when they were emitted.
- Stateful detection windows and duplicate-alert suppression remain separate concerns.
