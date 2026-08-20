# Detector evaluation contract

NetSentinel's stateful detectors use bounded windows so detection quality does not depend on unbounded in-memory state.

## Supported detector classes

- **Scan** — evaluates destination diversity within a bounded observation window.
- **Flood** — evaluates event volume within a bounded observation window.
- **Beacon** — evaluates timing regularity while retaining only bounded observations.

Every detector policy must define positive event and distinct-value budgets. Tests verify that the shipped defaults remain bounded and internally consistent.

These limits are safety controls, not detection bypasses: reaching a state budget is observable through sanitized window metrics while event payloads and keys remain excluded from telemetry.
