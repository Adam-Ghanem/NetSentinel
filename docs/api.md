# NetSentinel API Contract

The FastAPI surface is intentionally small and read-only until authentication, authorization, and a real SOAR execution boundary are reviewed.

## Supported endpoints

- `GET /` — service identity and API version.
- `GET /health/live` — process liveness; it does not depend on database or detection-rule health.
- `GET /health/ready` — readiness backed by both `DatabaseManager.database_health()` and the detection-rule loader. A degraded database or unhealthy rule set returns HTTP 503.
- `GET /api/v1/alerts?limit=N` — persisted alerts, bounded to 1–1000 records.
- `GET /api/v1/stats` — explicitly sampled packet/alert counts using a maximum sample of 1000 records.

Legacy `GET /alerts` and `GET /stats` remain available for compatibility but are marked deprecated in OpenAPI. New clients should use `/api/v1/*`.

## Readiness semantics

Detection readiness is fail-closed. NetSentinel reports the rule subsystem as unhealthy when there are no rule files, no validated rules, a YAML load error, or a rule validation error. The readiness payload exposes only aggregate fields (`files_seen`, `rules_loaded`, `load_errors`, and `invalid_rules`) so health checks do not leak rule contents or filesystem paths.

A healthy HTTP readiness response therefore means both persistence and the configured detection content passed their startup contracts. Liveness remains intentionally independent so an orchestrator can distinguish a running process from one that should not receive traffic.

## Safety boundary

NetSentinel does not expose a write endpoint that pretends to block an IP address. A previous placeholder `/soar/block/{ip}` route acknowledged actions it did not execute; it has been removed. Mutation routes should not be introduced until there is an authenticated, authorized, auditable execution path with clear failure semantics.

## Response semantics

Statistics are named `sampled_*`, not `total_*`, because the implementation intentionally reads at most 1000 recent rows. This avoids presenting a bounded query as a database-wide total.

Alert responses use a Pydantic model configured for ORM objects. Optional packet-address and enrichment fields may be `null` when the persisted alert does not contain them.

## Testing

`API Contracts` runs Ruff and all `tests/test_api_*.py` tests on Python 3.10 and 3.12. The contract covers product identity, liveness, database and rule readiness, versioned reads, query bounds, sampled-stat semantics, dependency injection, and the read-only mutation boundary. Core CI separately exercises rule-loader readiness, including the bundled rule set, so invalid shipped content cannot silently degrade production readiness.

## Deployment notes

The repository now pins FastAPI and Uvicorn as runtime dependencies and HTTPX for TestClient integration tests. Production deployments should run schema migrations before API startup, validate detection content before routing traffic, and place the service behind an authenticated boundary until first-party API authentication is implemented.
