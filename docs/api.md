# NetSentinel API Contract

The FastAPI surface is intentionally small and read-only until authentication, authorization, and a real SOAR execution boundary are reviewed.

## Supported endpoints

- `GET /` — service identity and API version.
- `GET /health/live` — process liveness; it does not depend on database access.
- `GET /health/ready` — readiness backed by `DatabaseManager.database_health()`. A degraded or unhealthy database returns HTTP 503.
- `GET /api/v1/alerts?limit=N` — persisted alerts, bounded to 1–1000 records.
- `GET /api/v1/stats` — explicitly sampled packet/alert counts using a maximum sample of 1000 records.

Legacy `GET /alerts` and `GET /stats` remain available for compatibility but are marked deprecated in OpenAPI. New clients should use `/api/v1/*`.

## Safety boundary

NetSentinel does not expose a write endpoint that pretends to block an IP address. A previous placeholder `/soar/block/{ip}` route acknowledged actions it did not execute; it has been removed. Mutation routes should not be introduced until there is an authenticated, authorized, auditable execution path with clear failure semantics.

## Response semantics

Statistics are named `sampled_*`, not `total_*`, because the implementation intentionally reads at most 1000 recent rows. This avoids presenting a bounded query as a database-wide total.

Alert responses use a Pydantic model configured for ORM objects. Optional packet-address and enrichment fields may be `null` when the persisted alert does not contain them.

## Testing

`API Contracts` runs Ruff and all `tests/test_api_*.py` tests on Python 3.10 and 3.12. The contract covers product identity, liveness, readiness, versioned reads, query bounds, sampled-stat semantics, dependency injection, and the read-only mutation boundary.

## Deployment notes

The repository now pins FastAPI and Uvicorn as runtime dependencies and HTTPX for TestClient integration tests. Production deployments should run schema migrations before API startup and should place the service behind an authenticated boundary until first-party API authentication is implemented.
