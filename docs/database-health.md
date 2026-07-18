# Database Health Checks

NetSentinel exposes a deterministic database health report for local operations, CI, and future service health endpoints.

## Run the check

```bash
python scripts/check_database_health.py
```

Override the configured database without editing `.env`:

```bash
python scripts/check_database_health.py --database-url sqlite:///:memory:
```

The command writes one JSON object to standard output and exits with code `0` only when the status is `healthy`. Degraded or unavailable databases return exit code `1`, which makes the command suitable for CI and container health checks.

## Report fields

- `status`: `healthy`, `degraded`, or `unhealthy`.
- `dialect`: SQLAlchemy database dialect.
- `connectivity`: whether a simple query succeeds.
- `schema`: whether every SQLAlchemy-managed table exists.
- `missing_tables`: sorted list of absent tables.
- `integrity`: SQLite `PRAGMA integrity_check` result when SQLite is used.
- `error`: exception class for failed connectivity without exposing credentials or connection strings.

## Operator response

### Unhealthy

1. Confirm the configured `DATABASE_URL` is reachable.
2. Check filesystem permissions for SQLite or network/DNS access for a server database.
3. Review application logs without printing credentials.
4. Restore from a verified backup when the database is unavailable or corrupted.

### Degraded schema

1. Stop write traffic.
2. Back up the database.
3. Compare `missing_tables` with the expected SQLAlchemy metadata.
4. Apply the approved schema migration path before restarting normal operation.

### Failed SQLite integrity

Treat any result other than `ok` as potential corruption. Preserve the original database for investigation, restore a verified backup, and validate the restored copy before resuming writes.

## Design limits

This check confirms basic reachability, expected table presence, and SQLite integrity. It is not a performance benchmark, replication monitor, migration framework, or substitute for external observability. Future service endpoints should wrap this report and avoid exposing raw exception messages or database URLs.
