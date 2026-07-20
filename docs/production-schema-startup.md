# Production schema startup policy

NetSentinel application workers must connect to an already migrated database. They must not create tables, patch columns, stamp migration history, or otherwise mutate schema during startup.

## Configuration

Production deployments must set:

```env
ENVIRONMENT=production
AUTO_CREATE_SCHEMA=false
```

The settings layer rejects production configuration when `AUTO_CREATE_SCHEMA=true`. `DatabaseManager` also blocks an explicit production bootstrap request as a second defensive boundary.

Development and test environments may keep `AUTO_CREATE_SCHEMA=true` for disposable local databases. Tests that rely on schema creation should request it explicitly so the behavior remains visible.

## Safe deployment sequence

1. Create and verify a database backup.
2. Run `alembic upgrade head` as a dedicated migration job.
3. Run `python scripts/check_migration_drift.py` in CI against a migrated temporary database.
4. Run `python scripts/check_database_readiness.py --database-url "$DATABASE_URL"` against the target database.
5. Start application workers only after the readiness gate succeeds.
6. Confirm application health before completing rollout.

## Runtime behavior

`DatabaseManager` separates connection setup from schema bootstrap:

- `auto_create_schema=False` opens runtime connections without creating tables.
- `bootstrap_schema()` is an explicit local-development helper.
- production rejects any attempt to enable automatic bootstrap.
- SQLite compatibility column updates run only as part of explicit bootstrap and never during migration-only production startup.

## Failure response

- Configuration validation failure: set `AUTO_CREATE_SCHEMA=false` and execute the reviewed migration workflow.
- Missing tables or outdated schema: stop deployment and run the required Alembic upgrade.
- Newer database schema than application: deploy a compatible application version or restore a verified compatible backup.
- Migration failure: do not start workers; preserve logs, verify backup integrity, and follow the database migration runbook.

Never bypass the readiness gate or enable schema auto-creation to repair a production deployment.
