# Database Migrations

NetSentinel uses Alembic for reviewed, repeatable schema changes. The application schema version in `app/schema.py` remains an operator-facing compatibility signal, while Alembic's `alembic_version` table is the authoritative migration history.

## Create a new database

Set `DATABASE_URL`, then apply all migrations:

```bash
python -m alembic -c alembic.ini upgrade head
```

After migration, verify both operational checks:

```bash
python scripts/check_database_health.py
python scripts/check_schema_version.py
```

## Upgrade an existing deployment

1. Stop write traffic.
2. Create a verified database backup.
3. Record the current Alembic revision with `python -m alembic current`.
4. Review the pending SQL with `python -m alembic upgrade head --sql` where the target dialect supports offline generation.
5. Apply `python -m alembic upgrade head` in a maintenance window.
6. Run database health and schema compatibility checks.
7. Resume writes only when both checks pass.

## Migration authoring rules

- One coherent schema change per revision.
- Every revision must have deterministic upgrade tests.
- Data backfills must be bounded, restartable, and observable.
- Never embed credentials or production URLs in migration files.
- Avoid runtime model imports inside revision files; revisions must remain stable as application code evolves.
- Update `CURRENT_SCHEMA_VERSION` only when compatibility requirements change, and seed the matching value in the reviewed migration.

## Rollback policy

The baseline downgrade intentionally raises an error because dropping all security telemetry, cases, alerts, and users is destructive. Recovery for the baseline is backup restoration, not automated downgrade.

Future revisions may provide a downgrade only when it is demonstrably non-destructive and covered by tests. Destructive changes require a forward-fix migration and a documented restore plan.

## Legacy databases

Databases created before Alembic are reported as `unversioned`. Do not stamp them blindly. First:

1. Back up and verify the database.
2. Compare its tables and columns against the baseline migration.
3. Repair any drift through a reviewed migration or controlled data export/import.
4. Stamp the baseline only after proving the live schema is equivalent.
