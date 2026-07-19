# Database Migrations

NetSentinel uses Alembic for reviewed, repeatable schema changes. The application schema version in `app/schema.py` remains an operator-facing compatibility signal, while Alembic's `alembic_version` table is the authoritative migration history.

## Create a new database

Set `DATABASE_URL`, then apply all migrations:

```bash
python -m alembic -c alembic.ini upgrade head
```

After migration, verify all operational checks:

```bash
python scripts/check_database_health.py
python scripts/check_schema_version.py
python scripts/check_migration_drift.py
```

The drift check returns JSON and exits successfully only when SQLAlchemy metadata matches the reviewed Alembic history. It intentionally sanitizes unexpected failures instead of printing connection strings or raw database errors.

## Upgrade an existing deployment

1. Stop write traffic.
2. Create a verified database backup.
3. Record the current Alembic revision with `python -m alembic current`.
4. Review the pending SQL with `python -m alembic upgrade head --sql` where the target dialect supports offline generation.
5. Apply `python -m alembic upgrade head` in a maintenance window.
6. Run database health, schema compatibility, and migration drift checks.
7. Resume writes only when every check passes.

## Migration authoring rules

- One coherent schema change per revision.
- Every revision must have deterministic upgrade tests.
- Model changes that affect persisted schema must include a reviewed migration in the same pull request.
- CI must run `scripts/check_migration_drift.py` against a newly migrated database on every supported Python version.
- Data backfills must be bounded, restartable, and observable.
- Never embed credentials or production URLs in migration files.
- Avoid runtime model imports inside revision files; revisions must remain stable as application code evolves.
- Update `CURRENT_SCHEMA_VERSION` only when compatibility requirements change, and seed the matching value in the reviewed migration.

## Drift response

A `drift_detected` result means application metadata contains schema operations that are absent from migration history. Do not bypass the gate or stamp the database. Generate and review a focused revision, inspect the upgrade operations, add deterministic tests, and rerun the check.

An `unhealthy` result means verification could not complete safely. Treat it as an operational failure: validate configuration, database reachability, migration state, and CI logs without copying credentials into issues or pull requests.

## Rollback policy

The baseline downgrade intentionally raises an error because dropping all security telemetry, cases, alerts, and users is destructive. Recovery for the baseline is backup restoration, not automated downgrade.

Future revisions may provide a downgrade only when it is demonstrably non-destructive and covered by tests. Destructive changes require a forward-fix migration and a documented restore plan.

## Legacy databases

Databases created before Alembic are reported as `unversioned`. Do not stamp them blindly. First:

1. Back up and verify the database.
2. Compare its tables and columns against the baseline migration.
3. Repair any drift through a reviewed migration or controlled data export/import.
4. Stamp the baseline only after proving the live schema is equivalent.
