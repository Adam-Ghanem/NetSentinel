# Legacy database adoption

NetSentinel treats adoption of a pre-Alembic database as an explicit operator action. Application workers must never infer that an existing schema is safe to stamp.

## Safety contract

Run the read-only validator before any migration metadata is written:

```bash
python scripts/check_legacy_database.py --database-url "$DATABASE_URL"
```

The command exits with `0` only when all expected application tables and columns match the current SQLAlchemy metadata and no existing NetSentinel or Alembic version table is present. Output is JSON and does not include the database URL or raw exception text.

A `blocked` result requires investigation. Missing tables, column drift, or existing migration metadata must not be bypassed with a blind `alembic stamp`. An `unhealthy` result means connectivity or inspection failed and also blocks adoption.

## Required procedure

1. Stop all application writers.
2. Create and verify a database backup.
3. Run `scripts/check_legacy_database.py` against the exact target database.
4. Review every unexpected table and column before proceeding.
5. Only after a `ready` result, use an explicitly reviewed Alembic stamping procedure for the baseline revision.
6. Run the database readiness and migration drift checks before restarting workers.
7. Keep the backup until post-deployment validation is complete.

## Why stamping is not automated

Stamping records migration history without executing schema changes. Doing it automatically could mark an incompatible database as current and hide missing constraints, tables, or columns. NetSentinel therefore separates read-only validation from the privileged stamping action.

## Recovery

If validation fails, do not alter the production database in place. Restore a copy into an isolated environment, reconcile the schema through a reviewed migration, test application compatibility, and repeat the validation. For destructive or ambiguous drift, restore from the verified backup rather than forcing migration metadata.
