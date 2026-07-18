# Schema Versioning

NetSentinel now defines an explicit application schema version in `app/schema.py` and provides an operator-facing compatibility check.

## Check compatibility

```bash
python scripts/check_schema_version.py
```

Use a specific database without editing local configuration:

```bash
python scripts/check_schema_version.py --database-url sqlite:///netsentinel.db
```

The command emits JSON and exits with code `0` only when the database version exactly matches the application version.

## Status meanings

- `current`: the database and application schema versions match.
- `unversioned`: no `netsentinel_schema` table exists; treat the database as legacy until it is backed up and migrated.
- `upgrade_required`: the database is older than this application build.
- `newer_than_application`: the application is older than the database; do not start write traffic.
- `unhealthy`: the database could not be inspected safely.

## Deployment rule

Before deploying a build that writes to an existing database:

1. Create and verify a backup.
2. Run the schema compatibility check.
3. Stop when the result is anything other than `current`.
4. Apply reviewed migrations in a maintenance window.
5. Re-run database health and schema compatibility checks before resuming writes.

## Migration roadmap

The version registry is intentionally small and does not replace Alembic. The next migration slice should add Alembic configuration, a baseline revision, deterministic upgrade tests, and an approved rollback policy. Automatic destructive downgrades should remain disabled.
