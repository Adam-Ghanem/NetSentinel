# Pre-deployment Database Safety Gate

NetSentinel deployments must verify the target database before application workers start. The gate is intentionally read-only and fail-closed.

## Command

```bash
python scripts/check_predeployment.py --database-url "$DATABASE_URL"
```

A successful result returns exit code `0` and JSON with `"ready": true`. Any blocked or indeterminate state returns exit code `1`.

## Checks

The gate runs checks in a safe order:

1. **Database readiness** verifies connectivity, required tables, schema-version compatibility, and SQLite integrity where applicable.
2. **Migration drift** runs only after readiness passes and verifies that reviewed Alembic migrations match application metadata.

If readiness fails, the drift check is skipped. This avoids producing misleading migration results against an incomplete or incompatible database.

## Deployment sequence

1. Back up the database and verify that the backup can be opened.
2. Apply reviewed Alembic migrations in a dedicated migration job.
3. Run the pre-deployment gate against the same target database.
4. Start application workers only after the gate exits successfully.
5. Keep `AUTO_CREATE_SCHEMA=false` in production.

## Blocker response

- `database_readiness`: inspect connectivity, missing tables, schema version, and integrity results. Do not stamp or create tables automatically.
- `migration_drift`: add and review the missing Alembic revision, then rerun CI and the gate.
- `unhealthy`: treat the verification itself as failed. Preserve sanitized output and investigate from a privileged operator environment.

The JSON output excludes database URLs and raw exception messages, but it may contain table names and compatibility states useful to operators.
