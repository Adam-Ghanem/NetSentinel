# Database readiness gate

NetSentinel deployments must verify the target database before starting application workers.

## Command

```bash
python scripts/check_database_readiness.py --database-url "$DATABASE_URL"
```

The command is intentionally read-only. It does not call `Base.metadata.create_all()`, stamp Alembic history, create missing tables, or alter existing schema.

A successful report requires:

- a working database connection;
- every table declared in the SQLAlchemy metadata;
- the current NetSentinel schema version;
- a successful SQLite integrity check when SQLite is used.

The command emits JSON and exits with status `0` only when `ready` is `true`. Any incomplete, unversioned, outdated, newer-than-application, corrupt, or unreachable database blocks deployment with a non-zero exit status.

## Deployment sequence

1. Back up the database and verify the backup.
2. Run `alembic upgrade head` as a dedicated migration job.
3. Run the readiness gate against the same database URL.
4. Start or roll out application instances only after the gate succeeds.
5. Keep the previous release available until application health checks pass.

## Safety rules

- Never use application startup to repair or create production schema.
- Never stamp a legacy database without comparing its tables and columns to the baseline migration.
- Do not bypass a blocked result. Investigate the reported state and follow the migration runbook.
- The JSON output is sanitized and must not contain connection strings or raw database exception messages.

## Operator response

- `schema=incomplete`: stop rollout, restore or apply the reviewed migration path.
- `schema_version=unversioned`: use the documented legacy adoption procedure only after structural verification.
- `schema_version=upgrade_required`: deploy migrations before the application.
- `schema_version=newer_than_application`: roll forward the application or restore a compatible backup.
- `connectivity=failed`: verify credentials, network policy, database availability, and TLS settings.
- non-`ok` SQLite integrity: isolate the database and use the backup and recovery runbook.
