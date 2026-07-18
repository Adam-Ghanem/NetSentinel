# Database Operations

NetSentinel uses SQLAlchemy with SQLite by default. The database layer is designed for a single local deployment or portfolio lab, not a multi-node production cluster.

## Reliability defaults

For file-backed SQLite databases, NetSentinel enables:

- foreign-key enforcement;
- a 5-second busy timeout for short write contention;
- write-ahead logging (WAL) for safer concurrent reads;
- `synchronous=NORMAL`, which is the standard WAL durability/performance trade-off;
- connection health checks before SQLAlchemy reuses pooled connections;
- short-lived sessions with commit-on-success and rollback-on-error semantics.

Query helpers reject non-integer, zero, negative, and excessively large limits. This prevents accidental unbounded dashboard reads.

## Backup

Do not copy a database file while the application is writing to it. Use SQLite's online backup API through the supplied command:

```bash
python scripts/backup_database.py
```

The command reads the configured `DATABASE_URL`, writes a timestamped file under `backups/`, runs `PRAGMA integrity_check`, and atomically renames the completed temporary file.

Choose explicit paths when needed:

```bash
python scripts/backup_database.py \
  --database data/netsentinel.db \
  --output backups/netsentinel-before-upgrade.db
```

Keep backups outside the repository and protect them as sensitive operational data. Packet metadata, alerts, cases, IOC results, and password hashes may all be confidential.

## Restore

1. Stop every NetSentinel process that can access the database.
2. Preserve the current database and its `-wal` and `-shm` companions for investigation.
3. Run an integrity check against the selected backup:

   ```bash
   sqlite3 backups/netsentinel-before-upgrade.db "PRAGMA integrity_check;"
   ```

4. Copy the verified backup to the path configured by `DATABASE_URL`.
5. Start NetSentinel and confirm login, recent alerts, cases, and packet queries.

Never merge a `-wal` file from one database snapshot with a different main database file.

## Schema changes

The current project has a small compatibility updater for additive packet columns. Before introducing destructive changes, table rewrites, or production deployments, adopt Alembic migrations with:

- one reviewed migration per schema change;
- upgrade and downgrade tests;
- a backup before upgrade;
- a documented rollback point;
- CI validation against both a new database and the previous supported schema.

## Operational limits

SQLite is suitable for a single-node demonstration and modest lab traffic. Move to PostgreSQL before supporting multiple application replicas, high write concurrency, large retention windows, or stricter recovery objectives.
