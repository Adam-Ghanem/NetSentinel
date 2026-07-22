# Container Operations

NetSentinel's default container profile is designed for local defensive analysis and portfolio demonstration without granting packet-capture privileges to the dashboard process.

## Security properties

The runtime image:

- uses Debian Bookworm slim with Python 3.12;
- installs dependencies into a dedicated virtual environment during a separate build stage;
- runs as the fixed non-root `netsentinel` user;
- copies only runtime application and reviewed operational paths into the final image;
- includes OCI source, revision, and build-date labels;
- exposes a Streamlit health check and uses `SIGTERM` for graceful shutdown.

The default Compose service:

- binds the dashboard to `127.0.0.1` rather than every host interface;
- drops all Linux capabilities;
- enables `no-new-privileges`;
- uses a read-only root filesystem and a constrained temporary filesystem;
- persists only the SQLite database and generated reports in named volumes;
- disables demo mode and automatic schema creation;
- relies on reviewed Alembic migrations before application startup.

The optional `operations` profile adds a one-shot migration job that uses the same non-root image and database volume without exposing ports or starting the dashboard.

## Build

```bash
VCS_REF="$(git rev-parse HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

docker build \
  --build-arg VCS_REF="$VCS_REF" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --tag netsentinel:local \
  .
```

## Prepare the persistent database

The application container does not create or mutate the schema automatically. Apply reviewed migrations to the shared named volume with the dedicated one-shot job:

```bash
docker compose --profile operations run --rm migrate
```

The migration runner:

- accepts only the reviewed Alembic `head` revision;
- applies migrations through the project Alembic configuration;
- runs database readiness checks after the upgrade;
- returns a non-zero exit code when migration or verification fails;
- emits a sanitized JSON summary without printing the database URL.

The command is idempotent and can be run again to confirm that the database remains at the reviewed head revision:

```bash
docker compose --profile operations run --rm migrate
```

After a successful migration, start the dashboard:

```bash
docker compose up --build -d netsentinel
```

For production-style deployments, take and verify a backup before running the migration job. Never start application workers after a failed migration or failed readiness result.

## Start and inspect

```bash
docker compose up --build -d netsentinel
docker compose ps
docker compose logs --follow netsentinel
```

The dashboard is available at `http://127.0.0.1:8501` by default. Override only the host port with `NETSENTINEL_PORT`; keep the loopback binding unless an authenticated reverse proxy is in front of the service.

## Stop safely

```bash
docker compose stop --timeout 30
docker compose down
```

Do not add `--volumes` unless the persistent database and reports have been backed up and are intentionally being removed.

## Packet capture

The secure default service has no `NET_RAW` or `NET_ADMIN` capability. Do not grant those capabilities to the dashboard container. Run packet collection as a separate, narrowly scoped sensor process and forward only normalized metadata to the application. This separation is required before NetSentinel should be presented as a production-style NDR architecture.

## Verification

CI validates:

```bash
docker compose --profile operations config --quiet
docker build --tag netsentinel:ci .
docker compose --profile operations run --rm --no-build migrate
```

It also verifies the configured non-root user, image health check, migration-job idempotency, least-privilege Compose options, persistent-volume boundaries, and build-context exclusions.
