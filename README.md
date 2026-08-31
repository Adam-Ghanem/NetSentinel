# NetSentinel

NetSentinel is a defensive network-monitoring and SOC engineering project built with Python, Scapy, Streamlit, SQLAlchemy, and bounded stateful detection components.

It is designed for learning, lab environments, portfolio work, and controlled defensive monitoring where packet inspection is authorized.

## What NetSentinel Does

NetSentinel turns network metadata into analyst-friendly evidence through a small, inspectable detection pipeline:

- parses Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, and selected HTTP metadata;
- tracks traffic and connection context;
- evaluates typed YAML-backed detection rules;
- detects unique-destination-port scans;
- detects per-service TCP SYN floods;
- detects periodic TCP beaconing behavior;
- suppresses repeated alerts through bounded cooldown state;
- persists validated alerts and investigation data through SQLAlchemy;
- exposes sanitized process-local detection metrics;
- supports IOC enrichment with optional external provider keys;
- provides a Streamlit SOC dashboard for packets, alerts, cases, IOC lookup, and reports.

## Detection Engineering

The stateful detection layer is intentionally bounded and explicit. Detector state uses deterministic expiry, per-key limits, and global cardinality controls so memory growth is constrained under noisy traffic.

| Detector | Behavior | Default ATT&CK mapping |
| --- | --- | --- |
| Unique destination-port scan | TCP SYN activity across multiple destination ports | T1046 |
| TCP SYN flood | High SYN volume against one destination service | T1498 |
| Periodic network beacon | Repeated connections with a stable interval | T1071 |

Detailed design and operational guidance:

- [Port-scan detection](docs/port-scan-detection.md)
- [SYN-flood detection](docs/syn-flood-detection.md)
- [Beacon detection](docs/beacon-detection.md)
- [Bounded event windows](docs/event-windows.md)
- [Alert suppression](docs/alert-suppression.md)
- [Detection observability](docs/detection-observability.md)

The detectors are evidence signals, not automatic proof of compromise. Scanner traffic, monitoring systems, automation, retries, and legitimate periodic software can produce similar patterns, so alerts should be validated with asset and operational context.

## Architecture

```text
packet source
    |
    v
sniffer -> parser -> analyzer
                    |
                    v
             DetectionEngine
              /     |      \
             /      |       \
      YAML rules  stateful   threat intel
                  detectors
                     |
                     v
              suppression
                     |
                     v
              validated alert
                     |
             +-------+-------+
             |               |
             v               v
          database        dashboard
```

Core modules:

```text
app/
├── sniffer.py
├── parser.py
├── analyzer.py
├── detection_engine.py
├── rules_engine.py
├── port_scan_detector.py
├── port_scan_policy.py
├── syn_flood_detector.py
├── syn_flood_policy.py
├── beacon_detector.py
├── beacon_policy.py
├── event_windows.py
├── alert_suppression.py
├── detection_observability.py
├── enrichment.py
├── database.py
├── report_generator.py
├── case_manager.py
└── config.py
```

## Current Status

### Implemented

- typed packet, rule, severity, and alert contracts;
- bounded stateful scan, SYN-flood, and beacon detection;
- duplicate-alert suppression with cooldowns;
- sanitized detector-pressure and suppression metrics;
- SQLite-backed packet, alert, case, IOC-cache, and user models;
- Alembic migration and schema-readiness tooling;
- local authentication with bcrypt password hashing;
- Streamlit dashboard surfaces for SOC-style investigation;
- IOC enrichment structure for AbuseIPDB and VirusTotal;
- PDF report generation module;
- exact dependency pins and dependency-policy checks;
- repository secret scanning;
- non-root Docker runtime, health checks, migration jobs, and container security gates;
- GitHub Actions coverage across Python 3.10 and 3.12.

### Still in Progress

- complete PCAP ingestion into the database workflow;
- stronger live-collection controls and dashboard integration;
- alert-to-case investigation workflow improvements;
- dashboard report-download integration;
- reviewed runtime detector configuration and scoped allowlisting;
- authenticated metrics/API export;
- realistic traffic fixtures and broader end-to-end testing;
- clearer sensor/UI separation for larger deployments.

See [ROADMAP.md](ROADMAP.md) for the prioritized backlog.

## Quick Start

### Requirements

- Python 3.10+
- Docker and Docker Compose optional
- elevated local permissions may be required for live packet capture

### Local environment

```bash
git clone https://github.com/Adam-Ghanem/NetSentinel.git
cd NetSentinel

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Keep `.env` local. Real API keys should come from your environment or a secret manager and must not be committed.

Create a local administrator:

```bash
python - <<'PY'
from getpass import getpass

from app.database import DatabaseManager

username = input("Admin username: ").strip()
password = getpass("Admin password: ")
DatabaseManager().create_user(username, password, role="Admin")
print("Local administrator created.")
PY
```

Run the dashboard:

```bash
streamlit run dashboard/streamlit_app.py --server.port=8501 --server.address=0.0.0.0
```

Then open `http://localhost:8501`.

## Docker

```bash
docker compose up --build
```

The runtime image is designed to run as a non-root user and includes health-check support. Production-style deployments should apply migrations through the provided migration workflow rather than relying on application-time schema creation.

## Development and Verification

Install development tooling:

```bash
pip install -r requirements-dev.txt
```

Run the repository quick check:

```bash
make check
```

Focused stateful-detection verification:

```bash
python -m pytest \
  tests/test_port_scan_detector.py \
  tests/test_port_scan_policy.py \
  tests/test_syn_flood_detector.py \
  tests/test_syn_flood_policy.py \
  tests/test_beacon_detector.py \
  tests/test_beacon_policy.py \
  tests/test_detection_observability.py \
  tests/test_stateful_detection_integration.py
```

Secret hygiene:

```bash
python scripts/check_secrets.py .
```

CI additionally covers configuration safety, database transactions, migrations, schema compatibility, container configuration, dependency policy, supply-chain checks, and the full stateful detection contract suite.

## Security Model

NetSentinel follows a few simple defensive engineering rules:

- packet-derived data is validated before alert persistence;
- detector state is bounded rather than allowed to grow indefinitely;
- observability avoids per-host high-cardinality labels and packet payloads;
- credentials are not stored in the repository;
- production configuration rejects unsafe demo behavior;
- the container runtime is non-root;
- database migrations and readiness checks are explicit deployment concerns;
- alerts remain evidence that requires analyst validation.

If a real credential is ever committed, remove it from the repository and rotate/revoke it immediately. Secret scanning is a preventive control, not a substitute for credential rotation.

## Project Scope

NetSentinel is not presented as a finished enterprise NDR platform. It is an actively improving defensive-security project focused on transparent detection logic, reproducible engineering, bounded state, and SOC workflow design.

The current architecture is process-local. Multi-sensor or horizontally scaled deployments need deliberate shared-state or deterministic traffic partitioning before detector counts can be interpreted globally.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, validation commands, security guidance, and the pull-request workflow.

## License

This project is provided for defensive security education, authorized lab use, and portfolio work.
