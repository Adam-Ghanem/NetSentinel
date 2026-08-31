<p align="center">
  <img src="assets/logo.svg" alt="NetSentinel logo" width="220">
</p>

<h1 align="center">NetSentinel</h1>

NetSentinel is an educational network metadata monitoring prototype. It is built to demonstrate Python, Scapy, Streamlit, SQLAlchemy, bounded detection logic, and SOC-style investigation workflows.

The project is intended for learning, lab environments, and portfolio demonstration. It should be used only in environments where monitoring is allowed.

## Current Project Status

This repository is a prototype, not a finished enterprise product. The documentation below separates completed work from features that are still in progress.

### Implemented

- Metadata parsing for Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, and basic HTTP fields.
- SQLAlchemy models for packets, connections, alerts, cases, IOC cache entries, and users.
- Local SQLite storage for packet metadata and alerts.
- Password hashing with bcrypt for local dashboard authentication.
- YAML rule loading for basic detection conditions.
- Bounded stateful detection for unique-destination-port scans, per-service TCP SYN floods, and periodic TCP beaconing.
- Immutable detector policies with deterministic expiry and explicit flow/event capacity limits.
- Sanitized process-local suppression and detector-pressure metrics without IP, port, or payload labels.
- Streamlit dashboard pages for login, overview metrics, packet display, alerts, cases, IOC lookup, and reports.
- IOC enrichment structure with optional AbuseIPDB and VirusTotal API keys.
- PDF report generator module using ReportLab.
- Docker and Docker Compose configuration for local deployment.
- Automated detection, parser, configuration, database, migration, and security contracts on Python 3.10 and 3.12.
- Typed startup configuration with production safety validation.
- Repository secret-hygiene scanning and safe environment defaults.

### Partially Implemented

- Live metadata collection backend exists, but the dashboard workflow still needs improvement.
- PCAP upload page exists, but full parsing and database ingestion are still in progress.
- Case management data model exists, but the dashboard workflow needs stronger integration with alerts.
- Report generation module exists, but the dashboard download workflow needs to be completed.
- Stateful detector policies are code-defined and validated; a reviewed runtime policy-loading/allowlisting boundary is still future work.

### Planned

- Evidence-driven detector tuning using realistic traffic fixtures.
- Better connection tracking and persistent connection logs.
- Improved dashboard actions for live collection, case updates, and report export.
- Broader end-to-end integration coverage.
- Authenticated metrics/API export and additional operational signals.
- Demo screenshots and sample data.

See [ROADMAP.md](ROADMAP.md) for the prioritized professionalization backlog.

## Validation

Before opening a pull request, run the repository checks that match the area you changed. The Detection Contracts workflow validates bounded detector behavior and integration on Python 3.10 and 3.12. General security checks should also include the repository secret scanner.

```bash
python -m pytest tests/test_port_scan_detector.py tests/test_syn_flood_detector.py tests/test_beacon_detector.py tests/test_stateful_detection_integration.py
python scripts/check_secrets.py .
```

The complete CI suite also covers configuration, database migrations, container hardening, dependency policy, and supply-chain checks.

## Architecture

```text
NetSentinel/
├── app/
│   ├── sniffer.py             # Scapy-based collection wrapper
│   ├── parser.py              # Metadata extraction
│   ├── analyzer.py            # Traffic statistics and connection tracking
│   ├── detection_engine.py    # Typed alert orchestration
│   ├── port_scan_detector.py  # Bounded unique-port scan state
│   ├── syn_flood_detector.py  # Bounded per-service SYN-rate state
│   ├── beacon_detector.py     # Bounded periodic connection state
│   ├── event_windows.py       # Shared bounded sliding-window primitive
│   ├── rules_engine.py        # YAML rule loading and evaluation
│   ├── enrichment.py          # IOC lookup and local cache support
│   ├── database.py            # SQLAlchemy models and database helper methods
│   ├── report_generator.py    # PDF report generation
│   ├── case_manager.py        # Case creation and update helpers
│   ├── config.py              # Validated environment configuration
│   └── utils.py               # Shared utility functions and logging
├── dashboard/
│   └── streamlit_app.py       # Streamlit user interface
├── rules/
│   └── default_rules.yaml     # Example detection rules
├── scripts/
│   └── check_secrets.py       # Deterministic repository secret scanner
├── data/
│   └── sample_packets.csv     # Sample packet data
├── tests/                     # Unit and integration contracts
├── reports/                   # Generated reports
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Requirements

- Python 3.10+
- Docker and Docker Compose, optional
- Elevated system permissions may be required for live network metadata collection

## Local Setup

```bash
git clone https://github.com/Adam-Ghanem/NetSentinel.git
cd NetSentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Keep `.env` local. Add real API keys only through your local environment or secret manager; never commit them.

For development and test tooling:

```bash
pip install -r requirements-dev.txt
python -m pytest tests/test_port_scan_detector.py tests/test_syn_flood_detector.py tests/test_beacon_detector.py tests/test_stateful_detection_integration.py
python scripts/check_secrets.py .
```

The repository also provides focused Makefile targets:

```bash
make check
```

Create a local administrator without hardcoded credentials:

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

## Security Configuration

The checked-in `.env.example` contains only safe defaults and empty secret fields. `DEMO_MODE` is disabled by default and cannot be enabled when `ENVIRONMENT=production`.

CI performs security checks across repository secrets, dependency policy, database readiness, and the runtime container. The scanner is a preventive quality gate, not a replacement for credential rotation or a managed secret store. If a real credential is ever committed, revoke and rotate it immediately even after removing it from Git history.

## Run the Dashboard

```bash
streamlit run dashboard/streamlit_app.py --server.port=8501 --server.address=0.0.0.0
```

Open the dashboard at:

```text
http://localhost:8501
```

## Docker Usage

```bash
docker compose up --build
```

The dashboard should be available on port `8501`.

## Detection Engineering

Rules are stored in YAML under `rules/`, while detector-specific stateful behavior is implemented in bounded components with validated policies.

Current stateful detectors:

- [Unique destination-port scan detection](docs/port-scan-detection.md)
- [TCP SYN flood detection](docs/syn-flood-detection.md)
- [Periodic network beacon detection](docs/beacon-detection.md)

Supporting safety boundaries:

- [Bounded event windows](docs/event-windows.md)
- [Alert suppression](docs/alert-suppression.md)
- [Detection observability](docs/detection-observability.md)

These components deliberately expose their assumptions, false-positive guidance, memory bounds, and distributed-deployment limitations instead of silently claiming enterprise-scale detection completeness.

## Example Workflow

1. Start the dashboard.
2. Log in with a local account.
3. Review stored metadata.
4. Review generated alerts.
5. Create or update investigation cases.
6. Enrich public indicators when API keys are configured.
7. Generate a PDF report once dashboard export is fully connected.

## Development Notes

The project is intentionally educational and incremental. It demonstrates networking, Python, Streamlit, SQLAlchemy, bounded stateful detection, basic detection engineering, and SOC workflow design while keeping incomplete product areas explicit.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local development setup, validation commands, security guidance, and pull-request workflow.

## License

This project is provided for defensive security education and portfolio use.
