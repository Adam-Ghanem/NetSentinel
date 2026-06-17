<p align="center">
  <img src="assets/logo.svg" alt="NetSentinel logo" width="220">
</p>

<h1 align="center">NetSentinel</h1>

NetSentinel is an educational network metadata monitoring prototype. It is built to demonstrate Python, Scapy, Streamlit, SQLAlchemy, basic detection logic, and SOC-style investigation workflows.

The project is intended for learning, lab environments, and portfolio demonstration. It should be used only in environments where monitoring is allowed.

## Current Project Status

This repository is a prototype, not a finished enterprise product. The documentation below separates completed work from features that are still in progress.

### Implemented

- Metadata parsing for Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, and basic HTTP fields.
- SQLAlchemy models for packets, connections, alerts, cases, IOC cache entries, and users.
- Local SQLite storage for packet metadata and alerts.
- Password hashing with bcrypt for local dashboard authentication.
- YAML rule loading for basic detection conditions.
- Streamlit dashboard pages for login, overview metrics, packet display, alerts, cases, IOC lookup, and reports.
- IOC enrichment structure with optional AbuseIPDB and VirusTotal API keys.
- PDF report generator module using ReportLab.
- Docker and Docker Compose configuration for local deployment.

### Partially Implemented

- Live metadata collection backend exists, but the dashboard workflow still needs improvement.
- PCAP upload page exists, but full parsing and database ingestion are still in progress.
- Case management data model exists, but the dashboard workflow needs stronger integration with alerts.
- Report generation module exists, but the dashboard download workflow needs to be completed.
- Detection rules include stateful ideas, but the rule engine needs more complete time-window logic.

### Planned

- More reliable time-window based detections.
- Better connection tracking and persistent connection logs.
- Improved dashboard actions for live collection, case updates, and report export.
- Unit and integration tests.
- GitHub Actions for automated testing.
- Dependency pinning and stronger Docker health checks.
- Demo screenshots and sample data.

## Architecture

```text
NetSentinel/
├── app/
│   ├── sniffer.py          # Scapy-based collection wrapper
│   ├── parser.py           # Metadata extraction
│   ├── analyzer.py         # Traffic statistics and connection tracking
│   ├── detection_engine.py # Alert creation from matched rules
│   ├── rules_engine.py     # YAML rule loading and evaluation
│   ├── enrichment.py       # IOC lookup and local cache support
│   ├── database.py         # SQLAlchemy models and database helper methods
│   ├── report_generator.py # PDF report generation
│   ├── case_manager.py     # Case creation and update helpers
│   ├── config.py           # Environment-based configuration
│   └── utils.py            # Shared utility functions and logging
├── dashboard/
│   └── streamlit_app.py    # Streamlit user interface
├── rules/
│   └── default_rules.yaml  # Example detection rules
├── data/
│   └── sample_packets.csv  # Sample packet data
├── reports/                # Generated reports
├── requirements.txt
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
```

Initialize the local database and create demo users:

```bash
python -c "from app.database import DatabaseManager; db = DatabaseManager(); db.create_user('admin', 'admin', role='Admin'); db.create_user('analyst', 'analyst', role='Analyst'); print('Demo users created.')"
```

Demo credentials are intended only for local testing:

```text
admin / admin
analyst / analyst
```

Optional `.env` example:

```env
ABUSEIPDB_API_KEY=""
VIRUSTOTAL_API_KEY=""
DATABASE_URL="sqlite:///netsentinel.db"
LOG_LEVEL="INFO"
```

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
docker-compose up --build
```

The dashboard should be available on port `8501`.

## Detection Rules

Rules are stored in YAML format under the `rules/` directory. The current rule engine supports a basic subset of conditions such as protocol, destination port, source IP, TCP flags, DNS query patterns, packet thresholds, unique destination ports, and selected unusual ports.

Some rule fields in `default_rules.yaml` describe planned stateful behavior. They should be treated as roadmap items until the engine fully supports time-window tracking.

## Example Workflow

1. Start the dashboard.
2. Log in with a local demo account.
3. Review stored metadata.
4. Review generated alerts.
5. Create or update investigation cases.
6. Enrich public indicators when API keys are configured.
7. Generate a PDF report once dashboard export is fully connected.

## Development Notes

The project is intentionally small and educational. It is useful for demonstrating knowledge of networking, Python, Streamlit, SQLAlchemy, basic detection engineering, and SOC workflow design.

Before presenting the project as a completed platform, the remaining partial features should be completed and tested.

## License

This project is provided for defensive security education and portfolio use.
