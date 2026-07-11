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
- SQLAlchemy models for packets, alerts, cases, IOC cache entries, and users.
- Local SQLite storage for packet metadata and alerts.
- Password hashing with bcrypt in the database helper layer.
- YAML rule loading for basic detection conditions.
- Streamlit dashboard pages for overview metrics, PCAP analysis, packet display, and alerts.
- IOC enrichment helpers with optional AbuseIPDB and VirusTotal API keys.
- Optional AlienVault OTX indicator sync through the CLI when an API key is configured.
- PDF report generator module using ReportLab.
- Docker and Docker Compose configuration for local deployment.
- Tests for parsing, rule evaluation, database access, PCAP processing, cases, IOC cache, and JA3 matching.

### Partially Implemented

- Live metadata collection backend exists, but the dashboard workflow still needs improvement.
- Case management and IOC cache helpers exist, but they are not connected to dashboard pages yet.
- Report generation module exists, but the dashboard download workflow needs to be completed.
- Detection windows are kept in memory and reset when the process restarts.

### Planned

- More reliable time-window based detections.
- Better connection tracking and persistent connection logs.
- Improved dashboard actions for live collection, case updates, and report export.
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

- Python 3.12+
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

Optional `.env` example:

```env
ABUSEIPDB_API_KEY=""
VIRUSTOTAL_API_KEY=""
OTX_API_KEY=""
DATABASE_URL="sqlite:///netsentinel.db"
LOG_LEVEL="INFO"
LOG_FILE=""
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
docker compose up --build
```

The dashboard should be available on port `8501`.

## Detection Rules

Rules are stored in YAML format under the `rules/` directory. The current rule engine supports protocol, destination port, source IP, TCP flags, payload and DNS patterns, recent packet thresholds, unique destination ports, byte rate, SYN/SYN-ACK ratio, repeated connections, interval variance, and selected unusual ports. Recent state is held in memory for up to ten minutes.

## Example Workflow

1. Start the dashboard.
2. Log in with a local demo account.
3. Review stored metadata.
4. Review generated alerts.
5. Export stored alerts as CSV.

## Development Notes

The project is intentionally small and educational. It is useful for demonstrating knowledge of networking, Python, Streamlit, SQLAlchemy, basic detection engineering, and SOC workflow design.

The repository describes itself as a prototype because case management, enrichment, report export, and long-term state are not yet connected end to end in the dashboard.

## License

This project is provided for defensive security education and portfolio use.
