# NetSentinel – Advanced Network Detection & Response Platform

## Project Overview
NetSentinel has been upgraded into a robust, professional-grade Network Detection and Response (NDR) platform. Designed for cybersecurity professionals, Security Operations Center (SOC) analysts, and educational purposes, it provides comprehensive network traffic analysis, advanced threat detection, and interactive incident management capabilities. This platform is ideal for demonstrating practical skills in network security, DevSecOps, and full-stack development.

## Features

### Core Functionality
*   **Live Packet Sniffing**: Utilizes Python and Scapy for real-time network traffic capture, now with persistent storage via SQLAlchemy.
*   **Offline PCAP Analysis**: Supports uploading and analyzing `.pcap` files for retrospective investigations, with results stored and queryable.
*   **Extensive Packet Metadata Extraction**: Captures essential details including timestamp, MAC addresses, IP addresses, protocols, ports, packet size, TCP flags, DNS queries, and HTTP host/path metadata.
*   **Broad Protocol Support**: Handles Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, and HTTP (metadata only).

### Advanced Detection Engine
NetSentinel incorporates a powerful and flexible detection engine with YAML-based rules for identifying various suspicious activities, now with enhanced stateful and time-windowed analysis:
*   **Port Scan Detection**
*   **ARP Spoofing Suspicion**
*   **DNS Flood / Abnormal DNS Request Volume**
*   **High Traffic Volume from a Single Host**
*   **Suspicious TCP SYN Activity**
*   **Unusual Destination Ports**
*   **Repeated Connections to the Same External IP**
*   **Possible Beaconing Behavior**

Each alert generated includes a unique ID, timestamp, source/destination IPs, alert type, severity (Low, Medium, High, Critical), description, recommended action, and relevant MITRE ATT&CK mapping, all persistently stored in the database.

### Advanced SOC Features
*   **Zeek-like Connection Logs**: Provides detailed connection records including connection ID, IPs, ports, protocol, service guess, duration, bytes transferred, and connection state, now fully persisted.
*   **IOC Enrichment**: Automatically detects private/public IPs and offers optional integration with AbuseIPDB or VirusTotal APIs for threat intelligence. Enrichment results are cached locally in the database, and the system functions even without API keys.
*   **Baseline Anomaly Detection**: (Future Enhancement) Learns normal traffic patterns to detect spikes and abnormal protocol distributions.
*   **YAML Rule Engine**: Allows for flexible and easy management of detection rules via YAML files, enabling quick updates without code changes, now with comprehensive rule evaluation logic.
*   **Case Management**: Facilitates the creation of cases from alerts, adding analyst notes, changing status (Open, Investigating, Closed), and assigning severity/tags, with full CRUD operations via the dashboard.

### Interactive Dashboard
The interactive Streamlit dashboard provides a comprehensive view of network activity and security posture, now fully integrated with the backend and database:
*   **Secure Login Page** with **Role-Based Access** (Admin, Analyst) and proper password hashing.
*   **Live Packet Table** for real-time monitoring of captured traffic.
*   **PCAP Upload Page** for analyzing historical traffic.
*   **Visualizations**: Interactive protocol distribution charts, top source/destination IPs, top destination ports, and more.
*   **Alerts Panel** and **Risk Score** for immediate threat overview.
*   **Cases Page** for incident management workflows.
*   **IOC Enrichment Page** for on-demand threat intelligence lookups.
*   **Export Options**: Download packets and alerts as CSV, and generate professional PDF security reports.

## Architecture
NetSentinel follows a modular, layered architecture, designed for scalability and maintainability. Key components include:

*   **Packet Capture & Processing**: `sniffer.py`, `parser.py`, `analyzer.py`
*   **Detection & Rules Engine**: `rules_engine.py`, `detection_engine.py`
*   **Persistence Layer**: `database.py` (SQLAlchemy ORM with SQLite backend)
*   **Enrichment & Case Management**: `enrichment.py`, `case_manager.py`
*   **Presentation Layer**: `dashboard/streamlit_app.py` (Streamlit)
*   **Utilities & Configuration**: `utils.py`, `config.py`

```
NetSentinel/
├── app/
│   ├── sniffer.py          # Live packet capture using Scapy, persists to DB
│   ├── parser.py           # Extracts metadata from raw packets
│   ├── analyzer.py         # Performs initial traffic analysis and connection tracking
│   ├── detection_engine.py # Implements detection rules and generates alerts
│   ├── rules_engine.py     # Loads and evaluates YAML-based detection rules
│   ├── enrichment.py       # Handles IOC enrichment via external APIs and local cache
│   ├── database.py         # Manages SQLAlchemy ORM interactions and schema
│   ├── report_generator.py # Generates professional PDF security reports
│   ├── case_manager.py     # Manages security cases and analyst workflows
│   ├── config.py           # Centralized configuration management (pydantic, dotenv)
│   └── utils.py            # Common utility functions and logging setup
├── dashboard/
│   └── streamlit_app.py    # The main Streamlit web application
├── rules/
│   └── default_rules.yaml  # YAML file for detection rules
├── data/
│   └── sample_packets.csv  # Sample data for testing and demonstration
├── reports/                # Directory for generated PDF reports
├── .github/workflows/      # GitHub Actions CI/CD workflows
│   └── ci.yml              # Automated testing and linting
├── tests/                  # Unit and integration tests (to be implemented)
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker build instructions (multi-stage, non-root)
├── docker-compose.yml      # Docker Compose configuration
├── README.md               # Project documentation
└── LICENSE                 # Project license
```

## Installation

### Prerequisites
*   Python 3.10+
*   Docker and Docker Compose (for containerized deployment)

### Local Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Adam-Ghanem/NetSentinel.git
    cd NetSentinel
    ```
2.  **Create a virtual environment and install dependencies:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
3.  **Initialize the database and create default user:**
    ```bash
    python -c "from app.database import DatabaseManager; db = DatabaseManager(); db.create_user(\"admin\", \"admin\", role=\"Admin\"); db.create_user(\"analyst\", \"analyst\", role=\"Analyst\"); print(\"Database and default users created successfully.\")"
    ```
4.  **Set up environment variables (optional but recommended for API keys):**
    Create a `.env` file in the root directory with your API keys:
    ```
    ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY"
    VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
    ```

### Docker Setup
1.  **Build and run the Docker containers:**
    ```bash
    docker-compose up --build -d
    ```
    The Streamlit dashboard will be accessible at `http://localhost:8501`.

## Usage

1.  **Start the Streamlit Dashboard:**
    ```bash
    streamlit run dashboard/streamlit_app.py --server.port=8501 --server.address=0.0.0.0
    ```
    (If running locally, ensure your virtual environment is activated.)

2.  **Access the Dashboard:** Open your web browser and navigate to `http://localhost:8501`.

3.  **Login:** Use the demo credentials `admin/admin` or `analyst/analyst`.

4.  **Explore Features:**
    *   **Live Packets**: Start live sniffing (requires appropriate network permissions and `sudo` or `CAP_NET_RAW` capabilities for the container).
    *   **PCAP Upload**: Upload `.pcap` files for analysis.
    *   **Alerts**: View detected security events.
    *   **Cases**: Manage incident response workflows.
    *   **IOC Enrichment**: Look up threat intelligence for IPs/domains.
    *   **Reports**: Generate PDF security reports.

## DevSecOps
*   **Continuous Integration**: Automated testing and linting are configured via GitHub Actions (`.github/workflows/ci.yml`) to ensure code quality and prevent regressions.
*   **Containerization**: Docker and Docker Compose are used for consistent and isolated deployment environments, with optimized multi-stage builds and non-root user execution for enhanced security.
*   **Logging**: Integrated Python `logging` module for structured application logs, aiding in debugging and operational monitoring.

## Important Security Rules & Disclaimer

**THIS PROJECT IS FOR DEFENSIVE AND EDUCATIONAL USE ONLY.**

*   **Do not** include credential stealing functionality.
*   **Do not** decrypt HTTPS traffic.
*   **Do not** capture passwords or private messages.
*   **Do not** perform Man-in-the-Middle (MITM) attacks.
*   **Only analyze packet headers and metadata.**
*   **Warning**: This tool must only be used on networks owned by the user or where explicit permission exists. Unauthorized network monitoring is illegal and unethical.

## Future Enhancements
*   Implement comprehensive unit and integration tests.
*   Develop a more sophisticated baseline anomaly detection module.
*   Integrate with more threat intelligence sources.
*   Add real-time data streaming to the dashboard using WebSockets.
*   Implement user management features for adding/removing users via the dashboard.
