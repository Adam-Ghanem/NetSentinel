# NetSentinel – Network Packet Sniffer, Traffic Analyzer & Mini NDR Platform

## Project Overview
NetSentinel is a professional cybersecurity portfolio project designed for educational, Security Operations Center (SOC), and personal cybersecurity use. It functions as a defensive network monitoring tool, capable of capturing network traffic, analyzing packet headers and metadata, detecting suspicious behavior, and presenting insights through an interactive dashboard. The platform also generates professional security reports, making it an ideal tool for demonstrating practical network security skills.

## Features

### Core Functionality
*   **Live Packet Sniffing**: Utilizes Python and Scapy for real-time network traffic capture.
*   **Offline PCAP Analysis**: Supports uploading and analyzing `.pcap` files for retrospective investigations.
*   **Extensive Packet Metadata Extraction**: Captures essential details including timestamp, MAC addresses, IP addresses, protocols, ports, packet size, TCP flags, DNS queries, and HTTP host/path metadata.
*   **Broad Protocol Support**: Handles Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, and HTTP (metadata only).

### Detection Engine
NetSentinel incorporates a robust detection engine with rules for identifying various suspicious activities:
*   **Port Scan Detection**
*   **ARP Spoofing Suspicion**
*   **DNS Flood / Abnormal DNS Request Volume**
*   **High Traffic Volume from a Single Host**
*   **Suspicious TCP SYN Activity**
*   **Unusual Destination Ports**
*   **Repeated Connections to the Same External IP**
*   **Possible Beaconing Behavior**

Each alert generated includes a unique ID, timestamp, source/destination IPs, alert type, severity (Low, Medium, High, Critical), description, recommended action, and relevant MITRE ATT&CK mapping.

### Advanced SOC Features
*   **Zeek-like Connection Logs**: Provides detailed connection records including connection ID, IPs, ports, protocol, service guess, duration, bytes transferred, and connection state.
*   **IOC Enrichment**: Automatically detects private/public IPs and offers optional integration with AbuseIPDB or VirusTotal APIs for threat intelligence. Enrichment results are cached locally, and the system functions even without API keys.
*   **Baseline Anomaly Detection**: Learns normal traffic patterns to detect spikes and abnormal protocol distributions.
*   **YAML Rule Engine**: Allows for flexible and easy management of detection rules via YAML files, enabling quick updates without code changes.
*   **Case Management**: Facilitates the creation of cases from alerts, adding analyst notes, changing status (Open, Investigating, Closed), and assigning severity/tags.

### Dashboard
The interactive Streamlit dashboard provides a comprehensive view of network activity and security posture:
*   **Login Page** with **Role-Based Access** (Admin, Analyst).
*   **Live Packet Table** for real-time monitoring.
*   **PCAP Upload Page**.
*   **Visualizations**: Protocol distribution charts, top source/destination IPs, top destination ports.
*   **Alerts Panel** and **Risk Score**.
*   **Cases Page** for incident management.
*   **IOC Enrichment Page**.
*   **Export Options**: Download packets and alerts as CSV, and generate professional PDF security reports.

## Architecture
NetSentinel follows a modular architecture, organized into distinct components:

```
NetSentinel/
├── app/
│   ├── sniffer.py          # Live packet capture using Scapy
│   ├── parser.py           # Extracts metadata from raw packets
│   ├── analyzer.py         # Performs initial traffic analysis and connection tracking
│   ├── detection_engine.py # Implements detection rules and generates alerts
│   ├── rules_engine.py     # Loads and evaluates YAML-based detection rules
│   ├── enrichment.py       # Handles IOC enrichment via external APIs and local cache
│   ├── database.py         # Manages SQLite database interactions and schema
│   ├── report_generator.py # Generates professional PDF security reports
│   ├── case_manager.py     # Manages security cases and analyst workflows
│   └── utils.py            # Common utility functions (e.g., timestamp, IP checks)
├── dashboard/
│   └── streamlit_app.py    # The main Streamlit web application
├── rules/
│   └── default_rules.yaml  # YAML file for detection rules
├── data/
│   └── sample_packets.csv  # Sample data for testing and demonstration
├── reports/                # Directory for generated PDF reports
├── screenshots/            # Placeholder for dashboard screenshots
├── tests/                  # Unit and integration tests
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker build instructions
├── docker-compose.yml      # Docker Compose configuration
├── README.md               # Project documentation
└── LICENSE                 # Project license
```

## Installation

### Prerequisites
*   Python 3.10+
*   Docker (for containerized deployment)

### Local Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/NetSentinel.git
    cd NetSentinel
    ```
2.  **Create a virtual environment and install dependencies:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
3.  **Initialize the database:**
    ```bash
    python -c "from app.database import create_connection, create_tables; conn = create_connection(); create_tables(conn); conn.close()"
    ```

### Docker Setup
1.  **Build and run the Docker containers:**
    ```bash
    docker-compose up --build
    ```
    The Streamlit dashboard will be accessible at `http://localhost:8501`.

## Usage

1.  **Start the Streamlit Dashboard:**
    ```bash
    streamlit run dashboard/streamlit_app.py
    ```
    (If running locally, ensure your virtual environment is activated.)

2.  **Access the Dashboard:** Open your web browser and navigate to `http://localhost:8501`.

3.  **Login:** Use the demo credentials `admin/admin` or `analyst/analyst`.

4.  **Explore Features:**
    *   **Live Packets**: Start live sniffing (requires appropriate network permissions).
    *   **PCAP Upload**: Upload `.pcap` files for analysis.
    *   **Alerts**: View detected security events.
    *   **Cases**: Manage incident response workflows.
    *   **IOC Enrichment**: Look up threat intelligence for IPs/domains.
    *   **Reports**: Generate PDF security reports.

## Important Security Rules & Disclaimer

**THIS PROJECT IS FOR DEFENSIVE AND EDUCATIONAL USE ONLY.**

*   **Do not** include credential stealing functionality.
*   **Do not** decrypt HTTPS traffic.
*   **Do not** capture passwords or private messages.
*   **Do not** perform Man-in-the-Middle (MITM) attacks.
*   **Only analyze packet headers and metadata.**
*   **Warning**: This tool must only be used on networks owned by the user or where explicit permission exists. Unauthorized network monitoring is illegal and unethical.

