# NetSentinel Upgraded Architecture and Improvement Plan

## 1. Introduction
This document outlines the proposed architectural upgrades and a detailed improvement plan for the NetSentinel project. The goal is to transform NetSentinel from a proof-of-concept into a professional, production-ready cybersecurity tool suitable for various use cases, including portfolio showcasing, LinkedIn demonstration, and academic presentations.

## 2. Current State Summary
As identified in the codebase audit, NetSentinel currently features a modular structure but suffers from significant gaps in its persistence layer, detection engine, and dashboard integration. Key issues include unimplemented database CRUD operations, a simplistic rule evaluation mechanism, and a largely mocked Streamlit dashboard.

## 3. Upgraded Architecture Design

### 3.1. Core Components Overview
The upgraded NetSentinel will maintain its modular design but with enhanced capabilities and robust inter-component communication. The main components will be:

*   **Packet Capture Module (`sniffer.py`)**: Responsible for live packet sniffing and PCAP file processing.
*   **Packet Processing Module (`parser.py`, `analyzer.py`)**: Extracts metadata, tracks connections, and performs initial traffic analysis.
*   **Detection Engine (`rules_engine.py`, `detection_engine.py`)**: Evaluates packets and connection states against dynamic rules to generate alerts.
*   **Persistence Layer (`database.py`)**: Manages all data storage and retrieval using SQLAlchemy for robust ORM capabilities.
*   **Enrichment Module (`enrichment.py`)**: Integrates with threat intelligence sources and caches results.
*   **Case Management Module (`case_manager.py`)**: Provides full CRUD operations for security cases.
*   **Reporting Module (`report_generator.py`)**: Generates professional PDF reports.
*   **Dashboard (`streamlit_app.py`)**: An interactive web interface for real-time monitoring, alert management, and data visualization.
*   **Configuration Management**: Centralized handling of application settings and secrets.
*   **Logging**: Comprehensive logging across all modules.

### 3.2. Detailed Component Enhancements

#### 3.2.1. Persistence Layer (Database)
*   **Technology**: Migrate from raw `sqlite3` to **SQLAlchemy ORM** for better abstraction, maintainability, and scalability. This will allow for easier integration with different database backends in the future (e.g., PostgreSQL).
*   **`DatabaseManager` Class**: Implement a dedicated `DatabaseManager` class with methods for inserting, querying, updating, and deleting records for packets, connections, alerts, cases, IOC cache, and users.
*   **Connection Tracking Persistence**: Ensure that connection states tracked by `analyzer.py` are regularly persisted to the database, allowing for stateful detection and historical analysis across restarts.

#### 3.2.2. Detection Engine
*   **Advanced Rule Evaluation**: Enhance `rules_engine.py` to fully support all fields defined in `default_rules.yaml`. This includes implementing logic for:
    *   **Time-windowed detections**: For port scans, high traffic volume, and beaconing.
    *   **Stateful analysis**: Leveraging persisted connection data for more accurate detections (e.g., SYN/ACK ratios, repeated connections).
    *   **Pattern matching**: For DNS queries and other payload-based detections.
*   **Rule Validation**: Implement validation for YAML rules to prevent malformed rules from crashing the engine.
*   **Alert Enrichment**: Automatically enrich alerts with relevant context (e.g., geo-IP data, asset information) before saving to the database.

#### 3.2.3. Dashboard (Streamlit)
*   **Full Integration**: Connect all dashboard components to the new `DatabaseManager` to display real-time and historical data.
*   **Live Packet Display**: Implement actual live packet streaming to the dashboard, not just simulated output.
*   **PCAP Upload & Analysis**: Fully implement PCAP file upload, processing, and display of results.
*   **Case Management**: Develop a fully functional case management interface with the ability to create, update, assign, and close cases, add analyst notes, and link to specific alerts.
*   **User Authentication & Authorization**: Implement proper password hashing (e.g., using `bcrypt`) and secure session management. Enforce role-based access control (RBAC) for Admin and Analyst roles.
*   **Interactive Visualizations**: Leverage Plotly or other interactive libraries for dynamic charts and graphs based on live and historical data.

#### 3.2.4. DevSecOps & Operational Excellence
*   **Unit and Integration Tests**: Implement comprehensive test suites for all core modules (packet processing, detection, database, enrichment).
*   **Docker Enhancements**: 
    *   **Multi-stage Builds**: Optimize Dockerfile for smaller image sizes and faster builds.
    *   **Non-root User**: Run the application as a non-root user inside the container for improved security.
    *   **Environment Variables**: Centralize configuration using environment variables and potentially `python-dotenv` for local development.
*   **CI/CD Pipeline**: Implement a GitHub Actions workflow for automated testing, linting, and Docker image building on every push to the repository.
*   **Logging**: Integrate Python's `logging` module for structured logging across the application, with configurable log levels and output destinations.
*   **Dependency Management**: Pin exact versions in `requirements.txt` and consider using `pip-tools` for better dependency management.

#### 3.2.5. Security Best Practices
*   **Credential Management**: Remove hardcoded credentials. Use environment variables or a secure configuration management system.
*   **Input Validation**: Implement robust input validation for all user-provided data (e.g., PCAP uploads, rule definitions, user inputs in the dashboard).
*   **Least Privilege**: Ensure the application runs with the minimum necessary permissions, especially during packet capture.

## 4. Implementation Plan

### Phase 1: Database Refactoring (Estimated: 3-5 days)
1.  **Install SQLAlchemy**: Add `sqlalchemy` and `alembic` (for migrations) to `requirements.txt`.
2.  **Define SQLAlchemy Models**: Create Python classes for `Packet`, `Connection`, `Alert`, `Case`, `IOCEntry`, and `User` that map to database tables.
3.  **Implement `DatabaseManager`**: Develop a `DatabaseManager` class that encapsulates all database interactions using SQLAlchemy sessions. This class will provide methods like `add_packet`, `get_alerts`, `update_case`, etc.
4.  **Integrate with Core Modules**: Update `detection_engine.py`, `enrichment.py`, `case_manager.py`, and `analyzer.py` to use the new `DatabaseManager`.
5.  **User Authentication**: Implement password hashing (e.g., `bcrypt`) for user passwords and integrate with the `DatabaseManager`.

### Phase 2: Detection Engine Enhancement (Estimated: 5-7 days)
1.  **Refactor `RulesEngine`**: Modify `_check_rule` in `rules_engine.py` to parse and evaluate all rule fields from `default_rules.yaml`.
2.  **Implement Stateful Detections**: Develop logic for time-windowed analysis, leveraging the persisted connection data from the database.
3.  **Rule Validation**: Add schema validation for YAML rules to ensure correctness.
4.  **Alert Enrichment Integration**: Integrate external threat intelligence lookups (AbuseIPDB, VirusTotal) directly into the alert generation process within `detection_engine.py`.
5.  **Unit Tests for Rules**: Write comprehensive unit tests for the `RulesEngine` and `DetectionEngine`.

### Phase 3: Dashboard Full Integration (Estimated: 7-10 days)
1.  **Connect to `DatabaseManager`**: Update `streamlit_app.py` to use the new `DatabaseManager` for all data access.
2.  **Implement Live Packet Stream**: Develop a mechanism to push live packet data from the sniffer to the Streamlit dashboard (e.g., using websockets or periodic polling).
3.  **PCAP Upload Functionality**: Implement file upload and processing logic for PCAP files, storing results in the database.
4.  **Case Management UI**: Build out the full UI for creating, viewing, editing, and managing cases.
5.  **Secure Login & RBAC**: Implement the secure login flow with hashed passwords and enforce role-based access for dashboard features.
6.  **Interactive Visualizations**: Replace static charts with interactive Plotly graphs for better data exploration.

### Phase 4: DevSecOps & Operationalization (Estimated: 4-6 days)
1.  **Comprehensive Testing**: Write unit and integration tests for all remaining modules.
2.  **Docker Optimization**: Implement multi-stage Dockerfile and run as a non-root user.
3.  **CI/CD Pipeline**: Set up GitHub Actions for automated testing, linting, and Docker image builds.
4.  **Logging System**: Integrate Python's `logging` module with configurable handlers.
5.  **Configuration Management**: Implement `python-dotenv` for local development and ensure environment variables are used for sensitive configurations.

### Phase 5: Documentation & Showcase (Estimated: 2-3 days)
1.  **Update README.md**: Revise the `README.md` to reflect the new features, architecture, installation, and usage instructions.
2.  **Architecture Document**: Finalize this architecture and improvement plan document.
3.  **Showcase Guide**: Create a guide for demonstrating NetSentinel for portfolio, LinkedIn, and presentations.
4.  **Screenshots**: Generate updated screenshots of the fully functional dashboard.

## 5. Conclusion
This plan provides a roadmap to elevate NetSentinel to a professional standard. By focusing on robust data persistence, advanced detection capabilities, a fully integrated dashboard, and strong DevSecOps practices, NetSentinel will become a powerful and demonstrable cybersecurity project.
