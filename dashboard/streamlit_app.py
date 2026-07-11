import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network
from scapy.all import rdpcap

# Add the project root to the Python path for local execution.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analyzer import PacketAnalyzer
from app.database import DatabaseManager
from app.detection_engine import DetectionEngine
from app.parser import parse_packet
from app.rules_engine import RulesEngine
from app.sniffer import PacketSniffer


st.set_page_config(
    page_title="NetSentinel | Network Metadata Prototype",
    page_icon="NS",
    layout="wide",
)

st.markdown(
    """
    <style>
    .main {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .block-container {
        padding-top: 3rem;
        padding-bottom: 3rem;
    }
    h1, h2, h3 {
        color: #58a6ff !important;
        letter-spacing: 0.5px;
    }
    .stButton>button {
        background-color: #238636;
        color: white;
        border: none;
        width: 100%;
        border-radius: 8px;
        padding: 0.6rem 1rem;
    }
    .stButton>button:hover {
        background-color: #2ea043;
        color: white;
    }
    .hero {
        border: 1px solid #30363d;
        background: linear-gradient(135deg, #111827 0%, #0d1117 65%);
        border-radius: 18px;
        padding: 2rem;
        margin-bottom: 1.5rem;
    }
    .hero-title {
        font-size: 2.4rem;
        font-weight: 800;
        color: #58a6ff;
        margin-bottom: 0.3rem;
    }
    .hero-subtitle {
        color: #8b949e;
        font-size: 1rem;
        max-width: 760px;
    }
    .metric-card {
        border: 1px solid #30363d;
        background: #161b22;
        border-radius: 14px;
        padding: 1.2rem;
        min-height: 118px;
    }
    .metric-label {
        color: #8b949e;
        font-size: 0.85rem;
        margin-bottom: 0.5rem;
    }
    .metric-value {
        color: #f0f6fc;
        font-size: 2rem;
        font-weight: 800;
    }
    .metric-help {
        color: #6e7681;
        font-size: 0.8rem;
        margin-top: 0.4rem;
    }
    .empty-state {
        border: 1px dashed #30363d;
        background: rgba(22, 27, 34, 0.65);
        border-radius: 16px;
        padding: 1.5rem;
        margin-top: 1rem;
    }
    .empty-state h3 {
        margin-top: 0;
    }
    .step-list li {
        margin-bottom: 0.45rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_db():
    return DatabaseManager()


@st.cache_resource
def get_components(_db):
    rules_engine = RulesEngine()

    try:
        analyzer = PacketAnalyzer(_db)
    except TypeError:
        analyzer = PacketAnalyzer()

    detection_engine = DetectionEngine(rules_engine, _db)

    try:
        sniffer = PacketSniffer(_db, analyzer, detection_engine)
    except TypeError:
        sniffer = PacketSniffer(_db, detection_engine)

    return {
        "rules_engine": rules_engine,
        "analyzer": analyzer,
        "detection_engine": detection_engine,
        "sniffer": sniffer,
    }


def metric_card(label, value, help_text=""):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-help">{help_text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def safe_get_connections(analyzer):
    try:
        return analyzer.get_connections()
    except Exception:
        return []


def show_branding():
    logo_path = "assets/logo.svg"
    if os.path.exists(logo_path):
        st.sidebar.image(logo_path, width=140)
    st.sidebar.title("NetSentinel")
    st.sidebar.caption("Educational network metadata monitoring prototype")


def seed_demo_data(_db):
    now = datetime.now(timezone.utc)
    demo_packets = [
        {
            "timestamp": now - timedelta(minutes=8),
            "source_mac": "00:11:22:33:44:55",
            "dest_mac": "66:77:88:99:aa:bb",
            "source_ip": "192.168.1.10",
            "dest_ip": "8.8.8.8",
            "protocol": "UDP",
            "source_port": 53530,
            "dest_port": 53,
            "packet_size": 84,
            "dns_query": "example.com",
        },
        {
            "timestamp": now - timedelta(minutes=7),
            "source_mac": "00:11:22:33:44:55",
            "dest_mac": "66:77:88:99:aa:bb",
            "source_ip": "192.168.1.10",
            "dest_ip": "93.184.216.34",
            "protocol": "TCP",
            "source_port": 52014,
            "dest_port": 80,
            "packet_size": 512,
            "tcp_flags": "PA",
            "http_host": "example.com",
            "http_path": "/",
        },
        {
            "timestamp": now - timedelta(minutes=6),
            "source_mac": "00:aa:bb:cc:dd:ee",
            "dest_mac": "66:77:88:99:aa:bb",
            "source_ip": "192.168.1.25",
            "dest_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 40120,
            "dest_port": 22,
            "packet_size": 128,
            "tcp_flags": "S",
        },
        {
            "timestamp": now - timedelta(minutes=5),
            "source_mac": "00:aa:bb:cc:dd:ee",
            "dest_mac": "66:77:88:99:aa:bb",
            "source_ip": "192.168.1.25",
            "dest_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 40121,
            "dest_port": 80,
            "packet_size": 128,
            "tcp_flags": "S",
        },
        {
            "timestamp": now - timedelta(minutes=4),
            "source_mac": "00:aa:bb:cc:dd:ee",
            "dest_mac": "66:77:88:99:aa:bb",
            "source_ip": "192.168.1.25",
            "dest_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 40122,
            "dest_port": 443,
            "packet_size": 128,
            "tcp_flags": "S",
        },
        {
            "timestamp": now - timedelta(minutes=2),
            "source_mac": "00:44:55:66:77:88",
            "dest_mac": "66:77:88:99:aa:bb",
            "source_ip": "192.168.1.40",
            "dest_ip": "1.1.1.1",
            "protocol": "UDP",
            "source_port": 53531,
            "dest_port": 53,
            "packet_size": 92,
            "dns_query": "cloudflare-dns.com",
        },
    ]

    for packet in demo_packets:
        _db.add_packet(packet)

    demo_alerts = [
        {
            "alert_id": f"demo-{uuid.uuid4()}",
            "timestamp": now - timedelta(minutes=5),
            "source_ip": "192.168.1.25",
            "dest_ip": "192.168.1.1",
            "alert_type": "Multiple connection attempts",
            "severity": "Medium",
            "description": "Demo alert showing repeated connection attempts to common service ports.",
            "recommended_action": "Review the source host and confirm whether the scan is expected lab activity.",
            "mitre_attack": "T1046",
        },
        {
            "alert_id": f"demo-{uuid.uuid4()}",
            "timestamp": now - timedelta(minutes=2),
            "source_ip": "192.168.1.40",
            "dest_ip": "1.1.1.1",
            "alert_type": "External DNS activity",
            "severity": "Low",
            "description": "Demo alert for external DNS lookup activity.",
            "recommended_action": "Validate DNS activity against the expected lab baseline.",
            "mitre_attack": "T1071.004",
        },
    ]

    for alert in demo_alerts:
        _db.insert_alert(alert)

    return len(demo_packets), len(demo_alerts)


def process_pcap_upload(_db, uploaded_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
        temp_file.write(uploaded_file.getbuffer())
        temp_path = temp_file.name

    packets = rdpcap(temp_path)
    stored_count = 0

    try:
        for packet in packets:
            packet_time = getattr(packet, "time", None)
            if packet_time is not None:
                timestamp = datetime.fromtimestamp(float(packet_time))
            else:
                timestamp = datetime.now(timezone.utc)

            packet_data = parse_packet(packet, timestamp)
            _db.add_packet(packet_data)
            stored_count += 1
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

    return stored_count


db = get_db()
app_components = get_components(db)


def overview_page():
    st.markdown(
        """
        <div class="hero">
            <div class="hero-title">Platform Overview</div>
            <div class="hero-subtitle">
                NetSentinel is running locally. This page shows stored packet metadata,
                generated alerts, active connection relationships, and the current lab status.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    alerts = db.get_alerts(limit=1000)
    packets = db.get_packets(limit=1000)
    connections = safe_get_connections(app_components["analyzer"])
    critical_alerts = [alert for alert in alerts if alert.severity == "Critical"]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Stored Packets", len(packets), "Saved in the local SQLite database")
    with col2:
        metric_card("Alerts", len(alerts), "Generated by detection rules")
    with col3:
        metric_card("Critical Alerts", len(critical_alerts), "Highest severity events")
    with col4:
        metric_card("Connections", len(connections), "Tracked during the current run")

    if not packets and not alerts and not connections:
        st.markdown(
            """
            <div class="empty-state">
                <h3>No traffic data yet</h3>
                <p>The dashboard is working, but the local database does not contain captured packet metadata yet.</p>
                <ul class="step-list">
                    <li>Click <strong>Load Demo Data</strong> in the sidebar to see the dashboard populated.</li>
                    <li>Use <strong>Start Local Collection</strong> only in a lab or authorized network.</li>
                    <li>Use the <strong>Analysis</strong> page to upload a PCAP file and store packet metadata.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.subheader("Network Relationship View")

    if connections:
        graph = nx.Graph()
        for connection in connections[:50]:
            source = connection.get("source_ip")
            destination = connection.get("dest_ip")
            if source and destination:
                graph.add_edge(source, destination)

        if graph.nodes:
            net = Network(height="420px", width="100%", bgcolor="#0d1117", font_color="white")
            net.from_nx(graph)
            graph_path = "network_graph.html"
            net.save_graph(graph_path)
            with open(graph_path, "r", encoding="utf-8") as graph_file:
                components.html(graph_file.read(), height=460)
        else:
            st.info("No connection relationships are available yet.")
    else:
        st.info("No connection data is available yet.")

    if packets:
        st.markdown("---")
        st.subheader("Recent Packets")
        packet_rows = [
            {
                "Time": packet.timestamp,
                "Source": packet.source_ip,
                "Destination": packet.dest_ip,
                "Protocol": packet.protocol,
                "Source Port": packet.source_port,
                "Destination Port": packet.dest_port,
                "Size": packet.packet_size,
            }
            for packet in packets[:100]
        ]
        st.dataframe(pd.DataFrame(packet_rows), use_container_width=True)


def analysis_page():
    st.title("Analysis Workspace")

    st.subheader("PCAP Upload")
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        if st.button("Analyze and Store PCAP Metadata"):
            try:
                stored_count = process_pcap_upload(db, uploaded_file)
                st.success(f"Stored metadata for {stored_count} packets.")
            except Exception as error:
                st.error(f"Unable to process PCAP: {error}")

    st.markdown("---")
    st.subheader("Traffic Statistics")

    analyzer = app_components["analyzer"]

    if hasattr(analyzer, "get_all_traffic_stats"):
        stats = analyzer.get_all_traffic_stats()
    elif hasattr(analyzer, "get_traffic_stats"):
        stats = analyzer.get_traffic_stats()
    else:
        stats = {}

    if stats:
        rows = []
        for ip_address, values in stats.items():
            rows.append(
                {
                    "Host": ip_address,
                    "Packets": values.get("total_packets", 0),
                    "Bytes": values.get("total_bytes", 0),
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("Traffic statistics are generated during live collection. Stored packet metadata is available in Overview.")


def alerts_page():
    st.title("Security Alerts")

    alerts = db.get_alerts(limit=100)

    if not alerts:
        st.info("No alerts are stored yet. Use Load Demo Data to preview this page.")
        return

    alert_rows = [
        {
            "Time": alert.timestamp,
            "Type": alert.alert_type,
            "Severity": alert.severity,
            "Source": alert.source_ip,
            "Destination": alert.dest_ip,
            "Description": alert.description,
        }
        for alert in alerts
    ]

    alert_df = pd.DataFrame(alert_rows)
    st.dataframe(alert_df, use_container_width=True)
    st.download_button(
        "Download alerts as CSV",
        alert_df.to_csv(index=False).encode("utf-8"),
        file_name="netsentinel_alerts.csv",
        mime="text/csv",
    )


def main():
    show_branding()

    page = st.sidebar.radio("Navigation", ["Overview", "Analysis", "Alerts"])

    if st.sidebar.button("Load Demo Data"):
        try:
            packet_count, alert_count = seed_demo_data(db)
            st.sidebar.success(f"Added {packet_count} packets and {alert_count} alerts.")
            st.rerun()
        except Exception as error:
            st.sidebar.error(f"Unable to load demo data: {error}")

    if st.sidebar.button("Start Local Collection"):
        try:
            app_components["sniffer"].start_sniffing()
            st.sidebar.success("Collection requested. System permissions may be required.")
        except Exception as error:
            st.sidebar.error(f"Unable to start collection: {error}")

    if page == "Overview":
        overview_page()
    elif page == "Analysis":
        analysis_page()
    elif page == "Alerts":
        alerts_page()


if __name__ == "__main__":
    main()
