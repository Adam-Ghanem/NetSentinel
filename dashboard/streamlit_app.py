import os
import sys

import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

# Add the project root to the Python path for local execution.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analyzer import PacketAnalyzer
from app.database import DatabaseManager
from app.detection_engine import DetectionEngine
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
    .stMetric {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px;
    }
    h1, h2, h3 { color: #58a6ff !important; }
    .stButton>button {
        background-color: #238636;
        color: white;
        border: none;
        width: 100%;
    }
    .stButton>button:hover { background-color: #2ea043; }
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


db = get_db()
app_components = get_components(db)


def overview_page():
    st.title("Platform Overview")

    alerts = db.get_alerts(limit=1000)
    packets = db.get_packets(limit=1000)
    connections = app_components["analyzer"].get_connections()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Stored Packets", len(packets))
    col2.metric("Alerts", len(alerts))
    col3.metric("Active Connections", len(connections))
    col4.metric("Data Source", "Local Lab")

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
            net = Network(height="400px", width="100%", bgcolor="#0d1117", font_color="white")
            net.from_nx(graph)
            graph_path = "network_graph.html"
            net.save_graph(graph_path)
            with open(graph_path, "r", encoding="utf-8") as graph_file:
                components.html(graph_file.read(), height=450)
        else:
            st.info("No connection relationships are available yet.")
    else:
        st.info("No connection data is available yet.")


def analysis_page():
    st.title("Analysis Workspace")

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
        st.info("No traffic statistics are available yet.")

    st.subheader("PCAP Analysis")
    st.info(
        "The PCAP workflow is part of the project roadmap. The current dashboard focuses on stored metadata and alert review."
    )


def alerts_page():
    st.title("Security Alerts")

    alerts = db.get_alerts(limit=100)

    if not alerts:
        st.info("No alerts are stored yet.")
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

    st.dataframe(pd.DataFrame(alert_rows), use_container_width=True)


def main():
    st.sidebar.title("NetSentinel")
    st.sidebar.caption("Educational network metadata monitoring prototype")

    page = st.sidebar.radio("Navigation", ["Overview", "Analysis", "Alerts"])

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
