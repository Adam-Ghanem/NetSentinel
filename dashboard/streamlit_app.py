import streamlit as st
import pandas as pd
import plotly.express as px
import os
import sys
import time
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import DatabaseManager
from app.sniffer import PacketSniffer
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from app.rules_engine import RulesEngine
from app.soar import SOARManager

# --- UI CONFIG ---
st.set_page_config(page_title="NetSentinel Ultra | Security Platform", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .stMetric { background-color: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; }
    h1, h2, h3 { color: #58a6ff !important; }
    .stButton>button { background-color: #238636; color: white; border: none; width: 100%; }
    .stButton>button:hover { background-color: #2ea043; }
    </style>
    """, unsafe_allow_html=True)

@st.cache_resource
def get_db(): return DatabaseManager()

@st.cache_resource
def get_comp(_db):
    re = RulesEngine()
    analyzer = PacketAnalyzer(_db)
    de = DetectionEngine(re, _db)
    sniffer = PacketSniffer(_db, analyzer, de)
    soar = SOARManager(_db)
    return {"re": re, "analyzer": analyzer, "de": de, "sniffer": sniffer, "soar": soar}

db = get_db()
comp = get_comp(db)

# --- PAGES ---
def overview_page():
    st.title("🌐 PLATFORM OVERVIEW")
    
    m1, m2, m3, m4 = st.columns(4)
    alerts = db.get_alerts(limit=1000)
    m1.metric("ML ANOMALIES", len([a for a in alerts if "ML" in a.description]))
    m2.metric("THREAT INTEL", len([a for a in alerts if "Intel" in a.alert_type]))
    m3.metric("FILES CARVED", len(os.listdir("extracted_files")) if os.path.exists("extracted_files") else 0)
    m4.metric("API STATUS", "ACTIVE (PORT 8000)")
    
    st.markdown("---")
    
    # Network Graph
    st.subheader("🕸️ REAL-TIME NETWORK TOPOLOGY")
    conns = comp["analyzer"].get_connections()
    if conns:
        G = nx.Graph()
        for c in conns[:50]: # Limit for performance
            G.add_edge(c["source_ip"], c["dest_ip"], weight=c["packets"])
        
        net = Network(height="400px", width="100%", bgcolor="#0d1117", font_color="white")
        net.from_nx(G)
        path = "network_graph.html"
        net.save_graph(path)
        with open(path, 'r', encoding='utf-8') as f:
            components.html(f.read(), height=450)
    else:
        st.info("No network data to visualize yet.")

def forensics_page():
    st.title("🔬 ULTRA FORENSICS")
    t1, t2 = st.tabs(["ML Anomaly Detection", "File Carving Explorer"])
    
    with t1:
        st.subheader("Isolation Forest Anomaly Scores")
        stats = comp["analyzer"].get_all_traffic_stats()
        if stats:
            df_ml = pd.DataFrame([{
                "Host": ip, "Threat Score": s["threat_score"], "Packets": s["total_packets"]
            } for ip, s in stats.items()])
            st.bar_chart(df_ml.set_index("Host")["Threat Score"])
            
    with t2:
        st.subheader("Extracted Files from HTTP Traffic")
        if os.path.exists("extracted_files"):
            files = os.listdir("extracted_files")
            if files:
                for f in files:
                    st.write(f"📄 `{f}`")
                    with open(f"extracted_files/{f}", "rb") as file:
                        st.download_button(f"Download {f}", file, file_name=f)
            else:
                st.info("No files carved yet.")

def main():
    st.sidebar.title("🛡️ NETSENTINEL ULTRA")
    nav = st.sidebar.radio("PLATFORM NAVIGATION", ["OVERVIEW", "FORENSICS", "ALERTS", "API DOCS"])
    
    if st.sidebar.button("START ULTRA ENGINE"):
        comp["sniffer"].start_sniffing()
        st.sidebar.success("Engine Running.")
        
    if nav == "OVERVIEW": overview_page()
    elif nav == "FORENSICS": forensics_page()
    elif nav == "ALERTS":
        st.title("🚨 SECURITY EVENTS")
        alerts = db.get_alerts(limit=100)
        st.dataframe(pd.DataFrame([{
            "Time": a.timestamp, "Type": a.alert_type, "Severity": a.severity, "Source": a.source_ip
        } for a in alerts]), use_container_width=True)
    elif nav == "API DOCS":
        st.title("🔌 EXTERNAL INTEGRATION API")
        st.markdown("""
        ### REST API Endpoints (FastAPI)
        - `GET /alerts`: Retrieve all security alerts.
        - `GET /stats`: System health and performance telemetry.
        - `POST /soar/block/{ip}`: Programmatically block an IP.
        
        **Base URL:** `http://localhost:8000`
        """)

if __name__ == "__main__":
    main()
