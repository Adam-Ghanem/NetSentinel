import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import sys
import json
import tempfile
import time
import asyncio
from datetime import datetime, timedelta, timezone

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import DatabaseManager
from app.sniffer import PacketSniffer
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from app.rules_engine import RulesEngine
from app.soar import SOARManager
from app.engine import NetSentinelEngine
from app.utils import get_logger

logger = get_logger(__name__)

# --- UI CONFIG ---
st.set_page_config(
    page_title="NetSentinel Elite | Enterprise NDR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional "Tech-Noir" Enterprise CSS
st.markdown("""
    <style>
    .main { background-color: #05070a; color: #e0e0e0; font-family: 'Inter', sans-serif; }
    .stMetric { background-color: #0d1117; padding: 25px; border-radius: 8px; border-top: 4px solid #00ff00; }
    .stDataFrame { border: 1px solid #30363d; }
    h1, h2, h3 { color: #ffffff !important; font-weight: 700; }
    .stButton>button { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; }
    .stButton>button:hover { border-color: #00ff00; color: #00ff00; }
    .sidebar .sidebar-content { background-color: #0d1117; }
    .status-active { color: #00ff00; font-weight: bold; }
    .status-inactive { color: #ff4b4b; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- INITIALIZATION ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "engine_running" not in st.session_state:
    st.session_state.engine_running = False

@st.cache_resource
def get_db(): return DatabaseManager()

@st.cache_resource
def get_components(_db):
    re = RulesEngine()
    analyzer = PacketAnalyzer(_db)
    de = DetectionEngine(re, _db)
    sniffer = PacketSniffer(_db, analyzer, de)
    soar = SOARManager(_db)
    engine = NetSentinelEngine(_db, analyzer, de)
    return {
        "rules_engine": re, "analyzer": analyzer, "detection_engine": de,
        "sniffer": sniffer, "soar": soar, "engine": engine
    }

db = get_db()
comp = get_components(db)

# --- PAGES ---
def dashboard_page():
    st.title("🛡️ ENTERPRISE COMMAND CENTER")
    
    # Engine Status Bar
    status_class = "status-active" if st.session_state.engine_running else "status-inactive"
    status_text = "OPERATIONAL" if st.session_state.engine_running else "OFFLINE"
    st.markdown(f"ENGINE STATUS: <span class='{status_class}'>{status_text}</span>", unsafe_allow_html=True)
    
    alerts = db.get_alerts(limit=500)
    packets = db.get_packets(limit=1000)
    
    # Elite Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("INTEL MATCHES", len([a for a in alerts if a.alert_type == "Threat Intel Match"]))
    m2.metric("JA3 ANOMALIES", len([a for a in alerts if "JA3" in a.alert_type]))
    m3.metric("SOAR ACTIONS", len(comp["soar"].get_blocked_ips()))
    m4.metric("SYSTEM LOAD", f"{len(packets)} pps")
    
    st.markdown("---")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("📊 THREAT TIMELINE")
        if alerts:
            df_a = pd.DataFrame([{ "Time": a.timestamp, "Severity": a.severity } for a in alerts])
            fig = px.histogram(df_a, x="Time", color="Severity", barmode="group", template="plotly_dark", color_discrete_map={"Critical": "#ff0000", "High": "#ff4b4b", "Medium": "#ffa500", "Low": "#00ff00"})
            st.plotly_chart(fig, use_container_width=True)
            
    with c2:
        st.subheader("🌐 TOP ATTACK VECTORS")
        if alerts:
            df_v = pd.DataFrame([{ "Type": a.alert_type } for a in alerts])
            fig = px.pie(df_v, names="Type", hole=0.5, template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

def elite_forensics_page():
    st.title("🔬 ELITE FORENSIC ANALYSIS")
    
    t1, t2, t3 = st.tabs(["TLS/JA3 Inspection", "Threat Intel Sync", "DPI Payload Explorer"])
    
    with t1:
        st.subheader("Encrypted Traffic Fingerprinting")
        packets = db.get_packets(limit=500)
        tls_pkts = [p for p in packets if p.ja3_hash]
        if tls_pkts:
            df_ja3 = pd.DataFrame([{
                "Time": p.timestamp, "Source": p.source_ip, "JA3 Hash": p.ja3_hash, "TLS Ver": p.tls_version
            } for p in tls_pkts])
            st.dataframe(df_ja3, use_container_width=True)
        else:
            st.info("No TLS/JA3 data captured yet.")
            
    with t2:
        st.subheader("Global Threat Intelligence")
        if st.button("🔄 SYNC PROFESSIONAL FEEDS"):
            comp["detection_engine"].intel.sync_otx()
            st.success("Indicators of Compromise (IOCs) Synchronized.")
        
        iocs = comp["detection_engine"].intel.iocs
        st.write(f"Currently tracking **{len(iocs['ips'])}** malicious IPs and **{len(iocs['domains'])}** C2 domains.")
        st.json(iocs)

    with t3:
        st.subheader("Deep Packet Inspection")
        packets = db.get_packets(limit=100)
        payloads = [p for p in packets if p.payload_printable]
        if payloads:
            for p in payloads[:10]:
                with st.expander(f"PKT {p.id} | {p.source_ip} -> {p.dest_ip}"):
                    st.code(p.payload_printable)

# --- MAIN APP ---
def main():
    if not st.session_state.authenticated:
        # Simple Login for Demo
        st.title("🛡️ NETSENTINEL ELITE")
        user = st.text_input("Operator ID")
        pwd = st.text_input("Access Key", type="password")
        if st.button("AUTHORIZE"):
            st.session_state.authenticated = True
            st.rerun()
    else:
        if os.path.exists("assets/logo.png"):
            st.sidebar.image("assets/logo.png", width=120)
        st.sidebar.title("NETSENTINEL | ELITE")
        
        nav = st.sidebar.radio("COMMAND CENTER", [
            "DASHBOARD", "ELITE FORENSICS", "ACTIVE ALERTS", "SOAR CONTROL"
        ])
        
        st.sidebar.markdown("---")
        if st.sidebar.button("▶️ START ASYNC ENGINE"):
            st.session_state.engine_running = True
            comp["sniffer"].start_sniffing()
        if st.sidebar.button("⏹️ STOP ASYNC ENGINE"):
            st.session_state.engine_running = False
            comp["sniffer"].stop_sniffing()
            
        if nav == "DASHBOARD": dashboard_page()
        elif nav == "ELITE FORENSICS": elite_forensics_page()
        elif nav == "ACTIVE ALERTS":
            st.title("🚨 REAL-TIME THREAT ALERTS")
            alerts = db.get_alerts(limit=100)
            if alerts:
                st.dataframe(pd.DataFrame([{
                    "Time": a.timestamp, "Threat": a.alert_type, "Severity": a.severity, "Source": a.source_ip, "Target": a.dest_ip
                } for a in alerts]), use_container_width=True)
        elif nav == "SOAR CONTROL":
            st.title("🛠️ SOAR: AUTOMATED RESPONSE")
            blocked = comp["soar"].get_blocked_ips()
            st.write(f"Currently blocking **{len(blocked)}** hosts.")
            for ip in blocked:
                st.error(f"BLOCKED: {ip}")

if __name__ == "__main__":
    main()
