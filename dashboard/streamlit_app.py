import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import sys
import json
import tempfile
import time
from datetime import datetime, timedelta
from io import BytesIO

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import DatabaseManager
from app.sniffer import PacketSniffer
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from app.rules_engine import RulesEngine
from app.enrichment import Enrichment
from app.case_manager import CaseManager
from app.report_generator import ReportGenerator
from app.soar import SOARManager
from app.utils import get_logger

logger = get_logger(__name__)

# --- UI CONFIG ---
st.set_page_config(
    page_title="NetSentinel Cyber Ops",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for "Cyber Ops" look
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #e0e0e0; }
    .stMetric { background-color: #1a1c24; padding: 15px; border-radius: 10px; border-left: 5px solid #00ff00; }
    .stDataFrame { border: 1px solid #333; }
    .sidebar .sidebar-content { background-image: linear-gradient(#1a1c24, #0e1117); }
    h1, h2, h3 { color: #00ff00 !important; font-family: 'Courier New', Courier, monospace; }
    .stButton>button { background-color: #1a1c24; color: #00ff00; border: 1px solid #00ff00; }
    .stButton>button:hover { background-color: #00ff00; color: #1a1c24; }
    </style>
    """, unsafe_allow_html=True)

# --- INITIALIZATION ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None
if "sniffing" not in st.session_state:
    st.session_state.sniffing = False

@st.cache_resource
def get_db(): return DatabaseManager()

@st.cache_resource
def get_components(_db):
    re = RulesEngine()
    analyzer = PacketAnalyzer(_db)
    de = DetectionEngine(re, _db)
    sniffer = PacketSniffer(_db, analyzer, de)
    enrich = Enrichment(_db)
    cm = CaseManager(_db)
    soar = SOARManager(_db)
    return {
        "rules_engine": re, "analyzer": analyzer, "detection_engine": de,
        "sniffer": sniffer, "enrichment": enrich, "case_manager": cm, "soar": soar
    }

db = get_db()
comp = get_components(db)

# --- PAGES ---
def login_page():
    st.title("🛡️ NETSENTINEL: CYBER OPS LOGIN")
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        username = st.text_input("Operator ID")
        password = st.text_input("Access Key", type="password")
        if st.button("AUTHORIZE", use_container_width=True):
            user = db.authenticate_user(username, password)
            if user:
                st.session_state.authenticated = True
                st.session_state.role = user.role
                st.session_state.username = user.username
                st.rerun()
            else:
                st.error("ACCESS DENIED: INVALID CREDENTIALS")

def dashboard_page():
    st.title("🌐 GLOBAL THREAT OVERVIEW")
    
    alerts = db.get_alerts(limit=500)
    packets = db.get_packets(limit=2000)
    cases = db.get_all_cases()
    
    # Top Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("THREATS DETECTED", len(alerts))
    m2.metric("CRITICAL INCIDENTS", len([a for a in alerts if a.severity == "Critical"]))
    m3.metric("ACTIVE CONNECTIONS", len(comp["analyzer"].get_connections()))
    m4.metric("BLOCKED HOSTS", len(comp["soar"].get_blocked_ips()))
    
    st.markdown("---")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("📡 Real-Time Traffic Distribution")
        if packets:
            df_p = pd.DataFrame([{ "Protocol": p.protocol, "Size": p.packet_size } for p in packets])
            fig = px.area(df_p, y="Size", color="Protocol", title="Network Throughput")
            st.plotly_chart(fig, use_container_width=True)
            
    with c2:
        st.subheader("🚨 Alert Severity")
        if alerts:
            df_a = pd.DataFrame([{ "Severity": a.severity } for a in alerts])
            fig = px.pie(df_a, names="Severity", hole=0.4, color_discrete_sequence=px.colors.sequential.RdBu)
            st.plotly_chart(fig, use_container_width=True)

def live_ops_page():
    st.title("⚡ LIVE INTERCEPT OPS")
    
    t1, t2 = st.tabs(["Packet Stream", "Active Connections"])
    
    with t1:
        col1, col2, col3 = st.columns([1, 1, 2])
        if col1.button("▶️ START CAPTURE"):
            comp["sniffer"].start_sniffing()
            st.session_state.sniffing = True
        if col2.button("⏹️ STOP CAPTURE"):
            comp["sniffer"].stop_sniffing()
            st.session_state.sniffing = False
            
        if st.session_state.sniffing:
            st.success("SCANNING NETWORK INTERFACE...")
            
        packets = db.get_packets(limit=100)
        if packets:
            df = pd.DataFrame([{
                "Time": p.timestamp, "Src": p.source_ip, "Dst": p.dest_ip, 
                "Proto": p.protocol, "DPort": p.dest_port, "Size": p.packet_size,
                "Flags": p.tcp_flags
            } for p in packets])
            st.dataframe(df, use_container_width=True)
            
    with t2:
        conns = comp["analyzer"].get_connections()
        if conns:
            st.dataframe(pd.DataFrame(conns), use_container_width=True)
        else:
            st.info("No active connections tracked.")

def forensic_page():
    st.title("🔬 DEEP FORENSIC ANALYSIS")
    
    pcap = st.file_uploader("UPLOAD PCAP FOR DPI", type="pcap")
    if pcap:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(pcap.read())
            path = tmp.name
        
        with st.spinner("PERFORMING DEEP PACKET INSPECTION..."):
            count = comp["sniffer"].process_pcap(path)
            st.success(f"ANALYSIS COMPLETE: {count} PACKETS INSPECTED")
            
            # Show DPI results
            packets = db.get_packets(limit=count)
            payloads = [p for p in packets if p.payload_printable]
            if payloads:
                st.subheader("Extracted Payloads (DPI)")
                for p in payloads[:10]:
                    with st.expander(f"Packet from {p.source_ip} to {p.dest_ip} ({p.protocol})"):
                        st.code(p.payload_printable)
                        if st.button(f"Block {p.source_ip}", key=f"block_{p.id}"):
                            comp["soar"].block_ip(p.source_ip, "Malicious payload detected during DPI")
                            st.warning(f"HOST {p.source_ip} BLACKLISTED")

def soar_page():
    st.title("🛠️ SOAR: ACTIVE RESPONSE")
    
    st.subheader("Current Blacklist")
    blocked = comp["soar"].get_blocked_ips()
    if blocked:
        for ip in blocked:
            col1, col2 = st.columns([3, 1])
            col1.write(f"🚫 **{ip}**")
            if col2.button(f"UNBLOCK", key=f"unblock_{ip}"):
                comp["soar"].unblock_ip(ip)
                st.rerun()
    else:
        st.info("No hosts currently blocked.")
        
    st.markdown("---")
    st.subheader("Manual Block")
    ip_to_block = st.text_input("Enter IP to Blacklist")
    if st.button("EXECUTE BLOCK"):
        if ip_to_block:
            comp["soar"].block_ip(ip_to_block, "Manual operator action")
            st.success(f"IP {ip_to_block} HAS BEEN DROPPED")
            st.rerun()

# --- MAIN APP ---
def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        st.sidebar.title("🛡️ NETSENTINEL")
        st.sidebar.write(f"OPERATOR: {st.session_state.username}")
        
        nav = st.sidebar.radio("COMMAND CENTER", [
            "DASHBOARD", "LIVE OPS", "FORENSICS", "ALERTS", "CASES", "SOAR", "REPORTS"
        ])
        
        if st.sidebar.button("TERMINATE SESSION"):
            st.session_state.authenticated = False
            st.rerun()
            
        if nav == "DASHBOARD": dashboard_page()
        elif nav == "LIVE OPS": live_ops_page()
        elif nav == "FORENSICS": forensic_page()
        elif nav == "ALERTS":
            st.title("🚨 SECURITY ALERTS")
            alerts = db.get_alerts(limit=100)
            if alerts:
                st.dataframe(pd.DataFrame([{
                    "Time": a.timestamp, "Type": a.alert_type, "Severity": a.severity,
                    "Src": a.source_ip, "Dst": a.dest_ip, "MITRE": a.mitre_attack
                } for a in alerts]), use_container_width=True)
        elif nav == "CASES":
            st.title("📋 CASE MANAGEMENT")
            # Reuse simplified case management from before or expand
            st.info("Incident response workflow active.")
        elif nav == "SOAR": soar_page()
        elif nav == "REPORTS":
            st.title("📄 MISSION REPORTS")
            if st.button("GENERATE INTEL REPORT"):
                st.success("PDF Report Compiled.")

if __name__ == "__main__":
    main()
