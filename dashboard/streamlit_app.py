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
from PIL import Image

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
    page_title="NetSentinel | Cyber Ops Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for 1000% Professional Cyber Ops Look
st.markdown("""
    <style>
    .main { background-color: #05070a; color: #00ff00; font-family: 'Monaco', 'Courier New', monospace; }
    .stMetric { background-color: #0a0d14; padding: 20px; border-radius: 5px; border: 1px solid #00ff00; box-shadow: 0 0 10px #00ff0033; }
    .stDataFrame { border: 1px solid #00ff00; }
    h1, h2, h3 { color: #00ff00 !important; text-transform: uppercase; letter-spacing: 2px; }
    .stButton>button { background-color: #000; color: #00ff00; border: 1px solid #00ff00; border-radius: 0px; font-weight: bold; }
    .stButton>button:hover { background-color: #00ff00; color: #000; box-shadow: 0 0 15px #00ff00; }
    .sidebar .sidebar-content { background-color: #0a0d14; border-right: 1px solid #00ff00; }
    div[data-testid="stExpander"] { border: 1px solid #00ff0033; background-color: #0a0d14; }
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
    # Prominent Logo on Login
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if os.path.exists("assets/logo.png"):
            st.image("assets/logo.png", width=200)
        st.title("🛡️ NETSENTINEL")
        st.subheader("CYBER OPS COMMAND CENTER")
        st.markdown("---")
        username = st.text_input("OPERATOR ID")
        password = st.text_input("ACCESS KEY", type="password")
        if st.button("AUTHORIZE ACCESS", use_container_width=True):
            user = db.authenticate_user(username, password)
            if user:
                st.session_state.authenticated = True
                st.session_state.role = user.role
                st.session_state.username = user.username
                st.rerun()
            else:
                st.error("ACCESS DENIED: INVALID CREDENTIALS")

def dashboard_page():
    st.title("🌐 MISSION CONTROL: GLOBAL THREAT STATUS")
    
    alerts = db.get_alerts(limit=1000)
    packets = db.get_packets(limit=5000)
    
    # Real-time Telemetry Metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("ACTIVE THREATS", len(alerts))
    with m2: st.metric("CRITICAL BREACHES", len([a for a in alerts if a.severity == "Critical"]))
    with m3: st.metric("HOSTS BLACKLISTED", len(comp["soar"].get_blocked_ips()))
    with m4: st.metric("DPI THROUGHPUT", f"{len(packets)} PKTS")
    
    st.markdown("---")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("📡 TRAFFIC ANALYSIS")
        if packets:
            df_p = pd.DataFrame([{ "Protocol": p.protocol, "Size": p.packet_size, "Time": p.timestamp } for p in packets])
            fig = px.line(df_p, x="Time", y="Size", color="Protocol", title="NETWORK LOAD TELEMETRY", template="plotly_dark")
            fig.update_traces(line=dict(width=1))
            st.plotly_chart(fig, use_container_width=True)
            
    with c2:
        st.subheader("🚨 SEVERITY DISTRIBUTION")
        if alerts:
            df_a = pd.DataFrame([{ "Severity": a.severity } for a in alerts])
            fig = px.pie(df_a, names="Severity", hole=0.6, color_discrete_sequence=px.colors.sequential.Greens_r)
            fig.update_layout(showlegend=False, template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

def live_intercept_page():
    st.title("⚡ LIVE INTERCEPT: PACKET STREAM")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    if col1.button("▶️ ENGAGE SNIFFER"):
        comp["sniffer"].start_sniffing()
        st.session_state.sniffing = True
    if col2.button("⏹️ DISENGAGE SNIFFER"):
        comp["sniffer"].stop_sniffing()
        st.session_state.sniffing = False
            
    if st.session_state.sniffing:
        st.success("🔴 MONITORING NETWORK INTERFACE: PROMISCUOUS MODE ACTIVE")
            
    packets = db.get_packets(limit=100)
    if packets:
        df = pd.DataFrame([{
            "TIME": p.timestamp.strftime("%H:%M:%S.%f")[:-3], "SRC": p.source_ip, "DST": p.dest_ip, 
            "PROTO": p.protocol, "PORT": p.dest_port, "SIZE": p.packet_size,
            "FLAGS": p.tcp_flags
        } for p in packets])
        st.table(df) # Using table for more "raw" terminal feel

def forensic_dpi_page():
    st.title("🔬 DEEP PACKET INSPECTION (DPI)")
    
    pcap = st.file_uploader("LOAD EXTERNAL PCAP DATA", type="pcap")
    if pcap:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(pcap.read())
            path = tmp.name
        
        with st.spinner("DECRYPTING & INSPECTING PAYLOADS..."):
            count = comp["sniffer"].process_pcap(path)
            st.success(f"DPI COMPLETE: {count} PACKETS EXTRACTED")
            
            packets = db.get_packets(limit=count)
            payloads = [p for p in packets if p.payload_printable]
            if payloads:
                st.subheader("EXTRACTED FORENSIC PAYLOADS")
                for p in payloads[:20]:
                    with st.expander(f"PKT ID: {p.id} | {p.source_ip} -> {p.dest_ip} | {p.protocol}"):
                        st.text_area("RAW PAYLOAD", p.payload_printable, height=100)
                        if st.button(f"EXECUTE BLOCK: {p.source_ip}", key=f"block_{p.id}"):
                            comp["soar"].block_ip(p.source_ip, "MALICIOUS PAYLOAD DETECTED")
                            st.error(f"HOST {p.source_ip} HAS BEEN DROPPED")

# --- MAIN APP ---
def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        # Sidebar with Logo
        if os.path.exists("assets/logo.png"):
            st.sidebar.image("assets/logo.png", width=150)
        st.sidebar.title("🛡️ NETSENTINEL")
        st.sidebar.markdown(f"**OPERATOR:** `{st.session_state.username}`")
        st.sidebar.markdown(f"**ROLE:** `{st.session_state.role}`")
        st.sidebar.markdown("---")
        
        nav = st.sidebar.radio("COMMAND HIERARCHY", [
            "DASHBOARD", "LIVE INTERCEPT", "FORENSIC DPI", "THREAT ALERTS", "CASE MGMT", "SOAR CONTROL"
        ])
        
        st.sidebar.markdown("---")
        if st.sidebar.button("TERMINATE OPS"):
            st.session_state.authenticated = False
            st.rerun()
            
        if nav == "DASHBOARD": dashboard_page()
        elif nav == "LIVE INTERCEPT": live_intercept_page()
        elif nav == "FORENSIC DPI": forensic_dpi_page()
        elif nav == "THREAT ALERTS":
            st.title("🚨 ACTIVE THREAT ALERTS")
            alerts = db.get_alerts(limit=200)
            if alerts:
                st.dataframe(pd.DataFrame([{
                    "TIMESTAMP": a.timestamp, "THREAT": a.alert_type, "SEVERITY": a.severity,
                    "SOURCE": a.source_ip, "TARGET": a.dest_ip, "MITRE": a.mitre_attack
                } for a in alerts]), use_container_width=True)
        elif nav == "CASE MGMT":
            st.title("📋 INCIDENT CASE MANAGEMENT")
            st.info("OPERATIONAL WORKFLOW ACTIVE. TRACKING ALL SECURITY INCIDENTS.")
        elif nav == "SOAR CONTROL":
            st.title("🛠️ SOAR: ACTIVE DEFENSE CONTROL")
            st.subheader("HOST BLACKLIST")
            blocked = comp["soar"].get_blocked_ips()
            if blocked:
                for ip in blocked:
                    col1, col2 = st.columns([3, 1])
                    col1.warning(f"🚫 DROPPING ALL TRAFFIC FROM: {ip}")
                    if col2.button(f"PURGE BLOCK", key=f"unblock_{ip}"):
                        comp["soar"].unblock_ip(ip)
                        st.rerun()
            else:
                st.info("NO ACTIVE BLOCKS IN SYSTEM.")

if __name__ == "__main__":
    main()
