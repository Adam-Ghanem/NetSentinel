import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import os
import sys

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import create_connection, create_tables
from app.sniffer import PacketSniffer
from app.parser import parse_packet
from app.analyzer import PacketAnalyzer
from app.detection_engine import DetectionEngine
from app.rules_engine import RulesEngine
from app.enrichment import Enrichment
from app.case_manager import CaseManager
from app.report_generator import ReportGenerator

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None
if "packets" not in st.session_state:
    st.session_state.packets = []
if "alerts" not in st.session_state:
    st.session_state.alerts = []

# Database connection
@st.cache_resource
def get_db_connection():
    conn = create_connection()
    create_tables(conn)
    return conn

# Login functionality
def login_page():
    st.set_page_config(page_title="NetSentinel - Login", layout="centered")
    st.title("NetSentinel - Network Monitoring Platform")
    st.subheader("Secure Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        # Simple hardcoded authentication (in production, use proper authentication)
        if username == "admin" and password == "admin":
            st.session_state.authenticated = True
            st.session_state.role = "Admin"
            st.success("Logged in as Admin")
            st.rerun()
        elif username == "analyst" and password == "analyst":
            st.session_state.authenticated = True
            st.session_state.role = "Analyst"
            st.success("Logged in as Analyst")
            st.rerun()
        else:
            st.error("Invalid credentials")

    st.warning("⚠️ Demo Credentials: admin/admin or analyst/analyst")

# Main dashboard
def main_dashboard():
    st.set_page_config(page_title="NetSentinel Dashboard", layout="wide")
    
    # Sidebar
    st.sidebar.title("NetSentinel")
    st.sidebar.write(f"Logged in as: **{st.session_state.role}**")
    
    page = st.sidebar.radio("Navigation", [
        "Dashboard",
        "Live Packets",
        "PCAP Upload",
        "Alerts",
        "Cases",
        "IOC Enrichment",
        "Reports"
    ])

    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.role = None
        st.rerun()

    # Page routing
    if page == "Dashboard":
        dashboard_page()
    elif page == "Live Packets":
        live_packets_page()
    elif page == "PCAP Upload":
        pcap_upload_page()
    elif page == "Alerts":
        alerts_page()
    elif page == "Cases":
        cases_page()
    elif page == "IOC Enrichment":
        ioc_enrichment_page()
    elif page == "Reports":
        reports_page()

def dashboard_page():
    st.title("Dashboard")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Packets", len(st.session_state.packets))
    with col2:
        st.metric("Active Alerts", len(st.session_state.alerts))
    with col3:
        st.metric("High Severity", sum(1 for a in st.session_state.alerts if a.get("severity") == "High"))
    with col4:
        st.metric("Risk Score", "7.2/10")

    st.subheader("Protocol Distribution")
    if st.session_state.packets:
        protocols = {}
        for packet in st.session_state.packets:
            proto = packet.get("protocol", "UNKNOWN")
            protocols[proto] = protocols.get(proto, 0) + 1
        
        fig = px.pie(values=list(protocols.values()), names=list(protocols.keys()), title="Protocol Distribution")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No packets captured yet.")

    st.subheader("Top Source IPs")
    if st.session_state.packets:
        src_ips = {}
        for packet in st.session_state.packets:
            src = packet.get("source_ip")
            if src:
                src_ips[src] = src_ips.get(src, 0) + 1
        
        top_src = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        fig = px.bar(x=[ip for ip, count in top_src], y=[count for ip, count in top_src], title="Top Source IPs")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No packets captured yet.")

def live_packets_page():
    st.title("Live Packet Capture")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Capture"):
            st.info("Packet capture started (simulated)")
            # In production, this would start the actual sniffer
    
    with col2:
        if st.button("Stop Capture"):
            st.info("Packet capture stopped")

    st.subheader("Captured Packets")
    if st.session_state.packets:
        df = pd.DataFrame(st.session_state.packets)
        st.dataframe(df, use_container_width=True)
        
        if st.button("Export Packets to CSV"):
            csv = df.to_csv(index=False)
            st.download_button(label="Download CSV", data=csv, file_name="packets.csv", mime="text/csv")
    else:
        st.info("No packets captured yet.")

def pcap_upload_page():
    st.title("PCAP File Upload & Analysis")
    
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])
    
    if uploaded_file is not None:
        st.success(f"File uploaded: {uploaded_file.name}")
        st.info("PCAP analysis feature is under development.")
        # In production, parse PCAP file and add packets to st.session_state.packets

def alerts_page():
    st.title("Security Alerts")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.selectbox("Filter by Severity", ["All", "Critical", "High", "Medium", "Low"])
    with col2:
        alert_type_filter = st.text_input("Filter by Type")
    with col3:
        if st.button("Refresh"):
            st.rerun()

    st.subheader("Alerts")
    if st.session_state.alerts:
        df = pd.DataFrame(st.session_state.alerts)
        st.dataframe(df, use_container_width=True)
        
        if st.button("Export Alerts to CSV"):
            csv = df.to_csv(index=False)
            st.download_button(label="Download CSV", data=csv, file_name="alerts.csv", mime="text/csv")
    else:
        st.info("No alerts at this time.")

def cases_page():
    st.title("Case Management")
    
    tab1, tab2 = st.tabs(["View Cases", "Create Case"])
    
    with tab1:
        st.subheader("Active Cases")
        st.info("Case management feature is under development.")
        # Display cases from database
    
    with tab2:
        st.subheader("Create New Case")
        case_title = st.text_input("Case Title")
        case_description = st.text_area("Description")
        case_severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
        
        if st.button("Create Case"):
            st.success(f"Case created: {case_title}")

def ioc_enrichment_page():
    st.title("IOC Enrichment")
    
    st.subheader("Enrich Indicators of Compromise")
    ioc_input = st.text_input("Enter IP Address or Domain")
    
    if st.button("Enrich"):
        if ioc_input:
            st.info(f"Enriching: {ioc_input}")
            st.write("Enrichment results would appear here.")
        else:
            st.warning("Please enter an IOC to enrich.")

def reports_page():
    st.title("Security Reports")
    
    st.subheader("Generate Report")
    report_type = st.selectbox("Report Type", ["Executive Summary", "Detailed Analysis", "Compliance Report"])
    
    if st.button("Generate Report"):
        st.info(f"Generating {report_type}...")
        st.success("Report generated successfully!")
        st.download_button(label="Download PDF", data=b"PDF content", file_name="report.pdf", mime="application/pdf")

# Main execution
if __name__ == "__main__":
    if not st.session_state.authenticated:
        login_page()
    else:
        main_dashboard()
