import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import sys
import json
import tempfile
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
from app.utils import get_logger

logger = get_logger(__name__)

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None
if "username" not in st.session_state:
    st.session_state.username = None
if "sniffing" not in st.session_state:
    st.session_state.sniffing = False

# Initialize database manager
@st.cache_resource
def get_db_manager():
    return DatabaseManager()

db = get_db_manager()

# Initialize components
@st.cache_resource
def get_components():
    rules_engine = RulesEngine()
    analyzer = PacketAnalyzer(db)
    detection_engine = DetectionEngine(rules_engine, db)
    sniffer = PacketSniffer(db, analyzer, detection_engine)
    enrichment = Enrichment(db)
    case_manager = CaseManager(db)
    return {
        "rules_engine": rules_engine,
        "analyzer": analyzer,
        "detection_engine": detection_engine,
        "sniffer": sniffer,
        "enrichment": enrichment,
        "case_manager": case_manager
    }

components = get_components()

# Login Page
def login_page():
    st.set_page_config(page_title="NetSentinel - Login", layout="centered")
    st.title("🛡️ NetSentinel")
    st.subheader("Network Detection & Response Platform")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("---")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", use_container_width=True):
            user = db.authenticate_user(username, password)
            if user:
                st.session_state.authenticated = True
                st.session_state.role = user.role
                st.session_state.username = user.username
                st.success(f"Logged in as {user.role}")
                st.rerun()
            else:
                st.error("Invalid credentials")
        
        st.markdown("---")
        st.info("📝 Demo Credentials: admin/admin or analyst/analyst")

# Dashboard Page
def dashboard_page():
    st.title("📊 Dashboard")
    
    alerts = db.get_alerts(limit=100)
    packets = db.get_packets(limit=1000)
    cases = db.get_all_cases()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Alerts", len(alerts))
    with col2:
        critical = len([a for a in alerts if a.severity == "Critical"])
        st.metric("Critical", critical)
    with col3:
        st.metric("Total Packets", len(packets))
    with col4:
        open_cases = len([c for c in cases if c.status == "Open"])
        st.metric("Open Cases", open_cases)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if alerts:
            severity_counts = {}
            for alert in alerts:
                severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
            
            fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Alert Severity Distribution",
                color_discrete_map={"Critical": "#d62728", "High": "#ff7f0e", "Medium": "#2ca02c", "Low": "#1f77b4"}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if packets:
            source_ips = {}
            for packet in packets:
                if packet.source_ip:
                    source_ips[packet.source_ip] = source_ips.get(packet.source_ip, 0) + 1
            
            top_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            if top_ips:
                fig = px.bar(
                    x=[ip[0] for ip in top_ips],
                    y=[ip[1] for ip in top_ips],
                    title="Top 10 Source IPs",
                    labels={"x": "Source IP", "y": "Packet Count"}
                )
                st.plotly_chart(fig, use_container_width=True)

# Live Packets Page
def live_packets_page():
    st.title("📡 Live Packet Capture")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("▶️ Start Sniffing", use_container_width=True):
            iface = st.session_state.get("selected_iface")
            components["sniffer"].start_sniffing(iface=iface)
            st.session_state.sniffing = True
            st.success("Packet capture started...")
    
    with col2:
        if st.button("⏹️ Stop Sniffing", use_container_width=True):
            components["sniffer"].stop_sniffing()
            st.session_state.sniffing = False
            st.info("Packet capture stopped.")
    
    with col3:
        st.session_state.selected_iface = st.selectbox("Interface", [None, "eth0", "wlan0", "lo"])
    
    if st.session_state.sniffing:
        st.warning("🔴 Capturing packets...")
    
    packets = db.get_packets(limit=50)
    if packets:
        packet_data = []
        for p in packets:
            packet_data.append({
                "Timestamp": p.timestamp,
                "Source IP": p.source_ip,
                "Dest IP": p.dest_ip,
                "Protocol": p.protocol,
                "Source Port": p.source_port,
                "Dest Port": p.dest_port,
                "Size": p.packet_size
            })
        
        df = pd.DataFrame(packet_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No packets captured yet.")

# PCAP Upload Page
def pcap_upload_page():
    st.title("📁 PCAP File Analysis")
    
    uploaded_file = st.file_uploader("Upload PCAP file", type="pcap")
    
    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.getbuffer())
            tmp_path = tmp.name
        
        st.info(f"Processing {uploaded_file.name}...")
        
        packet_count = components["sniffer"].process_pcap(tmp_path)
        
        if packet_count > 0:
            st.success(f"Processed {packet_count} packets successfully!")
            
            # Show summary
            packets = db.get_packets(limit=packet_count)
            alerts = db.get_alerts(limit=100)
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Packets", len(packets))
            with col2:
                st.metric("Alerts", len(alerts))
            with col3:
                protocols = {}
                for p in packets:
                    if p.protocol:
                        protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
                st.metric("Protocols", len(protocols))
            with col4:
                source_ips = set(p.source_ip for p in packets if p.source_ip)
                st.metric("Unique Sources", len(source_ips))
            
            st.markdown("---")
            
            # Protocol Distribution
            if protocols:
                fig = px.pie(
                    values=list(protocols.values()),
                    names=list(protocols.keys()),
                    title="Protocol Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Top Destination Ports
            dest_ports = {}
            for p in packets:
                if p.dest_port:
                    dest_ports[str(p.dest_port)] = dest_ports.get(str(p.dest_port), 0) + 1
            
            if dest_ports:
                top_ports = sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:10]
                fig = px.bar(
                    x=[p[0] for p in top_ports],
                    y=[p[1] for p in top_ports],
                    title="Top 10 Destination Ports",
                    labels={"x": "Port", "y": "Count"}
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Alerts
            if alerts:
                st.subheader("Alerts Generated")
                alert_data = []
                for alert in alerts:
                    alert_data.append({
                        "Type": alert.alert_type,
                        "Severity": alert.severity,
                        "Source": alert.source_ip,
                        "Description": alert.description
                    })
                st.dataframe(pd.DataFrame(alert_data), use_container_width=True)
        
        os.unlink(tmp_path)
    else:
        st.info("Upload a PCAP file to analyze network traffic.")

# Alerts Page
def alerts_page():
    st.title("🚨 Security Alerts")
    
    alerts = db.get_alerts(limit=100)
    
    if alerts:
        alert_data = []
        for alert in alerts:
            alert_data.append({
                "Timestamp": alert.timestamp,
                "Alert Type": alert.alert_type,
                "Severity": alert.severity,
                "Source IP": alert.source_ip,
                "Dest IP": alert.dest_ip,
                "Description": alert.description
            })
        
        df = pd.DataFrame(alert_data)
        st.dataframe(df, use_container_width=True)
        
        severity_filter = st.selectbox("Filter by Severity", ["All", "Critical", "High", "Medium", "Low"])
        if severity_filter != "All":
            df_filtered = df[df["Severity"] == severity_filter]
            st.dataframe(df_filtered, use_container_width=True)
    else:
        st.info("No alerts generated yet.")

# Cases Page
def cases_page():
    st.title("📋 Case Management")
    
    if st.session_state.role == "Admin" or st.session_state.role == "Analyst":
        if st.button("➕ Create New Case"):
            st.session_state.show_case_form = True
    
    if st.session_state.get("show_case_form", False):
        st.subheader("Create New Case")
        title = st.text_input("Case Title")
        notes = st.text_area("Initial Notes")
        tags = st.text_input("Tags (comma-separated)")
        
        if st.button("Save Case"):
            if title:
                case_data = {
                    "case_id": "",
                    "alert_id": None,
                    "title": title,
                    "analyst_notes": notes,
                    "status": "Open",
                    "severity": "Medium",
                    "tags": tags
                }
                components["case_manager"].create_case_from_alert(case_data, title, notes, tags)
                st.success("Case created successfully!")
                st.session_state.show_case_form = False
                st.rerun()
            else:
                st.error("Please enter a case title.")
    
    cases = db.get_all_cases()
    if cases:
        case_data = []
        for case in cases:
            case_data.append({
                "Case ID": case.case_id[:8],
                "Title": case.title,
                "Status": case.status,
                "Severity": case.severity,
                "Created": case.created_at
            })
        
        df = pd.DataFrame(case_data)
        st.dataframe(df, use_container_width=True)
        
        # Edit case
        if st.session_state.role == "Admin" or st.session_state.role == "Analyst":
            st.markdown("---")
            st.subheader("Update Case")
            case_id = st.selectbox("Select Case", [c.case_id for c in cases])
            if case_id:
                case = next((c for c in cases if c.case_id == case_id), None)
                if case:
                    new_status = st.selectbox("Status", ["Open", "Investigating", "Closed"], index=["Open", "Investigating", "Closed"].index(case.status))
                    new_notes = st.text_area("Analyst Notes", value=case.analyst_notes or "")
                    
                    if st.button("Update Case"):
                        db.update_case(case_id, {"status": new_status, "analyst_notes": new_notes})
                        st.success("Case updated!")
                        st.rerun()
    else:
        st.info("No cases created yet.")

# IOC Enrichment Page
def ioc_enrichment_page():
    st.title("🔍 IOC Enrichment")
    
    ioc_input = st.text_input("Enter IP address or domain to enrich")
    
    if st.button("Enrich"):
        if ioc_input:
            result = components["enrichment"].enrich_ip_address(ioc_input)
            st.json(result)
        else:
            st.warning("Please enter an IOC to enrich.")

# Reports Page
def reports_page():
    st.title("📄 Security Reports")
    
    if st.session_state.role == "Admin":
        if st.button("📊 Generate Report"):
            alerts = db.get_alerts(limit=100)
            packets = db.get_packets(limit=1000)
            
            report_data = {
                "title": "NetSentinel Security Report",
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alerts": alerts,
                "packets": packets
            }
            
            try:
                report_gen = ReportGenerator("temp_report.pdf")
                report_gen.generate_report(report_data)
                
                with open("temp_report.pdf", "rb") as f:
                    pdf_bytes = f.read()
                
                st.download_button(
                    label="📥 Download Report",
                    data=pdf_bytes,
                    file_name=f"NetSentinel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
                st.success("Report generated successfully!")
            except Exception as e:
                st.error(f"Error generating report: {e}")
    else:
        st.warning("Only Admins can generate reports.")

# Main Application
def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        st.set_page_config(page_title="NetSentinel Dashboard", layout="wide")
        
        # Sidebar
        st.sidebar.title("🛡️ NetSentinel")
        st.sidebar.write(f"**{st.session_state.role}**: {st.session_state.username}")
        
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
            st.session_state.username = None
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

if __name__ == "__main__":
    main()
