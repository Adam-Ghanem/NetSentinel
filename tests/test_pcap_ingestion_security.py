from pathlib import Path


def test_dashboard_pcap_ingestion_does_not_load_entire_capture_into_memory():
    dashboard_source = Path("dashboard/streamlit_app.py").read_text(encoding="utf-8")

    assert "rdpcap" not in dashboard_source
