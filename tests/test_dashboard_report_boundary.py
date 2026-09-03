from pathlib import Path


DASHBOARD = Path("dashboard/streamlit_app.py")


def dashboard_source():
    return DASHBOARD.read_text(encoding="utf-8")


def test_dashboard_wires_report_data_builder_and_pdf_generator():
    source = dashboard_source()

    assert "from app.report_data import build_report_data" in source
    assert "from app.report_generator import ReportGenerator" in source
    assert "build_report_data(packets, alerts)" in source


def test_dashboard_exposes_pdf_download_without_persistent_report_file():
    source = dashboard_source()

    assert 'mime="application/pdf"' in source
    assert 'file_name="netsentinel_security_report.pdf"' in source
    assert "generate_report_bytes" in source
    assert "security_report.pdf" not in source
