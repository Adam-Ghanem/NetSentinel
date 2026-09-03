from app.report_generator import ReportGenerator


def test_report_paragraph_preserves_untrusted_markup_as_literal_text(tmp_path):
    generator = ReportGenerator(tmp_path / "report.pdf")
    untrusted = '<b>scanner</b> & <font color="red">alert</font>'

    generator._add_paragraph(untrusted)

    paragraph = generator.elements[0]
    assert paragraph.getPlainText() == untrusted


def test_generate_report_bytes_returns_pdf_without_persistent_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    generator = ReportGenerator()

    pdf_bytes = generator.generate_report_bytes(
        {"executive_summary": "Evidence-only in-memory report."}
    )

    assert pdf_bytes.startswith(b"%PDF")
    assert not (tmp_path / "security_report.pdf").exists()
