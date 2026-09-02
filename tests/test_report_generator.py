from app.report_generator import ReportGenerator


def test_report_paragraph_preserves_untrusted_markup_as_literal_text(tmp_path):
    generator = ReportGenerator(tmp_path / "report.pdf")
    untrusted = '<b>scanner</b> & <font color="red">alert</font>'

    generator._add_paragraph(untrusted)

    paragraph = generator.elements[0]
    assert paragraph.getPlainText() == untrusted
