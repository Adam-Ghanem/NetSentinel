# PDF Report Generation

NetSentinel generates analyst-facing PDF reports with ReportLab. Report content may include values derived from network evidence, alerts, enrichment responses, or analyst-entered notes, so report rendering must preserve evidence text without treating that text as ReportLab paragraph markup.

## Literal text boundary

Dynamic paragraph content is escaped before it is passed to `reportlab.platypus.Paragraph`. Characters such as `<`, `>`, and `&` therefore render as literal evidence instead of being interpreted as formatting tags or entities.

This boundary protects both reliability and evidence fidelity. For example, a captured value such as `<b>scanner</b> & alert` must appear with the angle-bracket text intact rather than becoming bold text or losing markup-like characters.

Static headings remain application-owned strings. Table cells are passed to ReportLab tables as plain string values and are not parsed through the paragraph markup parser.

## Verification

Run the focused report contract locally with:

```bash
python -m pytest tests/test_report_generator.py
python -m ruff check app/report_generator.py tests/test_report_generator.py
```

The `Report Contracts` workflow runs the same regression boundary on Python 3.10 and Python 3.12 whenever the report generator, its tests, this documentation, or the workflow itself changes.

## Security and operational guidance

- Do not disable literal escaping to add rich formatting to untrusted fields.
- Keep application-owned formatting separate from packet-, alert-, provider-, and analyst-derived text.
- Treat report generation failures as visible workflow errors rather than silently dropping evidence.
- Avoid embedding packet payloads or secrets in reports unless a reviewed product requirement explicitly calls for them.
