# PDF Report Generation

NetSentinel generates analyst-facing PDF reports with ReportLab. Report content may include values derived from network evidence, alerts, enrichment responses, or analyst-entered notes, so report rendering must preserve evidence text without treating that text as ReportLab paragraph markup.

## Dashboard export flow

The Alerts page exposes an in-memory PDF download alongside the existing CSV alert export. The dashboard builds report evidence from a bounded snapshot of stored records, then calls `ReportGenerator.generate_report_bytes()` and passes the returned bytes directly to Streamlit's download control.

The dashboard does not create a persistent `security_report.pdf` file for this workflow. This avoids stale report files, cross-session filename collisions, and unnecessary evidence residue on the application filesystem.

The current dashboard snapshot is intentionally bounded:

- up to 1,000 stored packet metadata records;
- the 100 alerts loaded for the Alerts page;
- up to 10 aggregated top talkers in the report data;
- up to 25 alert rows embedded in the PDF.

These are product and resource bounds, not claims that the report represents every record ever observed by a sensor.

## Report evidence aggregation

`app/report_data.py` is a pure aggregation boundary between persistence/UI objects and ReportLab. It derives:

- protocol counts;
- per-source packet and byte totals;
- top talkers;
- severity distribution;
- bounded alert rows;
- MITRE ATT&CK technique counts;
- deterministic analyst guidance describing the snapshot scope.

Missing optional values degrade to explicit `Unknown`/`N/A` report evidence instead of crashing the export. Negative, missing, or non-numeric packet sizes do not reduce byte totals.

## Literal text boundary

Dynamic paragraph content is escaped before it is passed to `reportlab.platypus.Paragraph`. Characters such as `<`, `>`, and `&` therefore render as literal evidence instead of being interpreted as formatting tags or entities.

This boundary protects both reliability and evidence fidelity. For example, a captured value such as `<b>scanner</b> & alert` must appear with the angle-bracket text intact rather than becoming bold text or losing markup-like characters.

Static headings remain application-owned strings. Table cells are passed to ReportLab tables as plain string values and are not parsed through the paragraph markup parser.

## Verification

Run the focused report contracts locally with:

```bash
python -m pytest \
  tests/test_report_data.py \
  tests/test_report_generator.py \
  tests/test_dashboard_report_boundary.py

python -m ruff check \
  app/report_data.py \
  app/report_generator.py \
  dashboard/streamlit_app.py \
  tests/test_report_data.py \
  tests/test_report_generator.py \
  tests/test_dashboard_report_boundary.py
```

The `Report Contracts` workflow runs the same regression boundary on Python 3.10 and Python 3.12 whenever report aggregation, generation, dashboard wiring, tests, this documentation, or the workflow itself changes.

## Security and operational guidance

- Do not disable literal escaping to add rich formatting to untrusted fields.
- Keep application-owned formatting separate from packet-, alert-, provider-, and analyst-derived text.
- Treat report generation failures as visible workflow errors rather than silently dropping evidence.
- Avoid embedding packet payloads or secrets in reports unless a reviewed product requirement explicitly calls for them.
- Keep dashboard report inputs bounded; larger historical exports should use a separately reviewed asynchronous/export architecture rather than unbounded in-process aggregation.
