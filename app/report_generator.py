from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from app.utils import get_timestamp

class ReportGenerator:
    def __init__(self, output_filename="security_report.pdf"):
        self.output_filename = output_filename
        self.styles = getSampleStyleSheet()
        self.elements = []

        # Custom styles
        self.styles.add(ParagraphStyle(name=\'Heading1\', fontSize=24, leading=28, spaceAfter=20, alignment=1))
        self.styles.add(ParagraphStyle(name=\'Heading2\', fontSize=18, leading=22, spaceBefore=10, spaceAfter=10))
        self.styles.add(ParagraphStyle(name=\'Heading3\', fontSize=14, leading=18, spaceBefore=8, spaceAfter=8))
        self.styles.add(ParagraphStyle(name=\'Normal\', fontSize=10, leading=12, spaceAfter=6))
        self.styles.add(ParagraphStyle(name=\'Code\', fontName=\'Courier\', fontSize=9, leading=10, backColor=colors.lightgrey, borderPadding=5))

    def _add_heading(self, text, level=1):
        if level == 1:
            self.elements.append(Paragraph(text, self.styles["Heading1"]))
        elif level == 2:
            self.elements.append(Paragraph(text, self.styles["Heading2"]))
        elif level == 3:
            self.elements.append(Paragraph(text, self.styles["Heading3"]))
        self.elements.append(Spacer(1, 0.2 * inch))

    def _add_paragraph(self, text):
        self.elements.append(Paragraph(text, self.styles["Normal"]))
        self.elements.append(Spacer(1, 0.1 * inch))

    def _add_table(self, data, col_widths=None):
        table_style = TableStyle([
            (\'BACKGROUND\', (0, 0), (-1, 0), colors.grey),
            (\'TEXTCOLOR\', (0, 0), (-1, 0), colors.whitesmoke),
            (\'ALIGN\', (0, 0), (-1, -1), \'CENTER\'),
            (\'FONTNAME\', (0, 0), (-1, 0), \'Helvetica-Bold\'),
            (\'BOTTOMPADDING\', (0, 0), (-1, 0), 12),
            (\'BACKGROUND\', (0, 1), (-1, -1), colors.beige),
            (\'GRID\', (0, 0), (-1, -1), 1, colors.black)
        ])
        table = Table(data, colWidths=col_widths)
        table.setStyle(table_style)
        self.elements.append(table)
        self.elements.append(Spacer(1, 0.2 * inch))

    def generate_report(self, report_data):
        doc = SimpleDocTemplate(self.output_filename, pagesize=letter)
        self.elements = []

        # Title Page
        self._add_heading("NetSentinel Security Report", level=1)
        self._add_paragraph(f"Generated On: {get_timestamp()}")
        self._add_paragraph("Prepared by: NetSentinel Platform")
        self.elements.append(PageBreak())

        # Executive Summary
        self._add_heading("1. Executive Summary", level=2)
        self._add_paragraph(report_data.get("executive_summary", "This report provides an overview of network traffic and detected security events."))
        self.elements.append(Spacer(1, 0.2 * inch))

        # Traffic Overview
        self._add_heading("2. Traffic Overview", level=2)
        self._add_paragraph(report_data.get("traffic_overview", "Summary of overall network activity."))
        if "traffic_stats" in report_data:
            stats_data = [["Metric", "Value"]]
            for ip, stats in report_data["traffic_stats"].items():
                stats_data.append([f"Total Packets ({ip})", stats["total_packets"]])
                stats_data.append([f"Total Bytes ({ip})", stats["total_bytes"]])
            self._add_table(stats_data)

        # Protocol Statistics
        self._add_heading("3. Protocol Statistics", level=2)
        if "protocol_stats" in report_data:
            proto_data = [["Protocol", "Count"]]
            for proto, count in report_data["protocol_stats"].items():
                proto_data.append([proto, count])
            self._add_table(proto_data)

        # Top Talkers
        self._add_heading("4. Top Talkers", level=2)
        if "top_talkers" in report_data:
            talker_data = [["IP Address", "Packets", "Bytes"]]
            for ip, stats in report_data["top_talkers"].items():
                talker_data.append([ip, stats["total_packets"], stats["total_bytes"]])
            self._add_table(talker_data)

        # Top Alerts
        self._add_heading("5. Top Alerts", level=2)
        if "top_alerts" in report_data:
            alert_data = [["Timestamp", "Source IP", "Destination IP", "Type", "Severity"]]
            for alert in report_data["top_alerts"]:
                alert_data.append([
                    alert.get("timestamp", "N/A"),
                    alert.get("source_ip", "N/A"),
                    alert.get("dest_ip", "N/A"),
                    alert.get("alert_type", "N/A"),
                    alert.get("severity", "N/A")
                ])
            self._add_table(alert_data)

        # Severity Distribution
        self._add_heading("6. Severity Distribution", level=2)
        if "severity_distribution" in report_data:
            severity_data = [["Severity", "Count"]]
            for severity, count in report_data["severity_distribution"].items():
                severity_data.append([severity, count])
            self._add_table(severity_data)

        # MITRE ATT&CK Mapping
        self._add_heading("7. MITRE ATT&CK Mapping", level=2)
        if "mitre_attack_mapping" in report_data:
            mitre_data = [["Technique ID", "Technique Name", "Alert Count"]]
            for technique_id, details in report_data["mitre_attack_mapping"].items():
                mitre_data.append([technique_id, details["name"], details["count"]])
            self._add_table(mitre_data)

        # Recommendations
        self._add_heading("8. Recommendations", level=2)
        for rec in report_data.get("recommendations", ["Review all high-severity alerts.", "Implement stronger access controls."]):
            self._add_paragraph(f"- {rec}")

        # Appendix with Technical Details
        self._add_heading("9. Appendix - Technical Details", level=2)
        self._add_paragraph(report_data.get("appendix", "Detailed technical logs and raw data can be found in the system."))

        try:
            doc.build(self.elements)
            print(f"Report generated successfully: {self.output_filename}")
        except Exception as e:
            print(f"Error generating report: {e}")

if __name__ == '__main__':
    # Example Usage
    report_data = {
        "executive_summary": "This is a sample executive summary for the NetSentinel security report. It highlights key findings and overall security posture.",
        "traffic_overview": "The network experienced moderate traffic with a few spikes during the reporting period.",
        "traffic_stats": {
            "192.168.1.10": {"total_packets": 1500, "total_bytes": 150000},
            "10.0.0.5": {"total_packets": 800, "total_bytes": 80000}
        },
        "protocol_stats": {"TCP": 700, "UDP": 300, "ICMP": 50},
        "top_talkers": {
            "192.168.1.10": {"total_packets": 1500, "total_bytes": 150000},
            "10.0.0.5": {"total_packets": 800, "total_bytes": 80000}
        },
        "top_alerts": [
            {"timestamp": "2023-10-27T10:00:00", "source_ip": "192.168.1.10", "dest_ip": "1.2.3.4", "alert_type": "Port Scan", "severity": "High"},
            {"timestamp": "2023-10-27T10:05:00", "source_ip": "10.0.0.5", "dest_ip": "5.6.7.8", "alert_type": "Suspicious DNS", "severity": "Medium"}
        ],
        "severity_distribution": {"High": 10, "Medium": 25, "Low": 50},
        "mitre_attack_mapping": {
            "T1046": {"name": "Network Service Scanning", "count": 7},
            "T1071.004": {"name": "DNS Exfiltration", "count": 3}
        },
        "recommendations": [
            "Review firewall rules to block unauthorized port scans.",
            "Implement DNS sinkholing for known malicious domains.",
            "Conduct regular security awareness training for employees."
        ],
        "appendix": "This section would contain raw logs, detailed packet captures, or other technical data not suitable for the main report body."
    }

    generator = ReportGenerator("sample_security_report.pdf")
    generator.generate_report(report_data)
