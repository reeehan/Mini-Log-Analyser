"""
Report Writer — Generates a text summary report.
"""

import os
from collections import Counter

from app.config import OUTPUT_DIR
from app.utils.helpers import ensure_output_dir, timestamp_now


class ReportWriter:
    """Generates human-readable summary reports."""

    def __init__(self, output_dir=None):
        self.output_dir = output_dir or OUTPUT_DIR

    def generate(self, logs: list[dict], alerts: list[dict],
                 filename: str = "report.txt") -> str:
        """Write a text summary report to the output directory.

        Returns the output file path.
        """
        ensure_output_dir()
        filepath = os.path.join(self.output_dir, filename)

        # ── Compute statistics ──
        total_events = len(logs)
        severity_counts = Counter(r.get("severity", "UNKNOWN") for r in logs)
        ip_counts = Counter(r.get("ip") for r in logs if r.get("ip"))
        top_ips = ip_counts.most_common(10)

        alert_severity = Counter(a["severity"] for a in alerts)
        alert_types = Counter(a["type"] for a in alerts)

        # ── Build report ──
        lines = []
        lines.append("=" * 64)
        lines.append("       MINI SOC LOG ANALYZER — SUMMARY REPORT")
        lines.append("=" * 64)
        lines.append(f"  Generated : {timestamp_now()}")
        lines.append(f"  Total Log Entries Analyzed : {total_events}")
        lines.append(f"  Total Alerts Generated     : {len(alerts)}")
        lines.append("")

        # Severity distribution
        lines.append("-" * 40)
        lines.append("  EVENT SEVERITY DISTRIBUTION")
        lines.append("-" * 40)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            bar = "█" * min(count, 40)
            lines.append(f"  {sev:<10} : {count:>5}  {bar}")
        lines.append("")

        # Top source IPs
        lines.append("-" * 40)
        lines.append("  TOP 10 SOURCE IPs")
        lines.append("-" * 40)
        for ip, count in top_ips:
            lines.append(f"  {ip:<18} : {count:>5} events")
        lines.append("")

        # Alert summary
        lines.append("-" * 40)
        lines.append("  THREAT ALERTS")
        lines.append("-" * 40)
        if not alerts:
            lines.append("  No threats detected.")
        else:
            lines.append(f"  Total : {len(alerts)}")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in alert_severity:
                    lines.append(f"  {sev:<10} : {alert_severity[sev]}")
            lines.append("")
            for alert in alerts:
                lines.append(f"  [{alert['severity']}] {alert['type']}")
                lines.append(f"    Source IP : {alert.get('source_ip', 'N/A')}")
                lines.append(f"    Count    : {alert.get('count', 'N/A')}")
                lines.append(f"    Detail   : {alert.get('description', '')}")
                lines.append("")

        lines.append("=" * 64)
        lines.append("  End of Report")
        lines.append("=" * 64)

        report_text = "\n".join(lines)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_text)

        return filepath
