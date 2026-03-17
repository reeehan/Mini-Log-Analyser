"""
Rules Engine — Orchestrator for all detection modules.

Runs every detection module, deduplicates alerts, and assigns
final severity levels.
"""

from app.detection.brute_force import BruteForceDetector
from app.detection.suspicious_ip import SuspiciousIPDetector
from app.config import SEVERITY_LEVELS


class RulesEngine:
    """Runs all detection rules and aggregates the alerts."""

    def __init__(self):
        self.detectors = [
            BruteForceDetector(),
            SuspiciousIPDetector(),
        ]

    def run_all(self, logs: list[dict]) -> list[dict]:
        """Execute every registered detector against the parsed logs.

        Returns a deduplicated, severity-sorted list of alerts.
        """
        all_alerts = []

        for detector in self.detectors:
            alerts = detector.detect(logs)
            all_alerts.extend(alerts)

        # Deduplicate: key = (type, source_ip)
        seen = {}
        for alert in all_alerts:
            key = (alert["type"], alert.get("source_ip", ""))
            if key not in seen:
                seen[key] = alert
            else:
                # Keep the higher severity
                existing = seen[key]
                if SEVERITY_LEVELS.get(alert["severity"], 0) > SEVERITY_LEVELS.get(existing["severity"], 0):
                    seen[key] = alert

        deduped = list(seen.values())

        # Sort by severity descending
        deduped.sort(
            key=lambda a: SEVERITY_LEVELS.get(a["severity"], 0),
            reverse=True,
        )

        return deduped

    def get_summary(self, alerts: list[dict]) -> dict:
        """Produce a summary of all alerts by type and severity."""
        summary = {
            "total_alerts": len(alerts),
            "by_severity": {},
            "by_type": {},
        }

        for alert in alerts:
            sev = alert["severity"]
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            atype = alert["type"]
            summary["by_type"][atype] = summary["by_type"].get(atype, 0) + 1

        return summary
