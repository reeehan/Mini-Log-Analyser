"""
Unit tests for detection modules (BruteForce, SuspiciousIP, RulesEngine).
"""

import sys
import os
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.detection.brute_force import BruteForceDetector
from app.detection.suspicious_ip import SuspiciousIPDetector
from app.detection.rules_engine import RulesEngine


def _make_apache_log(ip, status, minute_offset=0):
    """Helper to create a fake Apache log record."""
    return {
        "ip": ip,
        "status": status,
        "timestamp": datetime(2026, 2, 27, 10, minute_offset, 0, tzinfo=timezone.utc),
        "log_type": "apache",
        "method": "POST",
        "url": "/login",
        "raw": f'{ip} - - "POST /login" {status}',
    }


def _make_windows_log(ip, event_id, message, minute_offset=0):
    """Helper to create a fake Windows log record."""
    return {
        "ip": ip,
        "event_id": event_id,
        "timestamp": datetime(2026, 2, 27, 10, minute_offset, 0, tzinfo=timezone.utc),
        "log_type": "windows",
        "severity": "HIGH" if event_id == 4625 else "INFO",
        "message": message,
        "raw": f"{ip} EventID:{event_id} {message}",
    }


class TestBruteForceDetector(unittest.TestCase):

    def test_detects_brute_force_apache(self):
        """Should flag IP with 5+ failed logins (401)."""
        logs = [_make_apache_log("10.0.0.1", 401, i) for i in range(6)]
        detector = BruteForceDetector(threshold=5)
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "Brute Force")
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.1")

    def test_no_alert_below_threshold(self):
        """Should NOT flag with only 3 failed logins (below threshold of 5)."""
        logs = [_make_apache_log("10.0.0.1", 401, i) for i in range(3)]
        detector = BruteForceDetector(threshold=5)
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 0)

    def test_ignores_200_status(self):
        """Successful requests should not trigger brute-force detection."""
        logs = [_make_apache_log("10.0.0.1", 200, i) for i in range(10)]
        detector = BruteForceDetector()
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 0)

    def test_detects_brute_force_windows(self):
        """Should flag EventID 4625 brute-force on Windows logs."""
        logs = [
            _make_windows_log("10.0.0.2", 4625, "An account failed to log on.", i)
            for i in range(6)
        ]
        detector = BruteForceDetector(threshold=5)
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.2")


class TestSuspiciousIPDetector(unittest.TestCase):

    def test_detects_suspicious_ip(self):
        """Should flag IPs from the blocklist."""
        logs = [_make_apache_log("203.0.113.42", 200)]
        detector = SuspiciousIPDetector(blocklist=["203.0.113.42"])
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "Suspicious IP")

    def test_no_alert_for_clean_ip(self):
        """Should NOT flag non-blocklisted IPs."""
        logs = [_make_apache_log("192.168.1.1", 200)]
        detector = SuspiciousIPDetector(blocklist=["10.0.0.99"])
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 0)

    def test_severity_escalates_with_count(self):
        """Severity should escalate from MEDIUM to HIGH to CRITICAL."""
        logs = [_make_apache_log("203.0.113.42", 200, i) for i in range(12)]
        detector = SuspiciousIPDetector(blocklist=["203.0.113.42"])
        alerts = detector.detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")


class TestRulesEngine(unittest.TestCase):

    def test_runs_all_detectors(self):
        """Engine should aggregate alerts from all detectors."""
        logs = [_make_apache_log("203.0.113.42", 401, i) for i in range(6)]
        engine = RulesEngine()
        alerts = engine.run_all(logs)
        # Should have brute-force and suspicious IP alerts
        types = {a["type"] for a in alerts}
        self.assertIn("Brute Force", types)
        self.assertIn("Suspicious IP", types)

    def test_get_summary(self):
        """Summary should count by severity and type."""
        alerts = [
            {"type": "Brute Force", "severity": "HIGH"},
            {"type": "Suspicious IP", "severity": "MEDIUM"},
        ]
        engine = RulesEngine()
        summary = engine.get_summary(alerts)
        self.assertEqual(summary["total_alerts"], 2)
        self.assertEqual(summary["by_severity"]["HIGH"], 1)
        self.assertEqual(summary["by_type"]["Brute Force"], 1)


if __name__ == "__main__":
    unittest.main()
