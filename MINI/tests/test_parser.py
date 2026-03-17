"""
Unit tests for Apache and Windows log parsers.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.parser.apache_parser import ApacheParser
from app.parser.windows_parser import WindowsParser


class TestApacheParser(unittest.TestCase):
    """Tests for ApacheParser."""

    def test_parse_valid_line(self):
        line = '192.168.1.10 - - [27/Feb/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
        result = ApacheParser.parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "192.168.1.10")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["url"], "/index.html")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["log_type"], "apache")

    def test_parse_401_gives_high_severity(self):
        line = '203.0.113.42 - - [27/Feb/2026:10:16:05 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"'
        result = ApacheParser.parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], 401)
        self.assertEqual(result["severity"], "HIGH")

    def test_parse_500_gives_critical_severity(self):
        line = '10.0.0.5 - - [27/Feb/2026:10:27:05 +0000] "DELETE /api/users/42 HTTP/1.1" 500 128 "-" "python-requests/2.28.0"'
        result = ApacheParser.parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], 500)
        self.assertEqual(result["severity"], "CRITICAL")

    def test_parse_empty_line_returns_none(self):
        self.assertIsNone(ApacheParser.parse_line(""))
        self.assertIsNone(ApacheParser.parse_line("   "))

    def test_parse_invalid_line_returns_none(self):
        self.assertIsNone(ApacheParser.parse_line("this is not a log line"))

    def test_parse_file(self):
        log_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "sample_apache.log"
        )
        if os.path.exists(log_path):
            records = ApacheParser.parse_file(log_path)
            self.assertGreater(len(records), 0)
            self.assertTrue(all(r["log_type"] == "apache" for r in records))


class TestWindowsParser(unittest.TestCase):
    """Tests for WindowsParser."""

    def test_parse_valid_line(self):
        line = "2026-02-27 10:15:00 | EventID: 4624 | INFORMATION | Security | An account was successfully logged on. Source: 192.168.1.10"
        result = WindowsParser.parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_id"], 4624)
        self.assertEqual(result["ip"], "192.168.1.10")
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["log_type"], "windows")

    def test_parse_failure_gives_high_severity(self):
        line = "2026-02-27 10:16:00 | EventID: 4625 | FAILURE | Security | An account failed to log on. Source: 203.0.113.42"
        result = WindowsParser.parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_id"], 4625)
        self.assertEqual(result["severity"], "HIGH")

    def test_parse_line_without_ip(self):
        line = "2026-02-27 10:20:00 | EventID: 7036 | INFORMATION | Service Control Manager | The Windows Firewall service entered the running state."
        result = WindowsParser.parse_line(line)
        self.assertIsNotNone(result)
        self.assertIsNone(result["ip"])

    def test_parse_empty_line_returns_none(self):
        self.assertIsNone(WindowsParser.parse_line(""))

    def test_parse_invalid_line_returns_none(self):
        self.assertIsNone(WindowsParser.parse_line("random text"))

    def test_parse_file(self):
        log_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "sample_windows.log"
        )
        if os.path.exists(log_path):
            records = WindowsParser.parse_file(log_path)
            self.assertGreater(len(records), 0)
            self.assertTrue(all(r["log_type"] == "windows" for r in records))


if __name__ == "__main__":
    unittest.main()
