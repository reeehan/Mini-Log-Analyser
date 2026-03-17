"""
Windows Event Log–style Parser.

Parses entries like:
2026-02-27 10:15:32 | EventID: 4625 | FAILURE | Security | An account failed to log on. Source: 192.168.1.50
"""

import re
from datetime import datetime


# Windows-style log regex
_WINDOWS_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*'
    r'EventID:\s*(?P<event_id>\d+)\s*\|\s*'
    r'(?P<level>\S+)\s*\|\s*'
    r'(?P<source>[^|]+?)\s*\|\s*'
    r'(?P<message>.+)'
)

# IP extraction from message body
_IP_IN_MSG = re.compile(r'(?:\bSource:\s*)?(\d+\.\d+\.\d+\.\d+)')

# Map Windows event levels to severity
_LEVEL_MAP = {
    "INFORMATION": "INFO",
    "INFO": "INFO",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "ERROR": "HIGH",
    "FAILURE": "HIGH",
    "CRITICAL": "CRITICAL",
    "AUDIT_FAILURE": "HIGH",
    "AUDIT_SUCCESS": "LOW",
}


class WindowsParser:
    """Parses Windows Event Log–style log files."""

    @staticmethod
    def parse_line(line: str) -> dict | None:
        """Parse a single Windows-style log line.

        Returns None if the line doesn't match.
        """
        line = line.strip()
        if not line:
            return None

        match = _WINDOWS_PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp
        try:
            data["timestamp"] = datetime.strptime(
                data["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            data["timestamp"] = None

        data["event_id"] = int(data["event_id"])

        # Extract IP from message if present
        ip_match = _IP_IN_MSG.search(data["message"])
        data["ip"] = ip_match.group(1) if ip_match else None

        # Map severity
        level = data["level"].upper().strip()
        data["severity"] = _LEVEL_MAP.get(level, "MEDIUM")
        data["source"] = data["source"].strip()
        data["message"] = data["message"].strip()
        data["raw"] = line
        data["log_type"] = "windows"
        return data

    @classmethod
    def parse_file(cls, filepath: str) -> list[dict]:
        """Parse an entire Windows-style log file.

        Returns a list of parsed log records.
        """
        records = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                record = cls.parse_line(line)
                if record:
                    records.append(record)
        return records
