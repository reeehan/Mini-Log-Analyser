"""
Apache Combined Log Format Parser.

Parses lines like:
192.168.1.10 - - [27/Feb/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
"""

import re
from datetime import datetime


# Apache Combined Log regex
_APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'          # Source IP
    r'(?P<ident>\S+)\s+'                         # Ident
    r'(?P<user>\S+)\s+'                          # User
    r'\[(?P<timestamp>[^\]]+)\]\s+'              # Timestamp
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+' # Request line
    r'(?P<status>\d{3})\s+'                      # Status code
    r'(?P<size>\S+)\s+'                          # Response size
    r'"(?P<referer>[^"]*)"\s+'                   # Referer
    r'"(?P<user_agent>[^"]*)"'                   # User agent
)


class ApacheParser:
    """Parses Apache Combined Log Format files."""

    @staticmethod
    def parse_line(line: str) -> dict | None:
        """Parse a single Apache log line into a structured dict.

        Returns None if the line doesn't match the expected format.
        """
        line = line.strip()
        if not line:
            return None

        match = _APACHE_PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp
        try:
            data["timestamp"] = datetime.strptime(
                data["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
            )
        except ValueError:
            data["timestamp"] = None

        # Convert status to int
        data["status"] = int(data["status"])

        # Determine severity based on status code
        status = data["status"]
        if status >= 500:
            data["severity"] = "CRITICAL"
        elif status in (401, 403):
            data["severity"] = "HIGH"
        elif status >= 400:
            data["severity"] = "MEDIUM"
        elif status >= 300:
            data["severity"] = "LOW"
        else:
            data["severity"] = "INFO"

        data["raw"] = line
        data["log_type"] = "apache"
        return data

    @classmethod
    def parse_file(cls, filepath: str) -> list[dict]:
        """Parse an entire Apache log file.

        Returns a list of parsed log records.
        """
        records = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                record = cls.parse_line(line)
                if record:
                    records.append(record)
        return records
