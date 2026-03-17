"""
Suspicious IP Detection Module.

Checks source IPs against a configurable blocklist.
"""

from app.config import SUSPICIOUS_IPS


class SuspiciousIPDetector:
    """Detects access from known suspicious/blocklisted IPs."""

    def __init__(self, blocklist=None):
        self.blocklist = set(blocklist or SUSPICIOUS_IPS)

    def detect(self, logs: list[dict]) -> list[dict]:
        """Check all log entries against the suspicious IP blocklist.

        Returns a list of alert dicts.
        """
        flagged_ips = {}

        for record in logs:
            ip = record.get("ip")
            if not ip or ip not in self.blocklist:
                continue

            if ip not in flagged_ips:
                flagged_ips[ip] = {
                    "type": "Suspicious IP",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "count": 0,
                    "first_seen": str(record.get("timestamp", "N/A")),
                    "last_seen": str(record.get("timestamp", "N/A")),
                    "description": f"Activity detected from blocklisted IP: {ip}",
                }

            flagged_ips[ip]["count"] += 1
            flagged_ips[ip]["last_seen"] = str(record.get("timestamp", "N/A"))

            # Escalate severity with higher activity counts
            if flagged_ips[ip]["count"] >= 10:
                flagged_ips[ip]["severity"] = "CRITICAL"
            elif flagged_ips[ip]["count"] >= 5:
                flagged_ips[ip]["severity"] = "HIGH"

        return list(flagged_ips.values())
