"""
Brute Force Attack Detection Module.

Detects multiple failed login attempts from the same source IP
within a configurable time window.
"""

from collections import defaultdict
from datetime import timedelta

from app.config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS


class BruteForceDetector:
    """Detects brute-force login attempts."""

    def __init__(self, threshold=None, window_seconds=None):
        self.threshold = threshold or BRUTE_FORCE_THRESHOLD
        self.window = timedelta(seconds=window_seconds or BRUTE_FORCE_WINDOW_SECONDS)

    def detect(self, logs: list[dict]) -> list[dict]:
        """Analyze logs for brute-force patterns.

        Looks for:
        - Apache: HTTP 401 status codes
        - Windows: EventID 4625 (logon failure) or 'failed' keyword

        Returns a list of alert dicts.
        """
        failed_by_ip = defaultdict(list)

        for record in logs:
            ip = record.get("ip")
            if not ip:
                continue

            is_failed = False
            if record.get("log_type") == "apache" and record.get("status") == 401:
                is_failed = True
            elif record.get("log_type") == "windows":
                if record.get("event_id") == 4625 or "failed" in record.get("message", "").lower():
                    is_failed = True

            if is_failed and record.get("timestamp"):
                failed_by_ip[ip].append(record)

        alerts = []
        for ip, attempts in failed_by_ip.items():
            # Sort by timestamp
            attempts.sort(key=lambda r: r["timestamp"])

            # Sliding window check
            window_attempts = []
            for attempt in attempts:
                window_attempts = [
                    a for a in window_attempts
                    if attempt["timestamp"] - a["timestamp"] <= self.window
                ]
                window_attempts.append(attempt)

                if len(window_attempts) >= self.threshold:
                    alerts.append({
                        "type": "Brute Force",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "count": len(attempts),
                        "first_seen": str(attempts[0]["timestamp"]),
                        "last_seen": str(attempts[-1]["timestamp"]),
                        "description": (
                            f"Detected {len(attempts)} failed login attempts "
                            f"from {ip} (threshold: {self.threshold})"
                        ),
                    })
                    break  # One alert per IP

        return alerts
