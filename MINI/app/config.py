"""
Central configuration for Mini SOC Log Analyzer.
"""

import os

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# ──────────────────────────────────────────────
# Detection Thresholds
# ──────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5          # failed attempts from same IP
BRUTE_FORCE_WINDOW_SECONDS = 300   # within 5 minutes

# ──────────────────────────────────────────────
# Suspicious IPs (blocklist)
# ──────────────────────────────────────────────
SUSPICIOUS_IPS = [
    "203.0.113.42",
    "198.51.100.23",
    "192.0.2.99",
    "10.0.0.254",
    "172.16.0.100",
]

# ──────────────────────────────────────────────
# Alert Severity Levels
# ──────────────────────────────────────────────
SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# ──────────────────────────────────────────────
# Email Alert Settings (stub)
# ──────────────────────────────────────────────
EMAIL_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "sender": "soc-alerts@example.com",
    "recipient": "admin@example.com",
    "username": "",
    "password": "",
}

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
LOG_LEVEL = "INFO"
LOG_FILE = os.path.join(OUTPUT_DIR, "soc_analyzer.log")
