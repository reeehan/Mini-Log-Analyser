"""
Helper utilities for the SOC Log Analyzer.
"""

import os
from datetime import datetime

from app.config import OUTPUT_DIR


def detect_log_type(filepath: str) -> str:
    """Auto-detect whether a log file is Apache or Windows format.

    Reads the first non-empty lines and checks patterns.
    Returns 'apache', 'windows', or 'unknown'.
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Apache lines typically start with an IP and contain HTTP method
            if line[0].isdigit() and ('"GET ' in line or '"POST ' in line or '"PUT ' in line or '"DELETE ' in line):
                return "apache"
            # Windows lines contain pipe-delimited fields with EventID
            if "EventID:" in line and "|" in line:
                return "windows"
    return "unknown"


def ensure_output_dir() -> str:
    """Create the output directory if it doesn't exist.

    Returns the output directory path.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    return OUTPUT_DIR


def timestamp_now() -> str:
    """Return a formatted timestamp string for the current time."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
