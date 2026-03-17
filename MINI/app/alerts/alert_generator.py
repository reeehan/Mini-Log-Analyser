"""
Alert Generator — Saves alerts to JSON and CSV formats.
"""

import csv
import json
import os

from app.config import OUTPUT_DIR
from app.utils.helpers import ensure_output_dir


class AlertGenerator:
    """Generates alert output files in JSON and CSV formats."""

    FIELDS = [
        "type", "severity", "source_ip", "count",
        "first_seen", "last_seen", "description",
    ]

    def __init__(self, output_dir=None):
        self.output_dir = output_dir or OUTPUT_DIR

    def save_json(self, alerts: list[dict], filename: str = "alerts.json") -> str:
        """Save alerts to a JSON file.

        Returns the output file path.
        """
        ensure_output_dir()
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=str)
        return filepath

    def save_csv(self, alerts: list[dict], filename: str = "alerts.csv") -> str:
        """Save alerts to a CSV file.

        Returns the output file path.
        """
        ensure_output_dir()
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(alerts)
        return filepath

    def save_all(self, alerts: list[dict]) -> dict:
        """Save alerts in both JSON and CSV formats.

        Returns dict with file paths.
        """
        return {
            "json": self.save_json(alerts),
            "csv": self.save_csv(alerts),
        }
