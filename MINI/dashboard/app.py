"""
Mini SOC Dashboard — Flask Web Application.

A premium dark-mode web dashboard for the SOC Log Analyzer.
Provides file upload, real-time analysis, interactive charts,
threat table, and log viewer.

Run with: python dashboard/app.py
"""

import sys
import os
import json

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, jsonify

from app.parser.apache_parser import ApacheParser
from app.parser.windows_parser import WindowsParser
from app.detection.rules_engine import RulesEngine
from app.alerts.alert_generator import AlertGenerator
from app.reports.report_writer import ReportWriter
from app.utils.helpers import detect_log_type, ensure_output_dir

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze uploaded log file or pasted log text.

    Accepts:
    - file: uploaded log file
    - log_text: pasted raw log text
    - log_type: 'apache', 'windows', or 'auto'

    Returns JSON with parsed logs, alerts, and statistics.
    """
    log_type = request.form.get("log_type", "auto")
    raw_text = None

    # Handle file upload
    if "file" in request.files and request.files["file"].filename:
        uploaded = request.files["file"]
        raw_text = uploaded.read().decode("utf-8", errors="ignore")

    # Handle pasted text
    elif request.form.get("log_text", "").strip():
        raw_text = request.form["log_text"]

    if not raw_text:
        return jsonify({"error": "No log data provided. Upload a file or paste log text."}), 400

    lines = raw_text.strip().splitlines()

    # Auto-detect log type from first non-empty line
    if log_type == "auto":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line[0].isdigit() and ('"GET ' in line or '"POST ' in line or '"PUT ' in line or '"DELETE ' in line):
                log_type = "apache"
                break
            if "EventID:" in line and "|" in line:
                log_type = "windows"
                break
        if log_type == "auto":
            log_type = "apache"  # Default fallback

    # Parse logs
    if log_type == "apache":
        parser = ApacheParser()
        logs = [r for line in lines if (r := parser.parse_line(line))]
    else:
        parser = WindowsParser()
        logs = [r for line in lines if (r := parser.parse_line(line))]

    if not logs:
        return jsonify({"error": "No valid log entries found. Check the log format."}), 400

    # Run detection
    engine = RulesEngine()
    alerts = engine.run_all(logs)
    summary = engine.get_summary(alerts)

    # Compute stats
    from collections import Counter
    severity_counts = Counter(r.get("severity", "UNKNOWN") for r in logs)
    ip_counts = Counter(r.get("ip") for r in logs if r.get("ip"))
    top_ips = ip_counts.most_common(10)

    # Timeline buckets (group by minute)
    timeline = {}
    for r in logs:
        ts = r.get("timestamp")
        if ts:
            key = ts.strftime("%H:%M")
            timeline[key] = timeline.get(key, 0) + 1
    timeline_sorted = sorted(timeline.items())

    # Save output files
    ensure_output_dir()
    AlertGenerator().save_all(alerts)
    ReportWriter().generate(logs, alerts)

    # Build response
    response = {
        "total_events": len(logs),
        "total_alerts": len(alerts),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "unique_ips": len(ip_counts),
        "severity_distribution": dict(severity_counts),
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "timeline": [{"time": t, "count": c} for t, c in timeline_sorted],
        "alerts": alerts,
        "logs": [
            {
                "severity": r.get("severity", "INFO"),
                "ip": r.get("ip", "N/A"),
                "timestamp": str(r.get("timestamp", "N/A")),
                "message": r.get("raw", "")[:200],
            }
            for r in logs
        ],
        "log_type": log_type,
    }

    return jsonify(response)


@app.route("/sample/<log_type>")
def get_sample(log_type):
    """Return sample log content for quick demo."""
    if log_type == "apache":
        filepath = os.path.join(PROJECT_ROOT, "logs", "sample_apache.log")
    elif log_type == "windows":
        filepath = os.path.join(PROJECT_ROOT, "logs", "sample_windows.log")
    else:
        return jsonify({"error": "Invalid log type"}), 400

    if not os.path.exists(filepath):
        return jsonify({"error": "Sample file not found"}), 404

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    return jsonify({"content": content, "type": log_type})


if __name__ == "__main__":
    print("\n🛡️  Mini SOC Dashboard running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
