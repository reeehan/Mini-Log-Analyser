# 🛡️ Mini SOC Log Analyzer

A Python-based **Security Operations Center (SOC) Log Analyzer** that parses security log files, detects threats using configurable rules, generates alerts, and produces summary reports.

---

## Features

| Feature | Description |
|---|---|
| **Multi-Format Parsing** | Apache Combined Log & Windows Event Log parsers |
| **Brute Force Detection** | Flags IPs with multiple failed login attempts within a time window |
| **Suspicious IP Detection** | Checks against a configurable IP blocklist with severity escalation |
| **Rules Engine** | Orchestrates all detectors, deduplicates, and severity-sorts alerts |
| **Alert Export** | Saves alerts to JSON and/or CSV in the `output/` directory |
| **Email Alerts (Stub)** | SMTP-ready email notification for critical threats |
| **Summary Reports** | Human-readable text report with severity distribution and top IPs |
| **Colored CLI Output** | ANSI-colored terminal summary with threat details |

---

## Project Structure

```
mini-soc-log-analyzer/
├── app/
│   ├── config.py              # Central configuration
│   ├── parser/
│   │   ├── apache_parser.py   # Apache Combined Log parser
│   │   └── windows_parser.py  # Windows Event Log parser
│   ├── detection/
│   │   ├── brute_force.py     # Brute-force attack detection
│   │   ├── suspicious_ip.py   # Blocklisted IP detection
│   │   └── rules_engine.py    # Detection orchestrator
│   ├── alerts/
│   │   ├── alert_generator.py # JSON/CSV alert writer
│   │   └── email_alert.py     # Email notification (stub)
│   ├── reports/
│   │   └── report_writer.py   # Text summary report
│   └── utils/
│       ├── logger.py          # Colored logging setup
│       └── helpers.py         # Auto-detection & utilities
├── dashboard/                 # Future Flask web dashboard
│   └── app.py
├── logs/                      # Sample log files
│   ├── sample_apache.log
│   └── sample_windows.log
├── output/                    # Generated at runtime
├── tests/
│   ├── test_parser.py
│   └── test_detection.py
├── main.py                    # CLI entry point
├── requirements.txt
└── README.md
```

---

## Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd mini-soc-log-analyzer

# (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Analyze Apache Logs
```bash
python main.py --file logs/sample_apache.log
```

### Analyze Windows Event Logs
```bash
python main.py --file logs/sample_windows.log --type windows
```

### Auto-detect Log Type
```bash
python main.py --file logs/sample_apache.log --type auto
```

### Choose Output Format
```bash
python main.py --file logs/sample_apache.log --output json
python main.py --file logs/sample_apache.log --output csv
python main.py --file logs/sample_apache.log --output both
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Configuration

Edit `app/config.py` to customize:

- **Brute-force threshold** — Number of failed attempts before alert (default: 5)
- **Time window** — Window in seconds for brute-force detection (default: 300)
- **Suspicious IPs** — Add/remove IPs from the blocklist
- **Email settings** — Configure SMTP for live email alerts

---

## Output Files

After running the analyzer, check the `output/` directory:

| File | Description |
|---|---|
| `alerts.json` | Alerts in JSON format |
| `alerts.csv` | Alerts in CSV format |
| `report.txt` | Human-readable summary report |
| `soc_analyzer.log` | Application log file |
