"""
Mini SOC Log Analyzer — CLI Entry Point.

Usage:
    python main.py --file logs/sample_apache.log
    python main.py --file logs/sample_windows.log --type windows
    python main.py --file logs/sample_apache.log --output both
"""

import argparse
import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.parser.apache_parser import ApacheParser
from app.parser.windows_parser import WindowsParser
from app.detection.rules_engine import RulesEngine
from app.alerts.alert_generator import AlertGenerator
from app.alerts.email_alert import EmailAlert
from app.reports.report_writer import ReportWriter
from app.utils.logger import setup_logger
from app.utils.helpers import detect_log_type, ensure_output_dir

logger = setup_logger("soc_analyzer")

# ANSI colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    """Print the SOC Analyzer banner."""
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║           🛡️  MINI SOC LOG ANALYZER  🛡️                 ║
║          Security Operations Center Tool                 ║
╚══════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def print_summary(logs, alerts, engine):
    """Print a colored summary to the terminal."""
    summary = engine.get_summary(alerts)

    print(f"\n{BOLD}{'─' * 50}{RESET}")
    print(f"{BOLD}  📊 ANALYSIS SUMMARY{RESET}")
    print(f"{BOLD}{'─' * 50}{RESET}")
    print(f"  Total Events Parsed  : {GREEN}{len(logs)}{RESET}")
    print(f"  Total Alerts         : {RED if alerts else GREEN}{len(alerts)}{RESET}")

    if summary["by_severity"]:
        print(f"\n  {BOLD}Alerts by Severity:{RESET}")
        colors = {"CRITICAL": MAGENTA, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary["by_severity"].get(sev, 0)
            if count:
                c = colors.get(sev, RESET)
                print(f"    {c}● {sev:<10}{RESET} : {count}")

    if summary["by_type"]:
        print(f"\n  {BOLD}Alerts by Type:{RESET}")
        for atype, count in summary["by_type"].items():
            print(f"    ● {atype:<20} : {count}")

    if alerts:
        print(f"\n  {BOLD}🚨 Threat Details:{RESET}")
        for alert in alerts:
            sev = alert["severity"]
            c = {"CRITICAL": MAGENTA, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}.get(sev, RESET)
            print(f"\n    {c}[{sev}]{RESET} {BOLD}{alert['type']}{RESET}")
            print(f"      Source IP : {alert.get('source_ip', 'N/A')}")
            print(f"      Count    : {alert.get('count', 'N/A')}")
            print(f"      Detail   : {alert.get('description', '')}")

    print(f"\n{BOLD}{'─' * 50}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Mini SOC Log Analyzer — Parse logs, detect threats, generate alerts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --file logs/sample_apache.log
  python main.py --file logs/sample_windows.log --type windows
  python main.py --file logs/sample_apache.log --output both
        """,
    )
    parser.add_argument(
        "--file", "-f", required=True,
        help="Path to the log file to analyze",
    )
    parser.add_argument(
        "--type", "-t", choices=["apache", "windows", "auto"], default="auto",
        help="Log file type (default: auto-detect)",
    )
    parser.add_argument(
        "--output", "-o", choices=["json", "csv", "both"], default="both",
        help="Alert output format (default: both)",
    )

    args = parser.parse_args()
    print_banner()

    # ── Validate input ──
    if not os.path.isfile(args.file):
        logger.error(f"File not found: {args.file}")
        sys.exit(1)

    # ── Detect log type ──
    log_type = args.type
    if log_type == "auto":
        log_type = detect_log_type(args.file)
        if log_type == "unknown":
            logger.error("Could not auto-detect log type. Use --type to specify.")
            sys.exit(1)
        logger.info(f"Auto-detected log type: {log_type}")
    else:
        logger.info(f"Using specified log type: {log_type}")

    # ── Parse ──
    logger.info(f"Parsing file: {args.file}")
    if log_type == "apache":
        logs = ApacheParser.parse_file(args.file)
    else:
        logs = WindowsParser.parse_file(args.file)

    if not logs:
        logger.warning("No log entries were parsed. Check file format.")
        sys.exit(0)

    logger.info(f"Parsed {len(logs)} log entries")

    # ── Detect threats ──
    logger.info("Running threat detection rules...")
    engine = RulesEngine()
    alerts = engine.run_all(logs)
    logger.info(f"Detection complete: {len(alerts)} alert(s) generated")

    # ── Generate alert files ──
    ensure_output_dir()
    alert_gen = AlertGenerator()

    if args.output in ("json", "both"):
        path = alert_gen.save_json(alerts)
        logger.info(f"Alerts saved to: {path}")

    if args.output in ("csv", "both"):
        path = alert_gen.save_csv(alerts)
        logger.info(f"Alerts saved to: {path}")

    # ── Generate report ──
    report = ReportWriter()
    report_path = report.generate(logs, alerts)
    logger.info(f"Report saved to: {report_path}")

    # ── Email alerts (if configured) ──
    email = EmailAlert()
    email.send_alert_summary(alerts)

    # ── Terminal summary ──
    print_summary(logs, alerts, engine)

    print(f"{GREEN}✓ Analysis complete. Check the 'output/' directory for results.{RESET}\n")


if __name__ == "__main__":
    main()
