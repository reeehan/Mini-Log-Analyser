"""
Email Alert Module (stub).

Sends alert notifications via SMTP. Currently a placeholder —
logs a warning if SMTP is not configured.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.config import EMAIL_CONFIG
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


class EmailAlert:
    """Sends email notifications for critical alerts."""

    def __init__(self, config=None):
        self.config = config or EMAIL_CONFIG

    def send(self, subject: str, body: str) -> bool:
        """Send an email alert.

        Returns True if sent successfully, False otherwise.
        """
        if not self.config.get("enabled"):
            logger.warning("Email alerts are disabled. Set EMAIL_CONFIG['enabled'] = True in config.py")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.config["sender"]
            msg["To"] = self.config["recipient"]
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                server.starttls()
                server.login(self.config["username"], self.config["password"])
                server.send_message(msg)

            logger.info(f"Email alert sent: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def send_alert_summary(self, alerts: list[dict]) -> bool:
        """Format and send a summary of all alerts via email."""
        if not alerts:
            return False

        critical = [a for a in alerts if a["severity"] == "CRITICAL"]
        high = [a for a in alerts if a["severity"] == "HIGH"]

        subject = f"🚨 SOC Alert: {len(alerts)} threats detected"
        if critical:
            subject += f" ({len(critical)} CRITICAL)"

        lines = ["=" * 60, "MINI SOC LOG ANALYZER — ALERT SUMMARY", "=" * 60, ""]
        for alert in alerts:
            lines.append(f"[{alert['severity']}] {alert['type']}")
            lines.append(f"  Source IP : {alert.get('source_ip', 'N/A')}")
            lines.append(f"  Count    : {alert.get('count', 'N/A')}")
            lines.append(f"  Detail   : {alert.get('description', '')}")
            lines.append("")

        return self.send(subject, "\n".join(lines))
