"""
Logging configuration with colored console output and file handler.
"""

import logging
import os
import sys

from app.config import LOG_LEVEL, LOG_FILE, OUTPUT_DIR


# ANSI color codes for console output
_COLORS = {
    "DEBUG": "\033[36m",      # Cyan
    "INFO": "\033[32m",       # Green
    "WARNING": "\033[33m",    # Yellow
    "ERROR": "\033[31m",      # Red
    "CRITICAL": "\033[35m",   # Magenta
    "RESET": "\033[0m",
}


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds ANSI colors to log level names."""

    FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    DATE_FMT = "%Y-%m-%d %H:%M:%S"

    def format(self, record):
        color = _COLORS.get(record.levelname, "")
        reset = _COLORS["RESET"]
        record.levelname = f"{color}{record.levelname}{reset}"
        formatter = logging.Formatter(self.FORMAT, datefmt=self.DATE_FMT)
        return formatter.format(record)


def setup_logger(name: str = "soc_analyzer") -> logging.Logger:
    """Configure and return the application logger.

    - Colored output to console (stderr)
    - Plain output to log file (output/soc_analyzer.log)
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ── Console handler ──
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ColoredFormatter())
    logger.addHandler(console)

    # ── File handler ──
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(file_handler)

    return logger
