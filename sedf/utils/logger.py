"""
sedf/utils/logger.py - Centralized logging for SEDF (NFR-04)

Provides color-coded, level-aware logging to stdout/stderr.
"""

import logging
import sys

_COLOURS = {
    "DEBUG": "\033[90m",     # Dark gray
    "INFO": "\033[36m",      # Cyan
    "WARNING": "\033[33m",   # Yellow
    "ERROR": "\033[31m",     # Red
    "CRITICAL": "\033[1;31m" # Bold red
}
_RESET = "\033[0m"


class ColourFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, "")
        prefix = f"{colour}[{record.levelname[0]}]{_RESET}"
        message = super().format(record)
        return f"{prefix} {message}"


def setup_logger(level: str = "INFO"):
    """Configure the root logger. Call once at startup."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColourFormatter("%(message)s"))

    root = logging.getLogger("sedf")
    root.setLevel(numeric_level)

    if not root.handlers:
        root.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "requests", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the 'sedf' namespace."""
    return logging.getLogger(f"sedf.{name.split('.')[-1]}")
