"""Dual-logger setup with per-request context variable.

Two loggers are configured at startup:
  - ``app``   — operational events, writes to stdout (and optionally a file).
  - ``audit`` — operator access events only, append-only file, never stdout.

Every record emitted by either logger automatically includes the current
request ID via a custom ``logging.Filter``.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Optional

# Request-scoped identifier; injected by the middleware for every request.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class _RequestIdFilter(logging.Filter):
    """Inject the current request ID into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.request_id = request_id_var.get("-")
        return True


_LOG_FORMAT = "%(asctime)s [%(levelname)s] [req=%(request_id)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def configure_logging(
    *,
    app_log_level: str = "INFO",
    audit_log_path: str,
    app_log_path: Optional[str] = None,
) -> None:
    """Call once at server startup.

    Parameters
    ----------
    app_log_level:
        Python logging level name for the ``app`` logger.
    audit_log_path:
        Absolute path to the append-only audit log file.
    app_log_path:
        Optional absolute path for the application log file.  If *None*,
        application events go to stdout only.
    """
    rid_filter = _RequestIdFilter()
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # ── Application logger ────────────────────────────────────────────────────
    app_logger = logging.getLogger("app")
    app_logger.setLevel(getattr(logging, app_log_level, logging.INFO))
    app_logger.handlers.clear()
    app_logger.propagate = False

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.addFilter(rid_filter)
    app_logger.addHandler(stdout_handler)

    if app_log_path:
        file_handler = logging.FileHandler(app_log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(rid_filter)
        app_logger.addHandler(file_handler)

    # ── Audit logger ─────────────────────────────────────────────────────────
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.handlers.clear()
    audit_logger.propagate = False  # never write to stdout

    audit_handler = logging.FileHandler(audit_log_path, mode="a", encoding="utf-8")
    audit_handler.setFormatter(formatter)
    audit_handler.addFilter(rid_filter)
    audit_logger.addHandler(audit_handler)


def get_app_logger() -> logging.Logger:
    return logging.getLogger("app")


def get_audit_logger() -> logging.Logger:
    return logging.getLogger("audit")
