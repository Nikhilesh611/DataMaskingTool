"""Application configuration loaded from environment variables.

The server will exit immediately with a clear message if any required
variable is absent or invalid.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict

from dotenv import load_dotenv

# Load .env file (if present) before reading any environment variables.
# Variables already set in the shell environment take precedence.
load_dotenv(override=True)


@dataclass(frozen=True)
class Settings:
    data_dir: str
    policy_path: str
    audit_log_path: str
    api_tokens: Dict[str, str]
    app_log_level: str = "INFO"


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"[FATAL] Required environment variable '{name}' is missing or empty. "
            "Set it before starting the server.",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def load_settings() -> Settings:
    data_dir = _require("DATA_DIR")
    policy_path = _require("POLICY_PATH")
    audit_log_path = _require("AUDIT_LOG_PATH")

    raw_tokens = _require("API_TOKENS")
    try:
        api_tokens: Dict[str, str] = json.loads(raw_tokens)
    except json.JSONDecodeError as exc:
        print(
            f"[FATAL] API_TOKENS is not valid JSON: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not isinstance(api_tokens, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in api_tokens.items()
    ):
        print(
            "[FATAL] API_TOKENS must be a JSON object mapping string tokens to string roles.",
            file=sys.stderr,
        )
        sys.exit(1)

    log_level = os.environ.get("APP_LOG_LEVEL", "INFO").upper()
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if log_level not in valid_levels:
        print(
            f"[FATAL] APP_LOG_LEVEL '{log_level}' is not valid. "
            f"Choose from: {', '.join(sorted(valid_levels))}",
            file=sys.stderr,
        )
        sys.exit(1)

    return Settings(
        data_dir=data_dir,
        policy_path=policy_path,
        audit_log_path=audit_log_path,
        api_tokens=api_tokens,
        app_log_level=log_level,
    )


# Singleton — populated once at startup by main.py
_settings: Settings | None = None


def get_settings() -> Settings:
    if _settings is None:
        raise RuntimeError("Settings have not been loaded. Call load_settings() at startup.")
    return _settings


def init_settings() -> Settings:
    """Load and cache the singleton settings object."""
    global _settings
    _settings = load_settings()
    return _settings
