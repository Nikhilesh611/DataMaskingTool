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

    # ── Enterprise JWT auth (AUTH_MODE=enterprise_jwt) ────────────────────────
    # auth_mode: "local" uses API_TOKENS; "enterprise_jwt" validates JWTs.
    # This is deployment configuration — not hot-switchable at runtime.
    auth_mode: str = "local"

    # IdP trust configuration (required when auth_mode == "enterprise_jwt")
    idp_issuer: str = ""          # JWT iss validation + OIDC discovery base URL
    idp_audience: str = ""        # JWT aud validation
    idp_mappings_path: str = ""   # Path to group_mappings.json

    # Optional IdP configuration
    idp_jwks_uri: str = ""        # Explicit JWKS URI; skips OIDC discovery
    idp_groups_claim: str = "groups"  # JWT claim key for the groups list
    idp_jwks_cache_ttl_seconds: int = 300  # JWKS cache TTL

    # ── Admin API (Phase 2) ───────────────────────────────────────────────────
    admin_token: str = ""         # Separate token for /admin/* endpoints


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

    # ── Auth mode ─────────────────────────────────────────────────────────────
    auth_mode = os.environ.get("AUTH_MODE", "local").lower().strip()
    if auth_mode not in ("local", "enterprise_jwt"):
        print(
            f"[FATAL] AUTH_MODE '{auth_mode}' is not valid. "
            "Choose from: local, enterprise_jwt",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Enterprise JWT settings ───────────────────────────────────────────────
    idp_issuer = os.environ.get("IDP_ISSUER", "").strip()
    idp_audience = os.environ.get("IDP_AUDIENCE", "").strip()
    idp_mappings_path = os.environ.get("IDP_MAPPINGS_PATH", "").strip()
    idp_jwks_uri = os.environ.get("IDP_JWKS_URI", "").strip()
    idp_groups_claim = os.environ.get("IDP_GROUPS_CLAIM", "groups").strip()

    raw_ttl = os.environ.get("IDP_JWKS_CACHE_TTL_SECONDS", "300").strip()
    try:
        idp_jwks_cache_ttl = int(raw_ttl)
        if idp_jwks_cache_ttl < 0:
            raise ValueError("must be non-negative")
    except ValueError as exc:
        print(
            f"[FATAL] IDP_JWKS_CACHE_TTL_SECONDS '{raw_ttl}' is not a valid "
            f"non-negative integer: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    if auth_mode == "enterprise_jwt":
        missing = []
        if not idp_issuer:
            missing.append("IDP_ISSUER")
        if not idp_audience:
            missing.append("IDP_AUDIENCE")
        if not idp_mappings_path:
            missing.append("IDP_MAPPINGS_PATH")
        if missing:
            print(
                f"[FATAL] AUTH_MODE=enterprise_jwt requires: {', '.join(missing)}.",
                file=sys.stderr,
            )
            sys.exit(1)

    admin_token = os.environ.get("ADMIN_TOKEN", "").strip()

    return Settings(
        data_dir=data_dir,
        policy_path=policy_path,
        audit_log_path=audit_log_path,
        api_tokens=api_tokens,
        app_log_level=log_level,
        auth_mode=auth_mode,
        idp_issuer=idp_issuer,
        idp_audience=idp_audience,
        idp_mappings_path=idp_mappings_path,
        idp_jwks_uri=idp_jwks_uri,
        idp_groups_claim=idp_groups_claim,
        idp_jwks_cache_ttl_seconds=idp_jwks_cache_ttl,
        admin_token=admin_token,
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
