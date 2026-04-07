"""Authentication and authorisation layer.

The ``TokenStore`` protocol decouples the dependency from how tokens are
stored, making it trivially replaceable in tests without patching env vars.

``require_role(*allowed_roles)`` returns a FastAPI dependency that:
  1. Extracts the ``X-API-Token`` header.
  2. Looks up the role in the store.
  3. Raises ``AuthenticationError`` (401) if the token is missing or unknown.
  4. Returns the resolved role string.

Endpoint-level role checking (e.g. auditor-only routes) is done by each
router or by passing the allowed roles to ``require_role``.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Optional, Protocol

from fastapi import Header

from app.exceptions import AuthenticationError, AuthorizationError


# ── Token store protocol ──────────────────────────────────────────────────────

class TokenStore(Protocol):
    def get_role(self, token: str) -> Optional[str]:
        """Return the role for *token*, or *None* if unrecognised."""
        ...


class EnvTokenStore:
    """Reads the ``API_TOKENS`` JSON env var and caches the mapping."""

    def __init__(self) -> None:
        raw = os.environ.get("API_TOKENS", "{}")
        try:
            mapping: Dict[str, str] = json.loads(raw)
        except json.JSONDecodeError:
            mapping = {}
        self._mapping = mapping

    def get_role(self, token: str) -> Optional[str]:
        return self._mapping.get(token)


# Module-level default store — replaced in tests by dependency override.
_store: TokenStore = EnvTokenStore()


def set_token_store(store: TokenStore) -> None:
    """Replace the active token store (useful in tests)."""
    global _store
    _store = store


def get_token_store() -> TokenStore:
    return _store


# ── FastAPI dependency factory ────────────────────────────────────────────────

def require_role(*allowed_roles: str):
    """Return a FastAPI dependency that validates the token and optionally restricts roles."""

    async def dependency(x_api_token: str = Header(default="")) -> str:
        if not x_api_token:
            raise AuthenticationError("Missing X-API-Token header.")
        role = _store.get_role(x_api_token)
        if role is None:
            raise AuthenticationError("Unrecognised API token.")
        if allowed_roles and role not in allowed_roles:
            raise AuthorizationError(role=role, endpoint="this endpoint")
        return role

    return dependency


def get_role_dependency():
    """Dependency that resolves any valid role (no restriction)."""
    return require_role()
