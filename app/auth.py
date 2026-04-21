"""Authentication and authorisation layer — v2.0.

v2.0 addition: ``resolve_role``
    A FastAPI dependency that first checks the ``X-Masking-Role`` header
    (simple, no cryptography — suitable for internal trusted networks).
    If absent or empty, falls back to the existing ``X-API-Token`` token-store
    lookup.  Both paths produce the same resolved role string that the rest
    of the pipeline consumes.

    This keeps the auth layer forward-upgradeable: swapping the header read
    for JWT claim extraction later requires only changing ``resolve_role``;
    the masking pipeline interface is unchanged.

Existing API (unchanged)
------------------------
``require_role(*allowed_roles)``  Token-store–only dependency (v1 behaviour).
``TokenStore`` / ``EnvTokenStore``  Protocol + implementation.
``set_token_store`` / ``get_token_store``  Test override helpers.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Optional, Protocol

from fastapi import Header

from app.exceptions import AuthenticationError, AuthorizationError
from app.policy.loader import get_policy


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


# ── FastAPI dependency factories ──────────────────────────────────────────────

def require_role(*allowed_roles: str):
    """Return a FastAPI dependency that validates the token and optionally restricts roles.

    This is the **v1** dependency — uses ``X-API-Token`` only.
    """

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


def resolve_role(*allowed_roles: str):
    """Return a FastAPI dependency that resolves role via header-first strategy.

    Resolution order
    ----------------
    1. ``X-Masking-Role`` header — if present and non-empty, used directly.
       No cryptographic verification; suitable for internal trusted networks.
    2. ``X-API-Token`` header — looked up in the token store (v1 fallback).

    Raises ``AuthenticationError`` (HTTP 401) when neither header is provided
    or the token is unrecognised.

    Raises ``AuthenticationError`` (HTTP 401) when the role from
    ``X-Masking-Role`` is not in the known set of valid roles.
    """

    async def dependency(
        x_masking_role: str = Header(default=""),
        x_api_token:    str = Header(default=""),
    ) -> str:
        # ── Priority 1: simple role header ───────────────────────────────────
        if x_masking_role:
            role = x_masking_role.lower().strip()
            
            try:
                known_roles = set(get_policy().roles.keys())
            except RuntimeError:
                known_roles = set()
                
            if role not in known_roles:
                raise AuthenticationError(
                    f"Unknown role '{role}' in X-Masking-Role. "
                    f"Valid roles: {sorted(known_roles)}."
                )
            if allowed_roles and role not in allowed_roles:
                raise AuthorizationError(role=role, endpoint="this endpoint")
            return role

        # ── Priority 2: token store lookup ────────────────────────────────────
        if not x_api_token:
            raise AuthenticationError(
                "Missing authentication header. Provide either "
                "X-Masking-Role or X-API-Token."
            )
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
