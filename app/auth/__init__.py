"""Authentication and authorisation layer — v3.0.

v3.0 additions: ``resolve_role_enterprise`` and ``get_mask_auth_dependency``
    ``resolve_role_enterprise`` is a FastAPI dependency that validates a JWT
    from an enterprise IdP (OIDC/JWKS), extracts the configured groups claim,
    resolves an internal masking role via the GroupMappingStore, and returns
    the same ``role: str`` the pipeline already consumes.

    ``get_mask_auth_dependency`` is a factory called once at route registration
    time.  It reads AUTH_MODE from settings and returns either:
      - ``resolve_role()``            for AUTH_MODE=local  (existing behaviour)
      - ``resolve_role_enterprise()`` for AUTH_MODE=enterprise_jwt

    The masking pipeline is completely unchanged: both paths produce the same
    ``role: str`` interface.

v2.0 addition: ``resolve_role``
    Checks ``X-Masking-Role`` header first, then falls back to ``X-API-Token``.

Existing API (all unchanged)
----------------------------
``require_role(*allowed_roles)``    Token-store–only dependency (v1 behaviour).
``resolve_role(*allowed_roles)``    Header-first dependency (v2 behaviour).
``TokenStore`` / ``EnvTokenStore``  Protocol + implementation.
``set_token_store`` / ``get_token_store``  Test override helpers.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Optional, Protocol

from fastapi import Header, Request

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

            valid_roles = known_roles if known_roles else {"analyst", "auditor", "operator"}
            if role not in valid_roles:
                raise AuthenticationError(
                    f"Unknown role '{role}' in X-Masking-Role. "
                    f"Valid roles: {sorted(valid_roles)}."
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


# ── v3.0: Enterprise JWT auth ─────────────────────────────────────────────

def resolve_role_enterprise():
    """Return a FastAPI dependency that validates an enterprise JWT.

    Flow
    ----
    1. Extract Bearer token from ``Authorization`` header.
    2. Validate JWT via ``jwt_validator.validate_jwt()`` (signature, iss, aud,
       exp, nbf) — all checked by PyJWT, no custom crypto.
    3. Extract IdP groups from the configured claim key.
    4. Resolve internal masking role via ``GroupMappingStore.resolve_role()``.
    5. Verify the resolved role exists in ``policy.roles``.
    6. Return the internal role string.

    Raises
    ------
    AuthenticationError (HTTP 401)
        Missing/malformed/expired/wrong-issuer/wrong-audience/unknown-kid JWT.
    AuthorizationError (HTTP 403)
        Valid JWT but no IdP group has a mapping (no mapping = no access).
    JWKSFetchError (HTTP 503)
        JWKS endpoint unreachable — service unavailable.
    """
    from fastapi import Depends
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

    from app.config import get_settings
    from app.idp.group_mapper import get_group_mapping_store
    from app.idp.jwt_validator import extract_groups, validate_jwt

    http_bearer = HTTPBearer(auto_error=False)

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
    ) -> str:
        if credentials is None or not credentials.credentials:
            raise AuthenticationError(
                "Missing Authorization header. Provide: Authorization: Bearer <JWT>"
            )

        token = credentials.credentials
        settings = get_settings()

        # Validate JWT — raises AuthenticationError (401) on any failure.
        # JWKSFetchError (503) propagates as-is if the IdP is unreachable.
        claims = await validate_jwt(
            token,
            issuer=settings.idp_issuer,
            audience=settings.idp_audience,
            jwks_uri_override=settings.idp_jwks_uri or None,
        )

        # Extract IdP groups from the configured claim.
        groups = extract_groups(claims, settings.idp_groups_claim)
        if not groups:
            raise AuthorizationError(
                role="<no groups>",
                endpoint="/mask",
            )

        # Map IdP groups → internal masking role.
        # None means no mapping exists — fail closed (403).
        store = get_group_mapping_store()
        internal_role = store.resolve_role(groups)
        if internal_role is None:
            raise AuthorizationError(
                role=f"groups={groups}",
                endpoint="/mask",
            )

        # Verify the resolved role is known to the current policy.
        # This is a configuration guard — catches mismatches between
        # group_mappings.json and policy.yaml at request time.
        try:
            known_roles = set(get_policy().roles.keys())
        except RuntimeError:
            known_roles = set()

        valid_roles = known_roles if known_roles else {"analyst", "auditor", "operator"}
        if internal_role not in valid_roles:
            raise AuthorizationError(
                role=internal_role,
                endpoint="/mask",
            )

        return internal_role

    return dependency


from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_http_bearer = HTTPBearer(auto_error=False)


async def get_mask_auth_dependency(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_http_bearer),
) -> str:
    """FastAPI dependency for the ``/mask`` endpoint.

    Dispatches to the correct auth mechanism based on AUTH_MODE, read lazily
    at each request rather than at module import time.  This is required because
    settings are not yet loaded when the module is first imported.

    AUTH_MODE is deployment/startup configuration — not hot-switchable.

    local          → resolve_role() logic   (existing v2 behaviour)
    enterprise_jwt → resolve_role_enterprise() logic (v3 JWT validation)

    Both paths return the same ``role: str`` interface so the masking pipeline
    requires zero changes.
    """
    from app.config import get_settings
    settings = get_settings()

    if settings.auth_mode == "enterprise_jwt":
        # Enterprise JWT path — extract Bearer token from Authorization header.
        from app.idp.group_mapper import get_group_mapping_store
        from app.idp.jwt_validator import extract_groups, validate_jwt

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise AuthenticationError(
                "Missing Authorization header. Provide: Authorization: Bearer <JWT>"
            )
        token = auth_header[7:].strip()
        if not token:
            raise AuthenticationError(
                "Missing Authorization header. Provide: Authorization: Bearer <JWT>"
            )

        claims = await validate_jwt(
            token,
            issuer=settings.idp_issuer,
            audience=settings.idp_audience,
            jwks_uri_override=settings.idp_jwks_uri or None,
        )

        groups = extract_groups(claims, settings.idp_groups_claim)
        if not groups:
            raise AuthorizationError(role="<no groups>", endpoint="/mask")

        store = get_group_mapping_store()
        internal_role = store.resolve_role(groups)
        if internal_role is None:
            raise AuthorizationError(role=f"groups={groups}", endpoint="/mask")

        try:
            known_roles = set(get_policy().roles.keys())
        except RuntimeError:
            known_roles = set()

        valid_roles = known_roles if known_roles else {"analyst", "auditor", "operator"}
        if internal_role not in valid_roles:
            raise AuthorizationError(role=internal_role, endpoint="/mask")

        return internal_role

    else:
        # Local mode — delegate to resolve_role() dependency chain.
        # We replicate the resolve_role() logic inline to avoid the factory
        # call pattern that breaks at import time.
        x_masking_role = request.headers.get("x-masking-role", "").strip()
        x_api_token = request.headers.get("x-api-token", "").strip()

        if x_masking_role:
            role = x_masking_role.lower().strip()
            try:
                known_roles = set(get_policy().roles.keys())
            except RuntimeError:
                known_roles = set()
            valid_roles = known_roles if known_roles else {"analyst", "auditor", "operator"}
            if role not in valid_roles:
                raise AuthenticationError(
                    f"Unknown role '{role}' in X-Masking-Role. "
                    f"Valid roles: {sorted(valid_roles)}."
                )
            return role

        if not x_api_token:
            raise AuthenticationError(
                "Missing authentication header. Provide either "
                "X-Masking-Role or X-API-Token."
            )
        role = _store.get_role(x_api_token)
        if role is None:
            raise AuthenticationError("Unrecognised API token.")
        return role
