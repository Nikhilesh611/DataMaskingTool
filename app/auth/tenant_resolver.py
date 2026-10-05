"""Multi-Tenant Request Context & Tenant Resolver (Phase 2).

Purpose
-------
Every authenticated request to the masking service belongs to exactly one
tenant.  This module resolves *which* tenant a request belongs to, then loads
that tenant's IdP configuration from the database so downstream components
(JWT validator, group mapper) have the correct per-tenant settings.

Resolution Strategy (priority order)
-------------------------------------
1. **JWT ``iss`` claim** (preferred for API clients)
   Peek at the unverified JWT header + payload to read ``iss``.
   Look up ``AuthProvider.issuer_url == iss`` in the database.
   This requires no extra header — the token is self-identifying.

2. **``X-Tenant-Slug`` header** (preferred for admin / dev flows)
   Clients can send ``X-Tenant-Slug: acme-corp`` to identify themselves.
   The slug is looked up in the ``Tenant`` table.  The tenant must be active
   and must have at least one ``AuthProvider`` configured.

3. **Subdomain header** (future / proxy-injected)
   Not yet wired to a route; placeholder for ``Host`` header parsing when
   the service is deployed behind an API gateway that injects tenant context
   via subdomain (``acme.masking.enterprise.com``).

Fail-Closed
-----------
If no tenant can be resolved (unknown issuer, unknown slug, inactive tenant,
no auth provider), the request fails with **HTTP 401** — not a fallback to a
default tenant.  There is no "default tenant" concept.

TenantContext
-------------
A frozen dataclass carrying everything the request needs about the tenant.
It is attached to the FastAPI request state after resolution and passed
directly to ``validate_jwt`` and the group mapper.

Usage (in routes)
-----------------
    from app.auth.tenant_resolver import TenantContext, resolve_tenant

    @router.post("/v1/mask")
    async def mask(
        tenant: TenantContext = Depends(resolve_tenant),
        ...
    ):
        claims = await validate_jwt(token, tenant=tenant)
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ApiKey, AuthProvider, Tenant
from app.db.session import get_session
from app.exceptions import AuthenticationError


# ── TenantContext ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TenantContext:
    """Resolved tenant identity and IdP configuration for one request.

    Attributes
    ----------
    tenant_id:
        UUID of the ``Tenant`` row.
    tenant_slug:
        Human-readable slug (e.g. ``"acme-corp"``).
    provider_id:
        UUID of the ``AuthProvider`` row used to authenticate this request.
    provider_type:
        ``"oidc"`` or ``"ldap"``.
    issuer_url:
        IdP issuer URL.  Used for ``iss`` claim validation.
    jwks_uri:
        Explicit JWKS URI if set; otherwise ``None`` (triggers OIDC discovery).
    audience:
        Expected ``aud`` claim in the JWT.
    groups_claim:
        JWT claim key where the IdP publishes group memberships.
    """

    tenant_id: str
    tenant_slug: str
    provider_id: str
    provider_type: str
    issuer_url: str
    jwks_uri: Optional[str]
    audience: str
    groups_claim: str


# ── Helper: peek at unverified JWT payload ─────────────────────────────────────

def _peek_jwt_iss(token: str) -> str | None:
    """Decode the JWT payload WITHOUT signature verification to extract ``iss``.

    This is safe because:
    - We only use the ``iss`` value to look up a tenant's public key.
    - The actual signature verification happens *after* we have the key.
    - An attacker cannot gain access by forging an ``iss`` — they still need
      a valid signature from the *real* key for that issuer.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        # Base64url decode with padding
        payload_b64 = parts[1] + "=="  # pad generously; Python ignores extra
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        iss = payload.get("iss")
        return iss if isinstance(iss, str) else None
    except Exception:
        return None


# ── Resolution helpers ─────────────────────────────────────────────────────────

async def _resolve_by_issuer(
    issuer: str, db: AsyncSession
) -> TenantContext | None:
    """Look up tenant by JWT ``iss`` → ``AuthProvider.issuer_url`` match."""
    issuer_clean = issuer.rstrip("/")

    result = await db.execute(
        select(AuthProvider, Tenant)
        .join(Tenant, Tenant.id == AuthProvider.tenant_id)
        .where(AuthProvider.issuer_url.in_([issuer_clean, issuer_clean + "/"]))
        .where(AuthProvider.is_active.is_(True))
        .where(Tenant.is_active.is_(True))
        .limit(1)
    )
    row = result.first()
    if row is None:
        return None

    provider, tenant = row
    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        provider_id=provider.id,
        provider_type=provider.provider_type,
        issuer_url=provider.issuer_url or "",
        jwks_uri=provider.jwks_uri or None,
        audience=provider.audience or "",
        groups_claim=provider.groups_claim or "groups",
    )


async def _resolve_by_slug(
    slug: str, db: AsyncSession
) -> TenantContext | None:
    """Look up tenant by ``X-Tenant-Slug`` header → ``Tenant.slug`` match."""
    result = await db.execute(
        select(Tenant).where(Tenant.slug == slug).where(Tenant.is_active.is_(True))
    )
    tenant = result.scalar_one_or_none()
    if tenant is None:
        return None

    # Pick the first active OIDC provider for this tenant
    prov_result = await db.execute(
        select(AuthProvider)
        .where(AuthProvider.tenant_id == tenant.id)
        .where(AuthProvider.is_active.is_(True))
        .limit(1)
    )
    provider = prov_result.scalar_one_or_none()
    if provider is None:
        return None

    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        provider_id=provider.id,
        provider_type=provider.provider_type,
        issuer_url=provider.issuer_url or "",
        jwks_uri=provider.jwks_uri or None,
        audience=provider.audience or "",
        groups_claim=provider.groups_claim or "groups",
    )


def hash_api_key(key: str) -> str:
    import hashlib
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()


async def _resolve_by_api_key(
    raw_key: str, db: AsyncSession
) -> tuple[TenantContext, ApiKey] | None:
    """Look up tenant and role by matching SHA-256 hash of API key."""
    key_hash = hash_api_key(raw_key)
    result = await db.execute(
        select(ApiKey, Tenant)
        .join(Tenant, Tenant.id == ApiKey.tenant_id)
        .where(ApiKey.key_hash == key_hash)
        .where(ApiKey.is_active.is_(True))
        .where(Tenant.is_active.is_(True))
        .limit(1)
    )
    row = result.first()
    if row is None:
        return None

    api_key, tenant = row
    ctx = TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        provider_id=api_key.id,
        provider_type="api_key",
        issuer_url="",
        jwks_uri=None,
        audience="",
        groups_claim="",
    )
    return ctx, api_key


# ── FastAPI dependency ─────────────────────────────────────────────────────────

_http_bearer = HTTPBearer(auto_error=False)


async def resolve_tenant(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_http_bearer),
    x_tenant_slug: str = Header(default=""),
    db: AsyncSession = Depends(get_session),
) -> TenantContext:
    """FastAPI dependency: resolve the tenant context for the current request.

    Resolution order
    ----------------
    0. API Key via ``X-API-Key`` header or ``Authorization: Bearer dm_...``.
    1. JWT ``iss`` claim from ``Authorization: Bearer <token>`` header.
    2. ``X-Tenant-Slug`` header.

    Returns
    -------
    TenantContext
        Frozen object carrying tenant identity and IdP config.

    Raises
    ------
    AuthenticationError (HTTP 401)
        If no matching active tenant+provider is found.
    """
    # ── Priority 0: API Key (direct developer / service / solo user) ──────────
    x_api_key = ""
    if hasattr(request, "scope") and isinstance(request.scope, dict) and "headers" in request.scope:
        x_api_key = request.headers.get("x-api-key", "")
    candidate_key = str(x_api_key).strip() if x_api_key else ""
    if not candidate_key and credentials and credentials.credentials:
        if str(credentials.credentials).startswith("dm_"):
            candidate_key = str(credentials.credentials).strip()

    if candidate_key:
        res = await _resolve_by_api_key(candidate_key, db)
        if res is not None:
            ctx, api_key_obj = res
            request.state.tenant_context = ctx
            request.state.api_key_role = api_key_obj.role
            request.state.api_key_name = api_key_obj.name
            return ctx
        raise AuthenticationError("Invalid or revoked API Key.")

    # ── Priority 1: JWT iss claim ─────────────────────────────────────────────
    if credentials and credentials.credentials:
        iss = _peek_jwt_iss(credentials.credentials)
        if iss:
            ctx = await _resolve_by_issuer(iss, db)
            if ctx is not None:
                # Attach to request state for downstream introspection/logging
                request.state.tenant_context = ctx
                return ctx

    # ── Priority 2: X-Tenant-Slug header ─────────────────────────────────────
    if x_tenant_slug:
        ctx = await _resolve_by_slug(x_tenant_slug.strip(), db)
        if ctx is not None:
            request.state.tenant_context = ctx
            return ctx

    # ── Fail closed ───────────────────────────────────────────────────────────
    raise AuthenticationError(
        "Unable to identify tenant. Provide a valid JWT with a known 'iss' claim, "
        "an 'X-Tenant-Slug' header matching a registered tenant, or an 'X-API-Key' header."
    )



async def resolve_tenant_optional(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_http_bearer),
    x_tenant_slug: str = Header(default=""),
    db: AsyncSession = Depends(get_session),
) -> TenantContext | None:
    """Like ``resolve_tenant`` but returns None instead of raising 401.

    Use this in endpoints that support both authenticated and unauthenticated
    flows (e.g., health checks, public endpoints).
    """
    try:
        return await resolve_tenant(request, credentials, x_tenant_slug, db)
    except AuthenticationError:
        return None
