"""OIDC Discovery — fetches and caches the IdP's well-known configuration.

Why OIDC discovery?
    Enterprise IdPs (Keycloak, Okta, Azure Entra) publish a standard metadata
    document at ``{issuer}/.well-known/openid-configuration``.  Consuming it
    means the admin only has to supply the issuer URL; the JWKS URI, supported
    algorithms, and other parameters are derived automatically.

Why the JWKS URI override (IDP_JWKS_URI)?
    Some environments cannot reach the OIDC discovery endpoint — air-gapped
    networks, custom PKI setups, or development mocks.  The override lets
    operators skip discovery entirely and supply the JWKS URI directly.
    When both are configured, the explicit URI takes precedence.

Caching:
    The discovery document rarely changes.  We cache it for the lifetime of the
    process.  If the issuer URL changes, a server restart is required (auth mode
    is deployment configuration, not runtime configuration).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from app.exceptions import MaskingAPIError


# ── Exceptions ────────────────────────────────────────────────────────────────

class OIDCDiscoveryError(MaskingAPIError):
    """OIDC discovery endpoint returned an unexpected response. → HTTP 503"""

    def __init__(self, issuer: str, reason: str) -> None:
        super().__init__(
            f"OIDC discovery failed for issuer '{issuer}': {reason}.",
            detail={"issuer": issuer, "reason": reason},
        )


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class OIDCMetadata:
    """Subset of the OIDC discovery document we actually use."""

    issuer: str
    jwks_uri: str


# ── Module-level cache ────────────────────────────────────────────────────────
# Keyed by issuer URL.  Populated lazily on first request.

_cache: dict[str, OIDCMetadata] = {}


# ── Public API ────────────────────────────────────────────────────────────────

async def fetch_oidc_metadata(issuer: str) -> OIDCMetadata:
    """Return OIDC metadata for *issuer*, using the in-process cache.

    The discovery document is fetched once per process lifetime.  The issuer
    URL must end without a trailing slash to match the standard
    ``{issuer}/.well-known/openid-configuration`` path.

    Raises
    ------
    OIDCDiscoveryError
        If the HTTP request fails, the response is not JSON, or the document
        does not contain the required ``jwks_uri`` and ``issuer`` fields.
    """
    issuer = issuer.rstrip("/")

    if issuer in _cache:
        return _cache[issuer]

    discovery_url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(discovery_url)
            resp.raise_for_status()
            doc = resp.json()
    except httpx.HTTPStatusError as exc:
        raise OIDCDiscoveryError(issuer, f"HTTP {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise OIDCDiscoveryError(issuer, str(exc)) from exc
    except Exception as exc:
        raise OIDCDiscoveryError(issuer, str(exc)) from exc

    jwks_uri: Optional[str] = doc.get("jwks_uri")
    discovered_issuer: Optional[str] = doc.get("issuer")

    if not jwks_uri:
        raise OIDCDiscoveryError(issuer, "discovery document missing 'jwks_uri'")
    if not discovered_issuer:
        raise OIDCDiscoveryError(issuer, "discovery document missing 'issuer'")

    metadata = OIDCMetadata(issuer=discovered_issuer, jwks_uri=jwks_uri)
    _cache[issuer] = metadata
    return metadata


def clear_cache() -> None:
    """Clear the discovery cache — used in tests only."""
    _cache.clear()
