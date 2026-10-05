"""JWKS Client — fetches and caches JSON Web Key Sets from the IdP.

Caching strategy:
    JWKS are expensive to fetch (network round-trip) and rarely change.
    We keep a simple in-memory cache keyed by ``(tenant_id, jwks_uri)``.

    Partitioning by tenant_id is a security invariant: Tenant A's public keys
    must NEVER be used to verify Tenant B's tokens, even if both happen to use
    the same JWKS URI (unlikely in production, but the cache must be safe
    regardless).

    TTL is configurable (IDP_JWKS_CACHE_TTL_SECONDS, default 300 s).
    The TTL is a *reasonable operational default*, not a hard security
    requirement — operators in high-security environments can shorten it.

Key rotation handling (kid miss):
    When a JWT's ``kid`` is not found in the cached keyset, we refresh the
    JWKS once before rejecting the token.  This handles the common case where
    the IdP has rotated signing keys since our last fetch.
    If the ``kid`` is still absent after the forced refresh, we raise
    JWKSKeyNotFoundError (→ HTTP 401) — the token is not valid with any
    currently trusted key.

    We do NOT implement background refresh threads.  Refresh is triggered
    lazily on-demand to keep the codebase simple and easy to reason about.

Key format:
    We return the raw JWKS ``keys`` list.  PyJWT's PyJWKClient is the
    alternative, but it requires a different code path.  Instead we keep
    the JWKS as raw dicts and let jwt.decode() receive the matching JWK
    object via PyJWT's ``PyJWK`` helper.  This keeps signature verification
    entirely within PyJWT — no custom cryptographic code here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.exceptions import MaskingAPIError


# ── Exceptions ────────────────────────────────────────────────────────────────

class JWKSFetchError(MaskingAPIError):
    """JWKS endpoint could not be reached or returned an error. → HTTP 503"""

    def __init__(self, jwks_uri: str, reason: str) -> None:
        super().__init__(
            f"Failed to fetch JWKS from '{jwks_uri}': {reason}. "
            "The IdP may be temporarily unreachable.",
            detail={"jwks_uri": jwks_uri, "reason": reason},
        )


class JWKSKeyNotFoundError(MaskingAPIError):
    """The JWT's kid does not match any key in the JWKS, even after refresh. → HTTP 401"""

    def __init__(self, kid: str, jwks_uri: str) -> None:
        super().__init__(
            f"No key with kid='{kid}' found in JWKS at '{jwks_uri}'. "
            "The token may have been issued with a revoked or unknown key.",
            detail={"kid": kid, "jwks_uri": jwks_uri},
        )


# ── Cache entry ───────────────────────────────────────────────────────────────

@dataclass
class _CacheEntry:
    keys: list[dict[str, Any]]  # raw JWK dicts from the JWKS ``keys`` array
    fetched_at: float = field(default_factory=time.monotonic)


# ── JWKS Cache ────────────────────────────────────────────────────────────────

class JWKSCache:
    """Thread-safe-enough in-memory JWKS cache for asyncio single-process use.

    FastAPI/uvicorn runs in a single asyncio event loop per worker, so a plain
    dict is safe here — no concurrent writes from multiple threads.

    Cache key
    ---------
    The cache is keyed by ``(tenant_id, jwks_uri)`` — a 2-tuple — so that two
    tenants sharing the same JWKS URI (unlikely, but possible) can never share
    key material.  Single-tenant callers pass an empty string for ``tenant_id``.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        # Key: (tenant_id, jwks_uri) → _CacheEntry
        self._store: dict[tuple[str, str], _CacheEntry] = {}

    def _is_expired(self, entry: _CacheEntry) -> bool:
        return (time.monotonic() - entry.fetched_at) > self._ttl

    def _key(self, jwks_uri: str, tenant_id: str = "") -> tuple[str, str]:
        return (tenant_id, jwks_uri)

    def get_cached(
        self, jwks_uri: str, tenant_id: str = ""
    ) -> list[dict[str, Any]] | None:
        """Return cached keys for ``(tenant_id, jwks_uri)`` if present and not expired."""
        entry = self._store.get(self._key(jwks_uri, tenant_id))
        if entry is None or self._is_expired(entry):
            return None
        return entry.keys

    def set(
        self, jwks_uri: str, keys: list[dict[str, Any]], tenant_id: str = ""
    ) -> None:
        """Store *keys* under the ``(tenant_id, jwks_uri)`` slot."""
        self._store[self._key(jwks_uri, tenant_id)] = _CacheEntry(keys=keys)

    def invalidate(self, jwks_uri: str, tenant_id: str = "") -> None:
        """Evict the entry for ``(tenant_id, jwks_uri)``."""
        self._store.pop(self._key(jwks_uri, tenant_id), None)

    def invalidate_tenant(self, tenant_id: str) -> None:
        """Evict ALL cached key-sets belonging to *tenant_id*.

        Called when a tenant's IdP configuration changes so no stale public
        keys remain for that tenant.
        """
        stale = [k for k in self._store if k[0] == tenant_id]
        for k in stale:
            del self._store[k]

    def clear(self) -> None:
        """Clear the entire cache — used in tests only."""
        self._store.clear()


# ── Module-level singleton ────────────────────────────────────────────────────
# TTL is set during startup from settings.  Tests can replace this.

_cache: JWKSCache = JWKSCache()


def get_jwks_cache() -> JWKSCache:
    return _cache


def set_jwks_cache(cache: JWKSCache) -> None:
    """Replace the module-level cache singleton — used in tests."""
    global _cache
    _cache = cache


# ── JWKS fetch ────────────────────────────────────────────────────────────────

async def _fetch_jwks_raw(jwks_uri: str) -> list[dict[str, Any]]:
    """Fetch and return the raw ``keys`` list from a JWKS endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            doc = resp.json()
    except httpx.HTTPStatusError as exc:
        raise JWKSFetchError(jwks_uri, f"HTTP {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise JWKSFetchError(jwks_uri, str(exc)) from exc
    except Exception as exc:
        raise JWKSFetchError(jwks_uri, str(exc)) from exc

    keys = doc.get("keys")
    if not isinstance(keys, list):
        raise JWKSFetchError(jwks_uri, "JWKS response missing 'keys' array")
    return keys


# ── Public API ────────────────────────────────────────────────────────────────

async def get_signing_key(
    jwks_uri: str,
    kid: str | None,
    *,
    tenant_id: str = "",
) -> dict[str, Any]:
    """Return the JWK dict for *kid* from *jwks_uri*, using the cache.

    Resolution order
    ----------------
    1. Check in-memory cache under ``(tenant_id, jwks_uri)`` (if not expired).
    2. If kid is not in cache, force-refresh once from the IdP.
    3. If kid is still missing after refresh → raise JWKSKeyNotFoundError.

    Parameters
    ----------
    jwks_uri:
        The JWKS endpoint URL.
    kid:
        The ``kid`` header from the JWT.  If ``None`` (JWT has no kid), the
        first key in the set is returned — supports IdPs with a single key.
    tenant_id:
        Tenant identifier used as the cache partition key.  Defaults to ``""``
        for backward-compatible single-tenant callers.

    Raises
    ------
    JWKSFetchError
        When the JWKS endpoint is unreachable or returns an error.
    JWKSKeyNotFoundError
        When no key matching *kid* is found after a forced refresh.
    """
    cache = _cache

    def _find_key(keys: list[dict[str, Any]]) -> dict[str, Any] | None:
        if kid is None:
            return keys[0] if keys else None
        return next((k for k in keys if k.get("kid") == kid), None)

    # ── Step 1: Check tenant-partitioned cache ────────────────────────────────
    cached_keys = cache.get_cached(jwks_uri, tenant_id=tenant_id)
    if cached_keys is not None:
        key = _find_key(cached_keys)
        if key is not None:
            return key
        # kid miss — fall through to refresh

    # ── Step 2: Force fetch (cache miss or kid miss) ──────────────────────────
    fresh_keys = await _fetch_jwks_raw(jwks_uri)
    cache.set(jwks_uri, fresh_keys, tenant_id=tenant_id)

    key = _find_key(fresh_keys)
    if key is None:
        raise JWKSKeyNotFoundError(kid or "<no kid>", jwks_uri)
    return key
