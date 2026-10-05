"""L2 Redis Cache & Distributed Token-Bucket Rate Limiter (Phase 4).

Features
--------
1. Async Redis connection manager with graceful in-memory fallback.
   If Redis is unconfigured or unreachable, the system continues serving
   requests safely using local in-memory fallbacks with structured warnings.
2. Distributed Token-Bucket Rate Limiting per tenant.
   When Redis is connected, token buckets are shared across all worker
   processes and instances, enforcing enterprise multi-tenant rate quotas.
3. FastAPI dependency ``check_tenant_rate_limit`` providing RFC-compliant
   ``X-RateLimit-*`` and ``Retry-After`` headers on 429 Too Many Requests.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from fastapi import Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from app.exceptions import MaskingAPIError
from app.logging_config import get_app_logger

try:
    import redis.asyncio as aioredis
    from redis.exceptions import RedisError
    _REDIS_AVAILABLE = True
except ImportError:  # pragma: no cover
    aioredis = None
    RedisError = Exception
    _REDIS_AVAILABLE = False


# ── Exceptions ────────────────────────────────────────────────────────────────

class RateLimitExceededError(MaskingAPIError):
    """Raised when a tenant exceeds their allotted request quota. -> HTTP 429"""

    def __init__(self, tenant_id: str, limit: int, retry_after: int) -> None:
        super().__init__(
            f"Rate limit exceeded for tenant '{tenant_id}'. Limit: {limit} req/min. "
            f"Retry after {retry_after} seconds.",
            detail={"tenant_id": tenant_id, "limit": limit, "retry_after": retry_after},
        )
        self.retry_after = retry_after
        self.limit = limit


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int


# ── In-Memory Token Bucket Fallback ───────────────────────────────────────────

class _LocalTokenBucket:
    """Thread-safe in-memory token bucket used when Redis is unavailable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # tenant_id -> (tokens: float, last_updated: float)
        self._buckets: Dict[str, Tuple[float, float]] = {}

    def check(self, tenant_id: str, limit_per_minute: int, cost: int = 1) -> RateLimitResult:
        now = time.monotonic()
        refill_rate = limit_per_minute / 60.0  # tokens per second

        with self._lock:
            tokens, last_updated = self._buckets.get(tenant_id, (float(limit_per_minute), now))
            # Refill tokens based on elapsed time
            elapsed = now - last_updated
            tokens = min(float(limit_per_minute), tokens + elapsed * refill_rate)

            if tokens >= cost:
                tokens -= cost
                self._buckets[tenant_id] = (tokens, now)
                reset_seconds = int((1.0 - (tokens / limit_per_minute)) * 60) if limit_per_minute > 0 else 0
                return RateLimitResult(
                    allowed=True,
                    limit=limit_per_minute,
                    remaining=max(0, int(tokens)),
                    reset_seconds=max(1, reset_seconds),
                )
            else:
                self._buckets[tenant_id] = (tokens, now)
                # Time until at least 1 token is available
                needed = cost - tokens
                reset_seconds = max(1, int(needed / refill_rate))
                return RateLimitResult(
                    allowed=False,
                    limit=limit_per_minute,
                    remaining=0,
                    reset_seconds=reset_seconds,
                )

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


# ── Redis Client Manager ──────────────────────────────────────────────────────

class RedisManager:
    """Manages the async Redis connection pool with health probes and failover."""

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self._url = redis_url or os.environ.get("REDIS_URL", "").strip()
        self._client: Optional[aioredis.Redis] = None
        self._is_connected = False
        self._local_fallback = _LocalTokenBucket()

    @property
    def is_connected(self) -> bool:
        return self._is_connected and self._client is not None

    async def connect(self) -> bool:
        """Establish Redis connection. Returns True on success, False on fallback."""
        if not _REDIS_AVAILABLE or not self._url:
            self._is_connected = False
            return False

        try:
            self._client = aioredis.from_url(
                self._url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )
            # Probe connection
            await self._client.ping()
            self._is_connected = True
            logger = get_app_logger()
            logger.info("Connected to Redis L2 cache at %s", self._url)
            return True
        except Exception as exc:
            self._is_connected = False
            logger = get_app_logger()
            logger.warning(
                "Redis connection failed (%s); operating in local fallback mode.", exc
            )
            return False

    async def disconnect(self) -> None:
        """Close connection pool cleanly."""
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
            self._is_connected = False

    def get_raw_client(self) -> Optional[aioredis.Redis]:
        return self._client if self.is_connected else None

    # ── High-Level Cache Operations ───────────────────────────────────────────

    async def get(self, key: str) -> Optional[str]:
        if not self.is_connected:
            return None
        try:
            return await self._client.get(key)
        except Exception:
            return None

    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> bool:
        if not self.is_connected:
            return False
        try:
            if ttl_seconds:
                await self._client.setex(key, ttl_seconds, value)
            else:
                await self._client.set(key, value)
            return True
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        if not self.is_connected:
            return False
        try:
            return bool(await self._client.delete(key))
        except Exception:
            return False

    async def publish(self, channel: str, message: str) -> int:
        if not self.is_connected:
            return 0
        try:
            return await self._client.publish(channel, message)
        except Exception:
            return 0


# ── Token-Bucket Rate Limiter ─────────────────────────────────────────────────

class TokenBucketRateLimiter:
    """Enterprise rate limiter supporting both distributed Redis and local fallback.

    Default Tier Quotas:
    - free:       20 requests / minute
    - standard:   100 requests / minute
    - enterprise: 1000 requests / minute
    """

    DEFAULT_TIERS: Dict[str, int] = {
        "free": 20,
        "standard": 100,
        "enterprise": 1000,
    }

    def __init__(
        self,
        redis_manager: RedisManager,
        custom_tier_quotas: Optional[Dict[str, int]] = None,
    ) -> None:
        self._redis_mgr = redis_manager
        self._tiers = {**self.DEFAULT_TIERS, **(custom_tier_quotas or {})}
        self._local_fallback = _LocalTokenBucket()

    def get_tier_limit(self, tier: str) -> int:
        return self._tiers.get(tier.lower(), self.DEFAULT_TIERS["standard"])

    async def check_rate_limit(
        self,
        tenant_id: str,
        tier: str = "standard",
        cost: int = 1,
    ) -> RateLimitResult:
        """Evaluate if *tenant_id* is within their rate quota."""
        limit_per_minute = self.get_tier_limit(tier)

        if not self._redis_mgr.is_connected:
            # Local in-memory fallback
            return self._local_fallback.check(tenant_id, limit_per_minute, cost)

        # Redis-backed sliding window / token bucket
        redis = self._redis_mgr.get_raw_client()
        key = f"ratelimit:{tenant_id}"
        now = time.time()
        window_seconds = 60

        try:
            pipe = redis.pipeline()
            # Remove timestamps outside current 60s sliding window
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            # Count current events in window
            pipe.zcard(key)
            results = await pipe.execute()
            current_count = results[1]

            if current_count + cost <= limit_per_minute:
                # Allow and record timestamp
                add_pipe = redis.pipeline()
                for i in range(cost):
                    add_pipe.zadd(key, {f"{now}-{i}": now})
                add_pipe.expire(key, window_seconds)
                await add_pipe.execute()

                remaining = max(0, limit_per_minute - (current_count + cost))
                return RateLimitResult(
                    allowed=True,
                    limit=limit_per_minute,
                    remaining=remaining,
                    reset_seconds=window_seconds,
                )
            else:
                # Blocked
                return RateLimitResult(
                    allowed=False,
                    limit=limit_per_minute,
                    remaining=0,
                    reset_seconds=window_seconds,
                )
        except Exception as exc:
            logger = get_app_logger()
            logger.warning("Redis rate limit query failed (%s); using local fallback", exc)
            return self._local_fallback.check(tenant_id, limit_per_minute, cost)


# ── Singletons & Dependencies ─────────────────────────────────────────────────

_redis_manager = RedisManager()
_rate_limiter = TokenBucketRateLimiter(_redis_manager)


def get_redis_manager() -> RedisManager:
    return _redis_manager


def get_rate_limiter() -> TokenBucketRateLimiter:
    return _rate_limiter


def set_rate_limiter(limiter: TokenBucketRateLimiter) -> None:
    """Override rate limiter in test fixtures."""
    global _rate_limiter
    _rate_limiter = limiter


async def enforce_tenant_rate_limit(
    request: Request,
    response: Response,
) -> None:
    """FastAPI dependency to enforce rate limits and attach RFC rate-limit headers."""
    # Read tenant context attached by resolve_tenant if present, or resolve lazily
    tenant_ctx = getattr(request.state, "tenant_context", None)
    if tenant_ctx is None:
        try:
            from app.auth.tenant_resolver import resolve_tenant_optional
            # resolve_tenant_optional takes request as first arg
            tenant_ctx = await resolve_tenant_optional(request)
        except Exception:
            tenant_ctx = None
    tenant_id = tenant_ctx.tenant_id if tenant_ctx else "anonymous"

    # Read optional tier header or default to standard
    tier = request.headers.get("X-Tenant-Tier", "standard")
    limiter = get_rate_limiter()
    result = await limiter.check_rate_limit(tenant_id, tier=tier)

    # Attach standard headers
    response.headers["X-RateLimit-Limit"] = str(result.limit)
    response.headers["X-RateLimit-Remaining"] = str(result.remaining)
    response.headers["X-RateLimit-Reset"] = str(result.reset_seconds)

    if not result.allowed:
        response.headers["Retry-After"] = str(result.reset_seconds)
        raise RateLimitExceededError(
            tenant_id=tenant_id,
            limit=result.limit,
            retry_after=result.reset_seconds,
        )
