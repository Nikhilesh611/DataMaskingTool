"""Two-tier caching, distributed rate limiting, and real-time invalidation.

Modules
-------
l1_cache     — In-memory thread-safe LRU rule & selector cache (< 50µs access).
redis_client — L2 Redis client manager & distributed token-bucket rate limiter.
pubsub       — Real-time Redis pub/sub invalidation mesh across worker nodes.
"""

from __future__ import annotations

from app.cache.l1_cache import L1Cache, get_l1_cache, set_l1_cache
from app.cache.pubsub import PubSubMesh, get_pubsub_mesh, set_pubsub_mesh
from app.cache.redis_client import (
    RateLimitExceededError,
    RateLimitResult,
    RedisManager,
    TokenBucketRateLimiter,
    enforce_tenant_rate_limit,
    get_rate_limiter,
    get_redis_manager,
    set_rate_limiter,
)

__all__ = [
    "L1Cache",
    "get_l1_cache",
    "set_l1_cache",
    "RedisManager",
    "get_redis_manager",
    "TokenBucketRateLimiter",
    "get_rate_limiter",
    "set_rate_limiter",
    "RateLimitResult",
    "RateLimitExceededError",
    "enforce_tenant_rate_limit",
    "PubSubMesh",
    "get_pubsub_mesh",
    "set_pubsub_mesh",
]
