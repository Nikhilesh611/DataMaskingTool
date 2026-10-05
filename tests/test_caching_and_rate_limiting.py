"""Phase 4 tests: Two-Tier Caching, Distributed Rate Limiting & Real-Time Invalidation.

Test Suites
-----------
TestL1Cache
    - Basic get/set roundtrip
    - Read-through get_or_compile
    - Sub-50µs latency benchmark on warm cache hit
    - TTL expiration
    - LRU eviction when capacity exceeded
    - Tenant-partitioned eviction (invalidate_tenant)
    - Thread concurrency safety

TestTokenBucketRateLimiting
    - Tier limits (free, standard, enterprise)
    - Token consumption and depletion
    - Rate quota exceeded returns allowed=False
    - Cross-tenant isolation (Tenant A quota exhausted does not affect Tenant B)
    - Token refill over time
    - FastAPI dependency attaches X-RateLimit-* headers
    - Exceeding limit raises RateLimitExceededError (HTTP 429) with Retry-After header

TestRedisManagerAndFallback
    - Graceful fallback when Redis is unconfigured or unreachable
    - Safe cache get/set/delete without unhandled exceptions in fallback mode

TestPubSubMesh
    - broadcast_invalidation evicts local L1 and JWKS caches
    - Message processing evicts target tenant only
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.cache.l1_cache import L1Cache, get_l1_cache, set_l1_cache
from app.cache.pubsub import INVALIDATION_CHANNEL, PubSubMesh, get_pubsub_mesh
from app.cache.redis_client import (
    RateLimitExceededError,
    RateLimitResult,
    RedisManager,
    TokenBucketRateLimiter,
    _LocalTokenBucket,
    enforce_tenant_rate_limit,
    get_rate_limiter,
    set_rate_limiter,
)
from app.idp.jwks_client import JWKSCache, set_jwks_cache


# ═════════════════════════════════════════════════════════════════════════════
# TestL1Cache
# ═════════════════════════════════════════════════════════════════════════════

class TestL1Cache:
    def test_basic_get_set(self):
        cache = L1Cache(max_size=100)
        cache.set("compiled:jsonpath:$.records[*]", "parsed_selector")
        assert cache.get("compiled:jsonpath:$.records[*]") == "parsed_selector"

    def test_get_missing_returns_none(self):
        cache = L1Cache(max_size=100)
        assert cache.get("nonexistent_key") is None

    def test_get_or_compile_read_through(self):
        cache = L1Cache(max_size=100)
        compiled_count = 0

        def compile_fn():
            nonlocal compiled_count
            compiled_count += 1
            return "compiled_ast"

        # First call: compiles
        res1 = cache.get_or_compile("xpath://patient", compile_fn)
        assert res1 == "compiled_ast"
        assert compiled_count == 1

        # Second call: cache hit, compile_fn not called
        res2 = cache.get_or_compile("xpath://patient", compile_fn)
        assert res2 == "compiled_ast"
        assert compiled_count == 1

    def test_sub_50_microsecond_hit_latency(self):
        """Warm cache lookup must execute in < 50 microseconds."""
        cache = L1Cache(max_size=1000)
        cache.set("test_key", {"rules": [1, 2, 3]})

        # Warm up
        for _ in range(10):
            cache.get("test_key")

        iterations = 10_000
        start = time.perf_counter()
        for _ in range(iterations):
            cache.get("test_key")
        elapsed = time.perf_counter() - start

        avg_latency_us = (elapsed / iterations) * 1_000_000
        assert avg_latency_us < 50.0, f"Average lookup was {avg_latency_us:.2f}µs, expected < 50µs"

    def test_ttl_expiration(self):
        cache = L1Cache(max_size=100)
        cache.set("ephemeral", "data", ttl=0.04)  # 40ms TTL
        assert cache.get("ephemeral") == "data"

        time.sleep(0.08)
        assert cache.get("ephemeral") is None

    def test_lru_eviction(self):
        cache = L1Cache(max_size=3)
        cache.set("k1", 1)
        cache.set("k2", 2)
        cache.set("k3", 3)

        # Access k1 to make it most-recently-used (MRU); k2 is now LRU
        cache.get("k1")

        # Insert k4, should evict k2
        cache.set("k4", 4)
        assert cache.get("k2") is None
        assert cache.get("k1") == 1
        assert cache.get("k3") == 3
        assert cache.get("k4") == 4

    def test_invalidate_tenant(self):
        cache = L1Cache(max_size=100)
        tenant_a = "tenant-aaa"
        tenant_b = "tenant-bbb"

        cache.set(f"tenant:{tenant_a}:policy:001", "policy_a")
        cache.set(f"tenant:{tenant_a}:groups", ["admin"])
        cache.set(f"tenant:{tenant_b}:policy:002", "policy_b")
        cache.set("global:compiled:xpath", "global_xpath")

        evicted = cache.invalidate_tenant(tenant_a)
        assert evicted == 2
        assert cache.get(f"tenant:{tenant_a}:policy:001") is None
        assert cache.get(f"tenant:{tenant_a}:groups") is None
        # Tenant B and global keys must remain intact
        assert cache.get(f"tenant:{tenant_b}:policy:002") == "policy_b"
        assert cache.get("global:compiled:xpath") == "global_xpath"

    def test_thread_concurrency_safety(self):
        cache = L1Cache(max_size=100)
        errors = []

        def worker(w_id: int):
            try:
                for i in range(200):
                    key = f"key_{w_id}_{i % 10}"
                    cache.set(key, i)
                    val = cache.get(key)
                    if val is not None and val != i:
                        errors.append(f"Mismatch in worker {w_id}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread safety errors: {errors}"


# ═════════════════════════════════════════════════════════════════════════════
# TestTokenBucketRateLimiting
# ═════════════════════════════════════════════════════════════════════════════

class TestTokenBucketRateLimiting:
    def test_tier_limits_assigned_correctly(self):
        mgr = RedisManager()
        limiter = TokenBucketRateLimiter(mgr)
        assert limiter.get_tier_limit("free") == 20
        assert limiter.get_tier_limit("standard") == 100
        assert limiter.get_tier_limit("enterprise") == 1000
        # Unknown tier defaults to standard
        assert limiter.get_tier_limit("custom_tier") == 100

    @pytest.mark.asyncio
    async def test_token_consumption_and_depletion(self):
        mgr = RedisManager()
        # Custom tier with 3 requests per minute for fast depletion test
        limiter = TokenBucketRateLimiter(mgr, custom_tier_quotas={"test_tier": 3})

        tenant_id = "tenant-test-deplete"
        r1 = await limiter.check_rate_limit(tenant_id, tier="test_tier")
        assert r1.allowed is True
        assert r1.remaining == 2

        r2 = await limiter.check_rate_limit(tenant_id, tier="test_tier")
        assert r2.allowed is True
        assert r2.remaining == 1

        r3 = await limiter.check_rate_limit(tenant_id, tier="test_tier")
        assert r3.allowed is True
        assert r3.remaining == 0

        # Fourth request: should be blocked
        r4 = await limiter.check_rate_limit(tenant_id, tier="test_tier")
        assert r4.allowed is False
        assert r4.remaining == 0
        assert r4.reset_seconds > 0

    @pytest.mark.asyncio
    async def test_tenant_rate_isolation(self):
        """Tenant A exhausting quota must not affect Tenant B."""
        mgr = RedisManager()
        limiter = TokenBucketRateLimiter(mgr, custom_tier_quotas={"small": 1})

        # Tenant A uses quota
        r_a1 = await limiter.check_rate_limit("tenant_a", tier="small")
        assert r_a1.allowed is True
        r_a2 = await limiter.check_rate_limit("tenant_a", tier="small")
        assert r_a2.allowed is False

        # Tenant B must still have quota
        r_b = await limiter.check_rate_limit("tenant_b", tier="small")
        assert r_b.allowed is True

    @pytest.mark.asyncio
    async def test_enforce_tenant_rate_limit_headers_and_exception(self):
        mgr = RedisManager()
        limiter = TokenBucketRateLimiter(mgr, custom_tier_quotas={"single": 1})
        set_rate_limiter(limiter)

        req_scope = {
            "type": "http",
            "headers": [(b"x-tenant-tier", b"single")],
            "state": {},
        }
        req = Request(req_scope)
        resp = Response()

        # First request succeeds and sets X-RateLimit headers
        await enforce_tenant_rate_limit(req, resp)
        assert resp.headers["X-RateLimit-Limit"] == "1"
        assert resp.headers["X-RateLimit-Remaining"] == "0"
        assert "X-RateLimit-Reset" in resp.headers

        # Second request raises RateLimitExceededError (HTTP 429)
        with pytest.raises(RateLimitExceededError) as exc_info:
            await enforce_tenant_rate_limit(req, resp)

        assert exc_info.value.retry_after > 0
        assert resp.headers["Retry-After"] == str(exc_info.value.retry_after)


# ═════════════════════════════════════════════════════════════════════════════
# TestRedisManagerAndFallback
# ═════════════════════════════════════════════════════════════════════════════

class TestRedisManagerAndFallback:
    @pytest.mark.asyncio
    async def test_unconfigured_redis_enters_fallback_mode(self):
        mgr = RedisManager(redis_url="")
        connected = await mgr.connect()
        assert connected is False
        assert mgr.is_connected is False
        assert mgr.get_raw_client() is None

    @pytest.mark.asyncio
    async def test_safe_operations_in_fallback_mode(self):
        mgr = RedisManager(redis_url="")
        await mgr.connect()

        # None of these should raise unhandled exceptions
        assert await mgr.get("any_key") is None
        assert await mgr.set("any_key", "val") is False
        assert await mgr.delete("any_key") is False
        assert await mgr.publish("channel", "msg") == 0


# ═════════════════════════════════════════════════════════════════════════════
# TestPubSubMesh
# ═════════════════════════════════════════════════════════════════════════════

class TestPubSubMesh:
    @pytest.mark.asyncio
    async def test_broadcast_invalidation_clears_local_caches(self):
        l1 = L1Cache(max_size=100)
        set_l1_cache(l1)
        jwks = JWKSCache()
        set_jwks_cache(jwks)

        tenant_id = "tenant-target-inval"
        l1.set(f"tenant:{tenant_id}:policy", "policy_content")
        l1.set(f"tenant:other-tenant:policy", "other_content")
        jwks.set("https://idp.example/jwks", [{"kid": "k1"}], tenant_id=tenant_id)
        jwks.set("https://idp.example/jwks", [{"kid": "k2"}], tenant_id="other-tenant")

        mesh = PubSubMesh(RedisManager(redis_url=""))
        await mesh.broadcast_invalidation(tenant_id)

        # Target tenant evicted from both caches
        assert l1.get(f"tenant:{tenant_id}:policy") is None
        assert jwks.get_cached("https://idp.example/jwks", tenant_id=tenant_id) is None

        # Other tenant untouched
        assert l1.get("tenant:other-tenant:policy") == "other_content"
        assert jwks.get_cached("https://idp.example/jwks", tenant_id="other-tenant") == [{"kid": "k2"}]
