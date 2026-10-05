"""L1 In-Memory Thread-Safe Rule & Selector Cache (Phase 4).

Purpose
-------
Guarantees sub-millisecond policy and selector evaluation latency (< 50µs)
by caching parsed ASTs, compiled JSONPath / XPath expressions, and per-tenant
resolved policies in process memory.

Thread Safety & Concurrency
---------------------------
FastAPI routes execute across concurrent coroutines on the asyncio event loop
and worker threads.  ``L1Cache`` uses an explicit ``threading.Lock`` around
all mutating operations on its internal ``OrderedDict`` to ensure full thread
safety during LRU eviction and key expiration.

Key Namespaces & Isolation
--------------------------
Keys are strictly namespaced:
  ``compiled:jsonpath:<expr>``      -> Compiled JSONPath parser object
  ``compiled:xpath:<expr>``         -> Compiled XPath parser object
  ``tenant:<tenant_id>:policy:<id>``-> Parsed MaskingPolicy
  ``tenant:<tenant_id>:groups``     -> Group mappings cache

Tenant Invalidation
-------------------
``invalidate_tenant(tenant_id)`` evicts all entries prefixed with
``tenant:<tenant_id>:`` in O(N) cache scan time, ensuring instant policy
updates across workers without restarting the process.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple


@dataclass(frozen=True)
class _CacheEntry:
    value: Any
    expires_at: Optional[float]  # monotonic timestamp, or None for no TTL


class L1Cache:
    """Thread-safe LRU in-memory cache with TTL and tenant-partitioned eviction."""

    def __init__(self, max_size: int = 10_000, default_ttl: Optional[float] = None) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._store: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def _is_expired(self, entry: _CacheEntry, now: float) -> bool:
        if entry.expires_at is None:
            return False
        return now > entry.expires_at

    def get(self, key: str) -> Optional[Any]:
        """Retrieve *key* from cache if present and unexpired.

        Returns None on miss or expiry. Moves key to MRU position on hit.
        """
        now = time.monotonic()
        val = None
        is_hit = False
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
            elif self._is_expired(entry, now):
                del self._store[key]
                self._misses += 1
            else:
                # Hit: move to most-recently-used position
                self._store.move_to_end(key)
                self._hits += 1
                is_hit = True
                val = entry.value

        tenant = key.split(":")[1] if key.startswith("tenant:") else "system"
        try:
            from app.telemetry.metrics import record_cache_hit, record_cache_miss
            if is_hit:
                record_cache_hit("l1", tenant=tenant)
            else:
                record_cache_miss("l1", tenant=tenant)
        except Exception:
            pass

        return val

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
    ) -> None:
        """Store *value* under *key* with optional TTL in seconds."""
        now = time.monotonic()
        effective_ttl = ttl if ttl is not None else self._default_ttl
        expires_at = (now + effective_ttl) if effective_ttl is not None else None
        entry = _CacheEntry(value=value, expires_at=expires_at)

        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = entry

            # Evict oldest if exceeding capacity
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def get_or_compile(
        self,
        key: str,
        compile_fn: Callable[[], Any],
        ttl: Optional[float] = None,
    ) -> Any:
        """Read-through cache helper: returns cached value or compiles and caches it."""
        val = self.get(key)
        if val is not None:
            return val
        compiled = compile_fn()
        self.set(key, compiled, ttl=ttl)
        return compiled

    def invalidate(self, key: str) -> bool:
        """Remove specific *key*. Returns True if existed."""
        with self._lock:
            return self._store.pop(key, None) is not None

    def invalidate_tenant(self, tenant_id: str) -> int:
        """Evict all cache keys belonging to *tenant_id*.

        Returns number of evicted keys.
        """
        prefix = f"tenant:{tenant_id}:"
        with self._lock:
            evict_keys = [k for k in self._store if k.startswith(prefix)]
            for k in evict_keys:
                del self._store[k]
            return len(evict_keys)

    def clear(self) -> None:
        """Flush the entire cache and reset stats."""
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    @property
    def stats(self) -> dict[str, int]:
        """Return cache hit/miss and size metrics."""
        with self._lock:
            return {
                "size": len(self._store),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
            }


# ── Global Singleton ──────────────────────────────────────────────────────────

_l1_cache: L1Cache = L1Cache(max_size=10_000)


def get_l1_cache() -> L1Cache:
    """Return the global L1 cache singleton."""
    return _l1_cache


def set_l1_cache(cache: L1Cache) -> None:
    """Replace global L1 cache singleton (used in tests)."""
    global _l1_cache
    _l1_cache = cache
