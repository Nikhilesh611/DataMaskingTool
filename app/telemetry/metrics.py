"""Phase 6 — Prometheus Metrics & Telemetry Engine.

Tracks:
1. ``masking_requests_total`` (Counter) — Labels: [tenant, role, format, status]
2. ``masking_latency_seconds`` (Histogram) — Labels: [tenant, role, format]
3. ``masking_cache_hits_total`` (Counter) — Labels: [cache_type, tenant]
4. ``masking_cache_misses_total`` (Counter) — Labels: [cache_type, tenant]
5. ``masking_rate_limit_exceeded_total`` (Counter) — Labels: [tenant]
"""

from __future__ import annotations

import time
from typing import Optional
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

# ── Metric Definitions ────────────────────────────────────────────────────────

REQUESTS_TOTAL = Counter(
    "masking_requests_total",
    "Total number of masking API requests processed.",
    ["tenant", "role", "format", "status"],
)

REQUEST_LATENCY = Histogram(
    "masking_latency_seconds",
    "Latency of masking requests in seconds.",
    ["tenant", "role", "format"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

CACHE_HITS = Counter(
    "masking_cache_hits_total",
    "Total number of cache hits in the masking engine.",
    ["cache_type", "tenant"],
)

CACHE_MISSES = Counter(
    "masking_cache_misses_total",
    "Total number of cache misses requiring compilation or remote fetch.",
    ["cache_type", "tenant"],
)

RATE_LIMIT_EXCEEDED = Counter(
    "masking_rate_limit_exceeded_total",
    "Total number of requests rejected due to rate quota exhaustion.",
    ["tenant"],
)


# ── Helper Functions ──────────────────────────────────────────────────────────

def record_request_metric(
    tenant: str,
    role: str,
    fmt: str,
    status: str,
    duration_s: float,
) -> None:
    """Record request completion counter and duration histogram."""
    REQUESTS_TOTAL.labels(tenant=tenant, role=role, format=fmt, status=status).inc()
    REQUEST_LATENCY.labels(tenant=tenant, role=role, format=fmt).observe(duration_s)


def record_cache_hit(cache_type: str, tenant: str = "default") -> None:
    """Record a cache hit in L1 or JWKS cache."""
    CACHE_HITS.labels(cache_type=cache_type, tenant=tenant).inc()


def record_cache_miss(cache_type: str, tenant: str = "default") -> None:
    """Record a cache miss in L1 or JWKS cache."""
    CACHE_MISSES.labels(cache_type=cache_type, tenant=tenant).inc()


def record_rate_limit_exceeded(tenant: str) -> None:
    """Record rate limit block."""
    RATE_LIMIT_EXCEEDED.labels(tenant=tenant).inc()


def get_prometheus_metrics_payload() -> tuple[bytes, str]:
    """Generate Prometheus exposition text and content-type."""
    return generate_latest(), CONTENT_TYPE_LATEST
