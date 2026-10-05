"""Phase 6 — Prometheus Metrics Endpoint.

Exposes GET /metrics in standard Prometheus text exposition format for scraping.
"""

from fastapi import APIRouter, Response
from app.telemetry.metrics import get_prometheus_metrics_payload

metrics_router = APIRouter(tags=["Telemetry"])


@metrics_router.get(
    "/metrics",
    summary="Scrape Prometheus Metrics",
    response_class=Response,
)
def prometheus_metrics() -> Response:
    """Returns application metrics formatted for Prometheus scrapers."""
    payload, media_type = get_prometheus_metrics_payload()
    return Response(content=payload, media_type=media_type)
