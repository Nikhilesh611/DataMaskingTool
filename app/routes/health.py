"""GET /health endpoint — no authentication required."""

from __future__ import annotations

import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.adapters.registry import supported_formats
from app.config import get_settings
from app.policy.loader import get_policy

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> JSONResponse:
    settings = get_settings()
    policy = get_policy()

    # Count files in the data directory.
    try:
        file_count = sum(
            1
            for f in os.listdir(settings.data_dir)
            if os.path.isfile(os.path.join(settings.data_dir, f))
        )
    except OSError:
        file_count = -1

    return JSONResponse(
        {
            "status": "ok",
            "policy_version": policy.version,
            "supported_formats": supported_formats(),
            "data_dir": settings.data_dir,
            "file_count": file_count,
        }
    )
