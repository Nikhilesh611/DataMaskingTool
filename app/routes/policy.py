"""GET /policy endpoint — operator and auditor only."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.auth import require_role
from app.policy.loader import get_policy

router = APIRouter(tags=["policy"])


@router.get("/policy")
async def get_policy_endpoint(
    role: Annotated[str, Depends(require_role("operator", "auditor"))],
) -> JSONResponse:
    policy = get_policy()
    return JSONResponse(policy.model_dump())
