"""Admin Control Plane REST API endpoints.

All administrative management operations (/api/v1/admin/*) require admin authentication
via Bearer session token or X-Admin-API-Key.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.admin.auth import (
    authenticate_admin_credentials,
    invalidate_admin_session,
    require_admin,
)
from app.config import get_settings
from app.exceptions import PolicyValidationError
from app.idp.group_mapper import GroupMapping, get_group_mapping_store
from app.pipeline.runner import run_pipeline
from app.policy.loader import get_policy, load_policy_from_string

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


# ── Pydantic Request Models ───────────────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    username: str
    password: str


class MappingRequest(BaseModel):
    group: str = Field(..., min_length=1, description="IdP Group Name")
    internal_role: str = Field(..., min_length=1, description="Internal Role or Profile")
    priority: int = Field(0, ge=0, description="Priority ordering (lower = higher priority)")


class PolicyUpdateRequest(BaseModel):
    yaml_content: str = Field(..., description="Raw YAML Policy Content")


class SimulateRequest(BaseModel):
    groups: List[str] = Field(..., description="List of IdP group claims from user token")


class SandboxRequest(BaseModel):
    payload: Any = Field(..., description="Sample JSON/string payload to test mask")
    role: str = Field("analyst", description="Role/profile to apply")
    format: str = Field("json", description="Data format (json, xml, yaml)")


# ── Authentication Endpoints ──────────────────────────────────────────────────

@router.post("/login", summary="Admin Login")
async def admin_login(body: AdminLoginRequest) -> Dict[str, Any]:
    token = authenticate_admin_credentials(body.username, body.password)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin username or password.",
        )
    return {
        "status": "success",
        "token": token,
        "token_type": "bearer",
    }


@router.post("/logout", summary="Admin Logout")
async def admin_logout(token: str = Depends(require_admin)) -> Dict[str, str]:
    invalidate_admin_session(token)
    return {"status": "logged_out"}


# ── Group Mapping CRUD Endpoints ──────────────────────────────────────────────

@router.get("/mappings", summary="List Group Mappings")
async def list_mappings(token: str = Depends(require_admin)) -> Dict[str, Any]:
    store = get_group_mapping_store()
    mappings = [asdict(m) for m in store.list_mappings()]
    return {
        "count": len(mappings),
        "mappings": mappings,
    }


@router.post("/mappings", summary="Create or Update Group Mapping")
async def upsert_mapping(
    body: MappingRequest,
    token: str = Depends(require_admin),
) -> Dict[str, Any]:
    store = get_group_mapping_store()
    settings = get_settings()

    mapping = GroupMapping(
        group=body.group.strip(),
        internal_role=body.internal_role.strip(),
        priority=body.priority,
    )

    store.upsert(mapping)

    # Persist to group_mappings.json if configured
    if settings.idp_mappings_path:
        try:
            store.save(settings.idp_mappings_path)
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to persist mapping to file: {exc}",
            )

    return {
        "status": "success",
        "message": f"Mapping for group '{mapping.group}' saved.",
        "mapping": asdict(mapping),
    }


@router.delete("/mappings/{group_name}", summary="Delete Group Mapping")
async def delete_mapping(
    group_name: str,
    token: str = Depends(require_admin),
) -> Dict[str, Any]:
    store = get_group_mapping_store()
    settings = get_settings()

    deleted = store.delete(group_name)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No group mapping found for '{group_name}'.",
        )

    if settings.idp_mappings_path and os.path.exists(settings.idp_mappings_path):
        try:
            store.save(settings.idp_mappings_path)
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to save updated mappings file: {exc}",
            )

    return {
        "status": "success",
        "message": f"Mapping for group '{group_name}' deleted.",
        "group": group_name,
    }


@router.post("/simulate-resolution", summary="Simulate Identity Resolution")
async def simulate_resolution(
    body: SimulateRequest,
    token: str = Depends(require_admin),
) -> Dict[str, Any]:
    store = get_group_mapping_store()
    resolved_role = store.resolve_role(body.groups)

    all_mappings = store.list_mappings()
    input_group_set = set(body.groups)

    evaluations = []
    for m in sorted(all_mappings, key=lambda x: x.priority):
        matched = m.group in input_group_set
        evaluations.append({
            "group": m.group,
            "internal_role": m.internal_role,
            "priority": m.priority,
            "in_user_claims": matched,
            "is_winner": (matched and m.internal_role == resolved_role and resolved_role is not None),
        })

    return {
        "resolved_role": resolved_role,
        "input_groups": body.groups,
        "match_found": resolved_role is not None,
        "evaluations": evaluations,
    }


# ── Policy & Rule Management Endpoints ────────────────────────────────────────

@router.get("/policy", summary="Get Active Policy")
async def get_policy_info(token: str = Depends(require_admin)) -> Dict[str, Any]:
    settings = get_settings()
    policy = get_policy()

    yaml_text = ""
    if os.path.exists(settings.policy_path):
        with open(settings.policy_path, "r", encoding="utf-8") as fh:
            yaml_text = fh.read()

    return {
        "policy_path": settings.policy_path,
        "yaml_content": yaml_text,
        "parsed": policy.model_dump(),
    }


@router.put("/policy", summary="Update Policy YAML")
async def update_policy_info(
    body: PolicyUpdateRequest,
    token: str = Depends(require_admin),
) -> Dict[str, Any]:
    settings = get_settings()

    # Step 1: Validate YAML and syntax using policy loader
    try:
        new_policy = load_policy_from_string(body.yaml_content)
    except PolicyValidationError as exc:
        errors = exc.detail.get("errors", [exc.message]) if isinstance(exc.detail, dict) else [exc.message]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Policy validation failed.",
                "errors": errors,
            },
        )

    # Step 2: Persist to file
    try:
        with open(settings.policy_path, "w", encoding="utf-8") as fh:
            fh.write(body.yaml_content)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to write policy file: {exc}",
        )

    # Step 3: Update global in-memory policy singleton
    from app.policy import loader as pl_mod
    pl_mod._policy = new_policy

    return {
        "status": "success",
        "message": "Policy updated and hot-reloaded successfully.",
        "parsed": new_policy.model_dump(),
    }


# ── Masking Sandbox / Dry-Run Endpoint ────────────────────────────────────────

@router.post("/sandbox", summary="Payload Masking Sandbox")
async def sandbox_mask(
    body: SandboxRequest,
    token: str = Depends(require_admin),
) -> Dict[str, Any]:
    policy = get_policy()
    fmt = body.format.lower().strip()

    if fmt not in ("json", "xml", "yaml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Supported formats for sandbox are 'json', 'xml', 'yaml'.",
        )

    # Format payload bytes
    if isinstance(body.payload, (dict, list)):
        raw_bytes = json.dumps(body.payload, indent=2).encode("utf-8")
    elif isinstance(body.payload, str):
        raw_bytes = body.payload.encode("utf-8")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a string or JSON object.",
        )

    try:
        result = run_pipeline(raw_bytes, fmt, policy, body.role)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Masking execution error: {exc}",
        )

    try:
        masked_str = result.output_bytes.decode("utf-8")
        if fmt == "json":
            masked_parsed = json.loads(masked_str)
        else:
            masked_parsed = masked_str
    except Exception:
        masked_parsed = result.output_bytes.decode("utf-8", errors="replace")

    return {
        "role_applied": body.role,
        "format": fmt,
        "masked_output": masked_parsed,
        "metrics": {
            "scopes_evaluated": result.scopes_evaluated,
            "scopes_dropped": result.scopes_dropped,
            "profiles_applied": result.profiles_applied,
            "conflict_count": result.conflict_count,
            "uncovered_count": result.uncovered_count,
        },
    }
