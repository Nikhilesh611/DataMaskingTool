"""Phase 3 — In-memory masking endpoints.

POST /v1/mask          — inline raw payload (JSON/XML/YAML in body).
POST /v1/mask/file     — multipart file upload; returns masked file as download.

Both endpoints share the same multi-tenant auth chain from Phase 2:
    resolve_tenant → validate_jwt_for_tenant → resolve_role_for_tenant

Zero disk I/O in the masking path — payloads live entirely in memory.

Auth modes
----------
Both endpoints use the same ``_resolve_role_multi_tenant`` dependency that
was introduced in Phase 2.  Local-mode deployments continue to work through
the fallback path in ``resolve_tenant``.
"""

from __future__ import annotations

import mimetypes
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

import time
from app.audit.ledger import get_audit_ledger
from app.auth.tenant_resolver import TenantContext, resolve_tenant
from app.cache.redis_client import RateLimitExceededError, RateLimitResult, get_rate_limiter
from app.config import get_settings
from app.db.session import get_session
from app.exceptions import (
    AuditLogWriteError,
    AuthenticationError,
    AuthorizationError,
    UnsupportedFormatError,
)
from app.idp.group_mapper import (
    resolve_role_and_policy_for_tenant,
    resolve_role_for_tenant,
)
from app.idp.jwt_validator import extract_groups, validate_jwt_for_tenant
from app.logging_config import get_app_logger, request_id_var
from app.pipeline.runner import PipelineResult, run_pipeline
from app.policy.loader import get_policy
from app.schemas.mask import InlineMaskRequest
from app.telemetry.metrics import record_rate_limit_exceeded, record_request_metric


router = APIRouter(prefix="/v1")

_CONTENT_TYPES: dict[str, str] = {
    "xml":  "application/xml",
    "json": "application/json",
    "yaml": "application/yaml",
}

_MIME_TO_FMT: dict[str, str] = {
    "application/json":  "json",
    "text/json":         "json",
    "application/xml":   "xml",
    "text/xml":          "xml",
    "application/yaml":  "yaml",
    "text/yaml":         "yaml",
    "text/x-yaml":       "yaml",
    "application/x-yaml": "yaml",
}

_EXT_TO_FMT: dict[str, str] = {
    ".json": "json",
    ".xml":  "xml",
    ".yaml": "yaml",
    ".yml":  "yaml",
}

_http_bearer = HTTPBearer(auto_error=False)


# ── Shared multi-tenant auth dependency ──────────────────────────────────────

async def _resolve_role_multi_tenant(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_http_bearer),
    tenant: TenantContext = Depends(resolve_tenant),
    db: AsyncSession = Depends(get_session),
) -> str:
    """Validate API Key or JWT for the resolved tenant and return the internal masking role."""
    # ── Path A: Direct API Key authentication (Solo developer / microservice) ─
    if hasattr(request.state, "api_key_role") and request.state.api_key_role:
        internal_role = request.state.api_key_role
        from sqlalchemy import select
        from app.db.models import MaskingPolicy
        from app.policy.loader import load_policy_from_string

        stmt = (
            select(MaskingPolicy)
            .where(MaskingPolicy.tenant_id == tenant.tenant_id)
            .where(MaskingPolicy.name == internal_role)
            .where(MaskingPolicy.is_active.is_(True))
        )
        p_res = await db.execute(stmt)
        p_row = p_res.scalar_one_or_none()
        if not p_row:
            stmt_fallback = (
                select(MaskingPolicy)
                .where(MaskingPolicy.tenant_id == tenant.tenant_id)
                .where(MaskingPolicy.is_active.is_(True))
                .order_by(MaskingPolicy.created_at.desc())
            )
            p_fallback = await db.execute(stmt_fallback)
            p_row = p_fallback.scalars().first()

        if p_row:
            tenant_policy = load_policy_from_string(p_row.policy_yaml)
            if tenant_policy and internal_role not in tenant_policy.roles and tenant_policy.roles:
                internal_role = next(iter(tenant_policy.roles.keys()))
        else:
            try:
                tenant_policy = get_policy()
            except Exception:
                tenant_policy = None

        request.state.tenant_policy = tenant_policy
        request.state.tenant_context = tenant
        request.state.user_id = f"apikey:{getattr(request.state, 'api_key_name', 'key')}"
        request.state.user_groups = [internal_role]

        limiter = get_rate_limiter()
        rate_result = await limiter.check_rate_limit(tenant.tenant_id, tier="standard")
        request.state.rate_limit_result = rate_result
        if not rate_result.allowed:
            record_rate_limit_exceeded(tenant=tenant.tenant_slug)
            raise RateLimitExceededError(
                tenant_id=tenant.tenant_id,
                limit=rate_result.limit,
                retry_after=rate_result.reset_seconds,
            )

        return internal_role

    # ── Path B: Enterprise Federated JWT (SSO / Okta / Azure AD) ─────────────
    if credentials is None or not credentials.credentials:
        raise AuthenticationError(
            "Missing credentials. Provide an API Key via 'X-API-Key' header or an enterprise JWT via 'Authorization: Bearer <token>'."
        )
    token = credentials.credentials
    claims = await validate_jwt_for_tenant(token, tenant)
    groups = extract_groups(claims, tenant.groups_claim)
    if not groups:
        raise AuthorizationError(role="<no groups>", endpoint="/v1/mask")

    res = await resolve_role_and_policy_for_tenant(groups, tenant.tenant_id, db)
    if res is None:
        raise AuthorizationError(role=f"groups={groups}", endpoint="/v1/mask")
    internal_role, tenant_policy = res
    request.state.tenant_policy = tenant_policy


    if tenant_policy is not None:
        known_roles = set(tenant_policy.roles.keys())
        if internal_role not in known_roles and known_roles:
            internal_role = next(iter(tenant_policy.roles.keys()))
    else:
        try:
            known_roles = set(get_policy().roles.keys())
        except Exception:
            known_roles = set()

    valid_roles = known_roles if known_roles else {"analyst", "auditor", "operator", "default"}
    if known_roles and internal_role not in valid_roles:
        raise AuthorizationError(role=internal_role, endpoint="/v1/mask")

    # Enforce rate limiting per tenant
    request.state.tenant_context = tenant
    request.state.user_id = str(claims.get("sub") or claims.get("preferred_username") or "anonymous")
    request.state.user_groups = groups

    limiter = get_rate_limiter()
    rate_result = await limiter.check_rate_limit(tenant.tenant_id, tier="standard")
    request.state.rate_limit_result = rate_result
    if not rate_result.allowed:
        record_rate_limit_exceeded(tenant=tenant.tenant_slug)
        raise RateLimitExceededError(
            tenant_id=tenant.tenant_id,
            limit=rate_result.limit,
            retry_after=rate_result.reset_seconds,
        )

    return internal_role


# ── Shared pipeline helper ────────────────────────────────────────────────────

def _run_and_respond(
    *,
    raw_bytes: bytes,
    fmt: str,
    role: str,
    tenant_slug: str,
    tenant_id: str = "default",
    policy: Any | None = None,
    user_id: str | None = None,
    groups: list[str] | None = None,
    rid: str,
    filename: str | None = None,
    as_attachment: bool = False,
    rate_result: RateLimitResult | None = None,
) -> Response:
    """Run pipeline on *raw_bytes* and return the appropriate Response."""
    t0 = time.perf_counter()
    if policy is None:
        policy = get_policy()

    logger = get_app_logger()
    try:
        settings = get_settings()
    except Exception:
        from app.config import init_settings
        settings = init_settings()

    if role == "operator":
        from datetime import datetime, timezone
        entry = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"request_id={rid} "
            f"tenant={tenant_slug} "
            f"format={fmt} "
            f"source={filename or 'inline'}\n"
        )
        try:
            with open(settings.audit_log_path, "a", encoding="utf-8") as af:
                af.write(entry)
        except OSError as exc:
            raise AuditLogWriteError(str(exc))
        logger.warning(
            "Operator raw access: tenant=%s format=%s source=%s",
            tenant_slug, fmt, filename or "inline",
        )
        duration_s = time.perf_counter() - t0
        duration_ms = int(duration_s * 1000)
        record_request_metric(tenant=tenant_slug, role=role, fmt=fmt, status="200", duration_s=duration_s)
        try:
            get_audit_ledger().record_event(
                tenant_id=tenant_id,
                user_id=user_id,
                groups=groups,
                policy_name="operator-bypass",
                fmt=fmt,
                execution_time_ms=duration_ms,
                request_id=rid,
            )
        except Exception as e:
            logger.warning("Failed to record audit event: %s", e)

        content_type = _CONTENT_TYPES.get(fmt, "application/octet-stream")
        headers = {
            "X-Request-ID": rid,
            "X-Unmasked":   "true",
            "X-Role":       role,
            "X-Tenant":     tenant_slug,
        }
        if rate_result is not None:
            headers["X-RateLimit-Limit"] = str(rate_result.limit)
            headers["X-RateLimit-Remaining"] = str(rate_result.remaining)
            headers["X-RateLimit-Reset"] = str(rate_result.reset_seconds)
        if as_attachment and filename:
            headers["Content-Disposition"] = f'attachment; filename="masked_{filename}"'
        return Response(content=raw_bytes, media_type=content_type, headers=headers)

    result: PipelineResult = run_pipeline(
        raw_bytes=raw_bytes, fmt=fmt, policy=policy, role=role, request_id=rid,
    )
    duration_s = time.perf_counter() - t0
    duration_ms = int(duration_s * 1000)
    record_request_metric(tenant=tenant_slug, role=role, fmt=fmt, status="200", duration_s=duration_s)
    try:
        get_audit_ledger().record_event(
            tenant_id=tenant_id,
            user_id=user_id,
            groups=groups,
            policy_name=role,
            fmt=fmt,
            execution_time_ms=duration_ms,
            request_id=rid,
        )
    except Exception as e:
        logger.warning("Failed to record audit event: %s", e)

    content_type = _CONTENT_TYPES.get(fmt, "application/octet-stream")
    headers = {
        "X-Request-ID":           rid,
        "X-Policy-Version":       policy.version,
        "X-Role":                 role,
        "X-Tenant":               tenant_slug,
        "X-Conflict-Count":       str(result.conflict_count),
        "X-Uncovered-Count":      str(result.uncovered_count),
        "X-K-Anonymity-Achieved": str(result.k_achieved).lower(),
        "X-Scopes-Evaluated":     str(result.scopes_evaluated),
        "X-Scopes-Dropped":       str(result.scopes_dropped),
        "X-Profiles-Applied":     ",".join(result.profiles_applied),
    }
    if rate_result is not None:
        headers["X-RateLimit-Limit"] = str(rate_result.limit)
        headers["X-RateLimit-Remaining"] = str(rate_result.remaining)
        headers["X-RateLimit-Reset"] = str(rate_result.reset_seconds)
    if as_attachment and filename:
        headers["Content-Disposition"] = f'attachment; filename="masked_{filename}"'

    from app.pipeline.phase2 import store_conflict_log
    store_conflict_log(rid, result.conflict_log)

    logger.info(
        "v1/mask: tenant=%s role=%s fmt=%s | conflicts=%d uncovered=%d",
        tenant_slug, role, fmt, result.conflict_count, result.uncovered_count,
    )

    if as_attachment:
        return StreamingResponse(
            iter([result.output_bytes]),
            media_type=content_type,
            headers=headers,
        )
    return Response(content=result.output_bytes, media_type=content_type, headers=headers)


# ── POST /v1/mask — inline raw payload ───────────────────────────────────────

@router.post("/mask")
async def v1_mask_inline(
    body: InlineMaskRequest,
    request: Request,
    role: Annotated[str, Depends(_resolve_role_multi_tenant)],
) -> Response:
    """Mask an inline JSON/XML/YAML payload with zero disk I/O.

    The request body carries both the format and the data to mask.
    The response contains the masked payload in the same format.

    Example request body::

        {
          "format": "json",
          "data": {"user_id": 1042, "ssn": "123-45-6789", "salary": 95000}
        }
    """
    rid = request_id_var.get("-")
    tenant_ctx: TenantContext | None = getattr(request.state, "tenant_context", None)
    tenant_slug = tenant_ctx.tenant_slug if tenant_ctx else "unknown"
    tenant_id = tenant_ctx.tenant_id if tenant_ctx else "default"
    user_id: str | None = getattr(request.state, "user_id", None)
    user_groups: list[str] | None = getattr(request.state, "user_groups", None)
    rate_result: RateLimitResult | None = getattr(request.state, "rate_limit_result", None)

    raw_bytes = body.to_bytes()
    tenant_policy = getattr(request.state, "tenant_policy", None)

    return _run_and_respond(
        raw_bytes=raw_bytes,
        fmt=body.format,
        role=role,
        tenant_slug=tenant_slug,
        tenant_id=tenant_id,
        policy=tenant_policy,
        user_id=user_id,
        groups=user_groups,
        rid=rid,
        filename=None,
        as_attachment=False,
        rate_result=rate_result,
    )


# ── POST /v1/mask/file — multipart file upload ────────────────────────────────

@router.post("/mask/file")
async def v1_mask_file(
    request: Request,
    role: Annotated[str, Depends(_resolve_role_multi_tenant)],
    file: UploadFile = File(..., description="File to mask (JSON, XML, or YAML)."),
) -> StreamingResponse:
    """Stream a file upload through the masking pipeline and return the masked file.

    The format is auto-detected from the file's MIME type or extension.
    The masked file is returned as an attachment download with
    ``Content-Disposition: attachment; filename="masked_<original>"``.

    Supports: ``.json``, ``.xml``, ``.yaml`` / ``.yml``
    Max recommended payload: 10 MB (enforce at API gateway layer).
    """
    rid = request_id_var.get("-")
    tenant_ctx: TenantContext | None = getattr(request.state, "tenant_context", None)
    tenant_slug = tenant_ctx.tenant_slug if tenant_ctx else "unknown"
    tenant_id = tenant_ctx.tenant_id if tenant_ctx else "default"
    tenant_policy = getattr(request.state, "tenant_policy", None)
    user_id: str | None = getattr(request.state, "user_id", None)
    user_groups: list[str] | None = getattr(request.state, "user_groups", None)
    rate_result: RateLimitResult | None = getattr(request.state, "rate_limit_result", None)

    # Detect format from MIME type, then fall back to filename extension.
    fmt: str | None = None
    if file.content_type:
        mime = file.content_type.split(";")[0].strip().lower()
        fmt = _MIME_TO_FMT.get(mime)

    if fmt is None and file.filename:
        import os
        _, ext = os.path.splitext(file.filename.lower())
        fmt = _EXT_TO_FMT.get(ext)

    if fmt is None:
        raise UnsupportedFormatError(file.filename or "<upload>")

    raw_bytes: bytes = await file.read()
    original_name = file.filename or f"upload.{fmt}"

    return _run_and_respond(  # type: ignore[return-value]
        raw_bytes=raw_bytes,
        fmt=fmt,
        role=role,
        tenant_slug=tenant_slug,
        tenant_id=tenant_id,
        policy=tenant_policy,
        user_id=user_id,
        groups=user_groups,
        rid=rid,
        filename=original_name,
        as_attachment=True,
        rate_result=rate_result,
    )


# ── Unversioned streaming routes (/mask and /mask/file) ──────────────────────
unversioned_router = APIRouter(tags=["On-The-Fly Masking"])
unversioned_router.add_api_route("/mask", v1_mask_inline, methods=["POST"], response_class=Response)
unversioned_router.add_api_route("/mask/file", v1_mask_file, methods=["POST"], response_class=StreamingResponse)


