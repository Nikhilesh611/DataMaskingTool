"""POST /mask endpoint — v2.0.

Changes from v1
---------------
* ``require_role()`` replaced by ``resolve_role()`` — supports both
  ``X-Masking-Role`` (simple header) and ``X-API-Token`` (token store).
* Three new response headers added from ``PipelineResult``:
    ``X-Scopes-Evaluated``  number of scopes matched in the document
    ``X-Scopes-Dropped``    number of scopes with ``drop_subtree`` strategy
    ``X-Profiles-Applied``  comma-separated list of profile names applied
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.auth import resolve_role
from app.config import get_settings
from app.exceptions import AuditLogWriteError
from app.file_reader import read_file
from app.logging_config import get_app_logger, get_audit_logger, request_id_var
from app.pipeline.runner import PipelineResult, run_pipeline
from app.policy.loader import get_policy

router = APIRouter()

_CONTENT_TYPES = {
    "xml":  "application/xml",
    "json": "application/json",
    "yaml": "application/yaml",
}


class MaskRequest:
    def __init__(self, filename: str):
        self.filename = filename


from pydantic import BaseModel


class MaskBody(BaseModel):
    filename: str


@router.post("/mask")
async def mask(
    body: MaskBody,
    request: Request,
    role: Annotated[str, Depends(resolve_role())],
) -> Response:
    settings = get_settings()
    policy = get_policy()
    logger = get_app_logger()
    audit_logger = get_audit_logger()
    rid = request_id_var.get("-")

    raw_bytes, fmt = read_file(body.filename, settings.data_dir)

    # Operator: return raw bytes after writing audit log.
    if role == "operator":
        real_path = os.path.realpath(
            os.path.join(settings.data_dir, os.path.basename(body.filename))
        )
        from datetime import datetime, timezone
        entry = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"request_id={rid} "
            f"token=<redacted> "
            f"filename={body.filename} "
            f"resolved_path={real_path} "
            f"client_ip={request.client.host if request.client else 'unknown'}\n"
        )
        try:
            with open(settings.audit_log_path, "a", encoding="utf-8") as af:
                af.write(entry)
        except OSError as exc:
            logger.warning("Failed to write audit log: %s", exc)
            raise AuditLogWriteError(str(exc))

        logger.warning(
            "Operator raw access: filename=%s resolved=%s", body.filename, real_path
        )
        content_type = _CONTENT_TYPES.get(fmt, "application/octet-stream")
        return Response(
            content=raw_bytes,
            media_type=content_type,
            headers={
                "X-Request-ID": rid,
                "X-Unmasked":   "true",
            },
        )

    result: PipelineResult = run_pipeline(
        raw_bytes=raw_bytes,
        fmt=fmt,
        policy=policy,
        role=role,
        request_id=rid,
    )

    content_type = _CONTENT_TYPES.get(fmt, "application/octet-stream")
    headers = {
        "X-Request-ID":          rid,
        "X-Policy-Version":      policy.version,
        "X-Role":                role,
        "X-Conflict-Count":      str(result.conflict_count),
        "X-Uncovered-Count":     str(result.uncovered_count),
        "X-K-Anonymity-Achieved": str(result.k_achieved).lower(),
        # v2.0 scope headers
        "X-Scopes-Evaluated":    str(result.scopes_evaluated),
        "X-Scopes-Dropped":      str(result.scopes_dropped),
        "X-Profiles-Applied":    ",".join(result.profiles_applied),
    }

    # Store conflict log for later retrieval by auditors.
    from app.routes.audit import store_conflict_log
    store_conflict_log(rid, result.conflict_log)

    logger.info(
        "Masked %s as %s | conflicts=%d uncovered=%d k_achieved=%s "
        "scopes=%d dropped=%d profiles=%s",
        body.filename, role,
        result.conflict_count, result.uncovered_count, result.k_achieved,
        result.scopes_evaluated, result.scopes_dropped,
        ",".join(result.profiles_applied) or "none",
    )

    return Response(
        content=result.output_bytes,
        media_type=content_type,
        headers=headers,
    )
