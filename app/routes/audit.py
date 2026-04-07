"""Audit endpoints (auditor-only).

GET /audit/coverage?filename=<name>
    Runs Phases 1 and 2 only and returns a node-level coverage report.
    No field values are included.

GET /audit/conflicts/{request_id}
    Returns the conflict log stored during a previous /mask call.
"""

from __future__ import annotations

import collections
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app.auth import require_role
from app.config import get_settings
from app.file_reader import read_file
from app.pipeline.phase1 import build_index
from app.pipeline.phase2 import ConflictLog, resolve_conflicts
from app.policy.loader import get_policy

router = APIRouter(prefix="/audit", tags=["audit"])

# ── In-memory conflict log store ──────────────────────────────────────────────
# Simple LRU-like eviction: keep the last 500 entries.
_MAX_STORED = 500
_conflict_store: "collections.OrderedDict[str, ConflictLog]" = collections.OrderedDict()


def store_conflict_log(request_id: str, log: ConflictLog) -> None:
    if request_id in _conflict_store:
        _conflict_store.move_to_end(request_id)
    _conflict_store[request_id] = log
    while len(_conflict_store) > _MAX_STORED:
        _conflict_store.popitem(last=False)


def get_conflict_log(request_id: str) -> Optional[ConflictLog]:
    return _conflict_store.get(request_id)


# ── Coverage report ───────────────────────────────────────────────────────────

@router.get("/coverage")
async def coverage_report(
    filename: str = Query(..., description="Name of the file to analyse."),
    role: Annotated[str, Depends(require_role("auditor"))] = "auditor",
) -> JSONResponse:
    settings = get_settings()
    policy = get_policy()

    raw_bytes, fmt = read_file(filename, settings.data_dir)

    from app.adapters.registry import get_adapter
    adapter = get_adapter(policy.format or fmt)
    tree = adapter.parse(raw_bytes)

    rule_index, coverage_index = build_index(adapter, tree, list(policy.rules))

    # Build coverage report — paths only, no values.
    covered_paths: List[str] = []
    for node in adapter.iter_nodes(tree):
        nid = adapter.get_identity(node)
        if nid in rule_index:
            covered_paths.append(adapter.get_path(node))

    uncovered_paths: List[str] = list(coverage_index.values())

    return JSONResponse(
        {
            "filename": filename,
            "format": fmt,
            "covered_count": len(covered_paths),
            "uncovered_count": len(uncovered_paths),
            "covered_nodes": covered_paths,
            "uncovered_nodes": uncovered_paths,
        }
    )


# ── Conflict log retrieval ────────────────────────────────────────────────────

@router.get("/conflicts/{request_id}")
async def get_conflicts(
    request_id: str,
    role: Annotated[str, Depends(require_role("auditor"))] = "auditor",
) -> JSONResponse:
    log = get_conflict_log(request_id)
    if log is None:
        return JSONResponse({"error": f"No conflict log found for request_id '{request_id}'."}, status_code=404)
    return JSONResponse({"request_id": request_id, "conflicts": log})
