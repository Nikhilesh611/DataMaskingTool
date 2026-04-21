"""Pipeline runner — orchestrates Phase 0 through k-anonymity.

v2.0 changes
------------
* Calls Phase 0 (``evaluate_scopes``) before Phase 1.
* Passes ``scope_plan`` to Phase 1, 2, and 3.
* ``PipelineResult`` gains scope metadata fields:
  ``scope_events``, ``scopes_evaluated``, ``scopes_dropped``,
  ``profiles_applied``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.adapters.base import FormatAdapter
from app.adapters.registry import get_adapter
from app.exceptions import UnknownRoleError
from app.pipeline.kanon import KAnonReport, enforce_k_anonymity
from app.pipeline.phase0 import ScopePlan, evaluate_scopes
from app.pipeline.phase1 import build_index
from app.pipeline.phase2 import ConflictLog, resolve_conflicts
from app.pipeline.phase3 import CoverageLog, apply_masking
from app.policy.models import MaskingPolicy


@dataclass
class PipelineResult:
    output_bytes: bytes
    conflict_log: ConflictLog
    coverage_log: CoverageLog
    kanon_report: Optional[KAnonReport]
    request_id: str
    scope_events: List[Dict[str, str]] = field(default_factory=list)

    # Computed in __post_init__
    conflict_count:   int        = field(init=False)
    uncovered_count:  int        = field(init=False)
    k_achieved:       bool       = field(init=False)
    scopes_evaluated: int        = field(init=False)
    scopes_dropped:   int        = field(init=False)
    profiles_applied: List[str]  = field(init=False)

    def __post_init__(self) -> None:
        self.conflict_count = len(self.conflict_log)
        self.uncovered_count = sum(
            1 for entry in self.coverage_log if entry.get("reason") != "ancestor suppressed"
        )
        self.k_achieved = self.kanon_report.achieved if self.kanon_report else True
        self.scopes_evaluated = len(self.scope_events)
        self.scopes_dropped = sum(
            1 for e in self.scope_events if e.get("strategy") == "drop_subtree"
        )
        # Deduplicated ordered list of profile names that were applied
        seen: dict = {}
        for e in self.scope_events:
            p = e.get("profile", "")
            if p:
                seen[p] = None
        self.profiles_applied = list(seen.keys())


def run_pipeline(
    raw_bytes: bytes,
    fmt: str,
    policy: MaskingPolicy,
    role: str,
    request_id: Optional[str] = None,
) -> PipelineResult:
    """Run the full masking pipeline for *role*.

    Parameters
    ----------
    raw_bytes:
        Raw file content as returned by the file reader.
    fmt:
        Format string (``"xml"``, ``"json"``, or ``"yaml"``).
    policy:
        Validated, immutable policy object.
    role:
        ``"analyst"``, ``"auditor"``, or ``"operator"``.
    request_id:
        Optional pre-generated request ID.  Generated internally if absent.

    Returns
    -------
    PipelineResult
        Contains output bytes, logs, k-anonymity report, and identifiers.
    """
    if request_id is None:
        request_id = str(uuid.uuid4())

    valid_roles = {"analyst", "auditor", "operator"}
    if role not in valid_roles:
        raise UnknownRoleError(role)

    # Operator bypasses the entire pipeline.
    if role == "operator":
        return PipelineResult(
            output_bytes=raw_bytes,
            conflict_log=[],
            coverage_log=[],
            kanon_report=None,
            request_id=request_id,
            scope_events=[],
        )

    adapter: FormatAdapter = get_adapter(fmt)

    # Check if policy overrides the format.
    if policy.format and policy.format != fmt:
        adapter = get_adapter(policy.format)

    # Parse
    tree = adapter.parse(raw_bytes)

    # ── Phase 0: Scope evaluation ─────────────────────────────────────────────
    scope_plan: ScopePlan = evaluate_scopes(adapter, tree, policy, role)

    # ── Phase 1: Build rule and coverage indexes ──────────────────────────────
    rule_index, coverage_index = build_index(
        adapter, tree, list(policy.rules), scope_plan=scope_plan
    )

    # ── Phase 2: Resolve conflicts ────────────────────────────────────────────
    # Build a path map from coverage index + all nodes for conflict records.
    all_node_paths = dict(coverage_index)   # uncovered nodes
    for node in adapter.iter_nodes(tree):
        nid = adapter.get_identity(node)
        if nid not in all_node_paths:
            all_node_paths[nid] = adapter.get_path(node)

    decision_index, conflict_log = resolve_conflicts(
        rule_index,
        list(policy.rules),
        node_paths=all_node_paths,
        expansion_rule_ids=scope_plan.expansion_rule_ids,
    )

    # ── Phase 3: Masking loop ─────────────────────────────────────────────────
    output_bytes, coverage_log = apply_masking(
        adapter, tree, decision_index, coverage_index, role,
        scope_plan=scope_plan,
    )

    # ── k-Anonymity engine (analyst role only, after masking) ─────────────────
    kanon_report: Optional[KAnonReport] = None
    if role == "analyst" and policy.k_anonymity and policy.k_anonymity.enabled:
        masked_tree = adapter.parse(output_bytes)
        kanon_report = enforce_k_anonymity(adapter, masked_tree, policy)
        if kanon_report is not None:
            output_bytes = adapter.serialise(masked_tree)

    return PipelineResult(
        output_bytes=output_bytes,
        conflict_log=conflict_log,
        coverage_log=coverage_log,
        kanon_report=kanon_report,
        request_id=request_id,
        scope_events=scope_plan.scope_events,
    )
