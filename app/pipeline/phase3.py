"""Phase 3 — The Masking Loop (v2.0).

Iterates every node in the document exactly once, checks its role in the
decision index, and applies the appropriate transformation (or label).

v2.0 additions
--------------
Pre-loop subtree operations
    Before the per-node loop, the phase processes every subtree root in
    ``scope_plan.subtree_roots`` whose strategy is not ``"masked"`` or
    ``"default_allow"``:

    * ``drop_subtree``  — ``adapter.remove_node(root)``
    * ``deep_redact``   — walk all leaves → set to ``[REDACTED]``
    * ``synthesize``    — walk all leaves → set to synthetic value

    After bulk ops, any remaining node whose scope strategy is one of the
    above (or ``"default_allow"``) is skipped in the regular loop, avoiding
    double-processing and suppressing spurious coverage_log entries.

mask_pattern technique
    The new element-level ``mask_pattern`` technique is handled in
    ``_apply_technique`` via ``techniques.mask_pattern``.

Roles
-----
analyst   Apply the actual masking technique.
auditor   Replace every covered node with a descriptive label; replace
          every uncovered node with ``[UNMASKED — NO RULE DEFINED]``.
          Scope labels are added for scoped nodes in bulk strategies.
operator  Phase 3 does not run — the raw bytes are returned by the runner.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from app.adapters.base import FormatAdapter
from app.pipeline.phase0 import ScopePlan
from app.pipeline.phase1 import CoverageIndex
from app.pipeline.phase2 import DecisionIndex
from app.policy.models import MaskingRule
from app import techniques


CoverageLog = List[Dict[str, str]]   # list of {path, reason}

# Strategies handled as bulk subtree operations before the main loop
_BULK_STRATEGIES = frozenset({"drop_subtree", "deep_redact", "synthesize"})

# Strategies completely excluded from the per-node coverage/masking loop
_SKIP_STRATEGIES = frozenset({"drop_subtree", "deep_redact", "synthesize", "default_allow"})


def _is_leaf(adapter: FormatAdapter, node: Any) -> bool:
    """Return True if *node* holds a scalar value (not a container)."""
    val = adapter.get_value(node)
    return not isinstance(val, (dict, list))


# ── Role-specific technique dispatch ─────────────────────────────────────────

def _apply_technique(
    adapter: FormatAdapter,
    node: Any,
    rule: MaskingRule,
    coverage_log: CoverageLog,
    node_path: str,
) -> None:
    """Apply the winning rule's technique to *node* for the analyst role."""
    t = rule.technique
    if t == "suppress":
        techniques.suppress(adapter, node)
    elif t == "nullify":
        techniques.nullify(adapter, node)
    elif t == "redact":
        techniques.redact(adapter, node)
    elif t == "pseudonymize":
        techniques.pseudonymize(adapter, node, consistent=rule.consistent if rule.consistent is not None else True)
    elif t == "generalize":
        techniques.generalize(
            adapter,
            node,
            hierarchy=rule.hierarchy or "",
            level=rule.level or 0,
            coverage_log=coverage_log,
            node_path=node_path,
        )
    elif t == "format_preserve":
        techniques.format_preserve(adapter, node)
    elif t == "noise":
        techniques.noise(adapter, node, coverage_log=coverage_log, node_path=node_path)
    elif t == "mask_pattern":
        techniques.mask_pattern(adapter, node, pattern=rule.pattern or "")
    else:
        # Should never reach here — Pydantic validates technique names.
        techniques.redact(adapter, node)


def _auditor_label(rule: MaskingRule) -> str:
    """Build a descriptive label for the auditor role."""
    t = rule.technique
    if t == "generalize":
        return f"[WOULD APPLY: generalize | hierarchy={rule.hierarchy} | level={rule.level}]"
    if t == "pseudonymize":
        cons = rule.consistent if rule.consistent is not None else True
        return f"[WOULD APPLY: pseudonymize | consistent={cons}]"
    if t == "noise":
        return "[WOULD APPLY: noise | ±10%]"
    if t == "mask_pattern":
        return f"[WOULD APPLY: mask_pattern | pattern={rule.pattern}]"
    return f"[WOULD APPLY: {t}]"


# ── Subtree bulk operation helpers ────────────────────────────────────────────

def _deep_redact_node(adapter: FormatAdapter, root: Any) -> None:
    """Walk all leaves in *root*'s subtree and set each to ``[REDACTED]``."""
    techniques.deep_redact_subtree(adapter, root)


def _synthesize_node(adapter: FormatAdapter, root: Any) -> None:
    """Walk all leaves in *root*'s subtree and replace with synthetic data."""
    techniques.synthesize_subtree(adapter, root)


# ── Main phase-3 entry point ──────────────────────────────────────────────────

def apply_masking(
    adapter: FormatAdapter,
    tree: Any,
    decision_index: DecisionIndex,
    coverage_index: CoverageIndex,
    role: str,
    scope_plan: Optional[ScopePlan] = None,
) -> Tuple[bytes, CoverageLog]:
    """Apply masking to the tree according to *role* and return serialised bytes.

    Parameters
    ----------
    adapter:
        Format adapter for this document.
    tree:
        Parsed document tree (will be mutated in place).
    decision_index:
        Maps node identity → winning MaskingRule (Phase 2 output).
    coverage_index:
        Maps node identity → path for unmatched nodes (Phase 1 output).
    role:
        ``"analyst"`` or ``"auditor"``.
    scope_plan:
        Phase 0 output.  ``None`` is equivalent to an empty plan (v1 mode).

    Returns
    -------
    output_bytes:
        The serialised, masked document.
    coverage_log:
        Records nodes skipped (ancestor suppressed) and generalise / noise
        fallbacks, plus subtree bulk operation records.
    """
    _plan = scope_plan or ScopePlan()
    members = _plan.members
    coverage_log: CoverageLog = []

    # ── Phase 3.0: Bulk subtree operations (pre-loop) ─────────────────────────
    # Process each unique subtree root exactly once.
    processed_root_ids: Set[int] = set()

    for root_node, decision in _plan.subtree_roots:
        root_id = adapter.get_identity(root_node)
        if root_id in processed_root_ids:
            continue
        processed_root_ids.add(root_id)

        if not adapter.is_attached(root_node):
            continue  # Already detached by an outer scope's drop_subtree

        strategy = decision.strategy

        if strategy == "drop_subtree":
            try:
                scope_path = adapter.get_path(root_node)
            except Exception:
                scope_path = decision.scope_path
            if role == "auditor":
                # Auditor sees the label instead of a drop
                adapter.set_value(
                    root_node,
                    f"[SCOPE STRATEGY: drop_subtree | profile={decision.profile_name or 'none'}]",
                ) if adapter.is_leaf_node(root_node) else None
            else:
                adapter.remove_node(root_node)
            coverage_log.append({"path": scope_path, "reason": "scope:drop_subtree"})

        elif strategy == "deep_redact":
            try:
                scope_path = adapter.get_path(root_node)
            except Exception:
                scope_path = decision.scope_path
            _deep_redact_node(adapter, root_node)
            coverage_log.append({"path": scope_path, "reason": "scope:deep_redact"})
            if role == "auditor":
                # Additional label on the root element if it's a leaf
                pass  # leaf values already set to [REDACTED] by deep_redact

        elif strategy == "synthesize":
            try:
                scope_path = adapter.get_path(root_node)
            except Exception:
                scope_path = decision.scope_path
            _synthesize_node(adapter, root_node)
            coverage_log.append({"path": scope_path, "reason": "scope:synthesize"})

        # "masked" and "default_allow" are handled in the per-node loop below.

    # ── Phase 3.1: Per-node masking loop ──────────────────────────────────────
    # Snapshot all nodes before mutating anything (suppress mutates parent
    # containers which would raise RuntimeError during iteration).
    all_nodes = list(adapter.iter_nodes(tree))

    for node in all_nodes:
        node_id = adapter.get_identity(node)

        # Skip nodes that belong to bulk-processed or default_allow scopes.
        scope_decision = members.get(node_id)
        if scope_decision is not None and scope_decision.strategy in _SKIP_STRATEGIES:
            continue

        if node_id not in decision_index:
            # Uncovered node (not matched by any rule).
            if role == "auditor":
                if adapter.is_attached(node) and _is_leaf(adapter, node):
                    adapter.set_value(node, "[UNMASKED — NO RULE DEFINED]")
            # analyst and operator: leave unchanged.
            continue

        # Check whether a previous suppress already removed an ancestor.
        if not adapter.is_attached(node):
            try:
                path = adapter.get_path(node)
            except Exception:
                path = "<detached>"
            coverage_log.append({"path": path, "reason": "ancestor suppressed"})
            continue

        rule = decision_index[node_id]
        node_path = adapter.get_path(node)

        if role == "auditor":
            if _is_leaf(adapter, node):
                label = _auditor_label(rule)
                adapter.set_value(node, label)
        else:
            _apply_technique(adapter, node, rule, coverage_log, node_path)

    output_bytes = adapter.serialise(tree)
    return output_bytes, coverage_log
