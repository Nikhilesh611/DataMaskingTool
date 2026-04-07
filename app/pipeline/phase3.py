"""Phase 3 — The Masking Loop.

Iterates every node in the document exactly once, checks its role in the
decision index, and applies the appropriate transformation (or label).

Roles
-----
analyst   Apply the actual masking technique.
auditor   Replace every covered node with a descriptive label; replace
          every uncovered node with ``[UNMASKED — NO RULE DEFINED]``.
operator  Phase 3 does not run — the raw bytes are returned directly by
          the runner.

No new index building or conflict resolution happens here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.adapters.base import FormatAdapter
from app.pipeline.phase1 import CoverageIndex
from app.pipeline.phase2 import DecisionIndex
from app.policy.models import MaskingRule
from app import techniques


CoverageLog = List[Dict[str, str]]   # list of {path, reason}


def _is_leaf(adapter: FormatAdapter, node: Any) -> bool:
    """Return True if *node* holds a scalar value (not a container).

    Setting a label on a dict/list node would corrupt the serialised output.
    We only label leaf (scalar) nodes.  Container nodes are structural.
    """
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
    return f"[WOULD APPLY: {t}]"


# ── Main phase-3 entry point ──────────────────────────────────────────────────

def apply_masking(
    adapter: FormatAdapter,
    tree: Any,
    decision_index: DecisionIndex,
    coverage_index: CoverageIndex,
    role: str,
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

    Returns
    -------
    output_bytes:
        The serialised, masked document.
    coverage_log:
        Records nodes skipped (ancestor suppressed) and generalise / noise
        fallbacks.
    """
    if role == "operator":
        raise ValueError("Phase 3 must not run for the operator role.")

    coverage_log: CoverageLog = []

    # Snapshot all nodes before mutating anything.
    # Suppressing a node modifies the underlying dict/list during iteration,
    # which raises RuntimeError in Python.  A pre-built list avoids this.
    all_nodes = list(adapter.iter_nodes(tree))

    for node in all_nodes:
        node_id = adapter.get_identity(node)

        if node_id not in decision_index:
            # Uncovered node.
            if role == "auditor":
                if adapter.is_attached(node) and _is_leaf(adapter, node):
                    adapter.set_value(node, "[UNMASKED — NO RULE DEFINED]")
            # analyst and operator: leave unchanged
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

        if role == "analyst":
            _apply_technique(adapter, node, rule, coverage_log, node_path)
        elif role == "auditor":
            if _is_leaf(adapter, node):
                label = _auditor_label(rule)
                adapter.set_value(node, label)

    output_bytes = adapter.serialise(tree)
    return output_bytes, coverage_log
