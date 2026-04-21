"""Phase 1 — Scope-Aware Index Building.

Evaluates every rule's selector against the tree and builds two indexes:

``rule_index``
    Maps node identity (int) → list of competing MaskingRule objects.

``coverage_index``
    Maps node identity (int) → path string for every node that was NOT
    matched by any rule.  This is what the auditor sees as "gaps".

v2.0 changes
------------
* Accepts an optional ``ScopePlan`` from Phase 0.
* Global rules are NOT evaluated against nodes in bulk-processed scopes
  (``drop_subtree``, ``deep_redact``, ``synthesize``) or ``default_allow``
  scopes.
* Scope-expanded rules (from profiles + inline scope rules) are evaluated
  globally but then filtered to only accept nodes that belong to the
  relevant scope (via the ``members`` mapping in ``ScopePlan``).
* Coverage index excludes bulk-processed and default_allow nodes.

No tree mutations happen here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from app.adapters.base import FormatAdapter
from app.pipeline.phase0 import ScopePlan
from app.policy.models import MaskingRule

# Type aliases for clarity
RuleIndex    = Dict[int, List[MaskingRule]]   # node_id → [rules...]
CoverageIndex = Dict[int, str]                 # node_id → path string (uncovered nodes)

# Strategies that are handled as bulk subtree operations — individual nodes
# in these scopes are excluded from element-level rule matching.
_BULK_STRATEGIES = frozenset({"drop_subtree", "deep_redact", "synthesize"})


def build_index(
    adapter: FormatAdapter,
    tree: Any,
    rules: List[MaskingRule],
    scope_plan: Optional[ScopePlan] = None,
) -> Tuple[RuleIndex, CoverageIndex]:
    """Evaluate every rule's selector and catalogue all nodes.

    Parameters
    ----------
    adapter:
        The format adapter for the document (XML / JSON / YAML).
    tree:
        The parsed document tree produced by ``adapter.parse()``.
    rules:
        The ordered list of *global* masking rules from the policy.
    scope_plan:
        Phase 0 output.  ``None`` is equivalent to an empty plan (v1 mode).

    Returns
    -------
    rule_index:
        Maps each matched node's identity to the list of rules that
        selected it.  A node matched by two selectors gets two entries.
    coverage_index:
        Maps each *unmatched* node's identity to its path string.
    """
    members = scope_plan.members if scope_plan else {}

    def _is_bulk(node_id: int) -> bool:
        d = members.get(node_id)
        return d is not None and d.strategy in _BULK_STRATEGIES

    def _is_default_allow(node_id: int) -> bool:
        d = members.get(node_id)
        return d is not None and d.strategy == "default_allow"

    rule_index: RuleIndex = {}

    # ── Step 1: Global rules ──────────────────────────────────────────────────
    for rule in rules:
        matched_nodes = adapter.select(tree, rule.selector)
        for node in matched_nodes:
            node_id = adapter.get_identity(node)
            if _is_bulk(node_id) or _is_default_allow(node_id):
                continue
            rule_index.setdefault(node_id, []).append(rule)

    # ── Step 2: Scope-expanded rules (only for "masked" scopes) ───────────────
    if scope_plan and scope_plan.subtree_roots:
        # Build per-decision member sets so we can filter expanded rule matches
        # to only the nodes that belong to that specific scope.
        decision_member_sets: Dict[int, Set[int]] = {}
        for node_id, decision in members.items():
            key = id(decision)
            decision_member_sets.setdefault(key, set()).add(node_id)

        processed_decisions: Set[int] = set()
        for _, decision in scope_plan.subtree_roots:
            dec_id = id(decision)
            if dec_id in processed_decisions:
                continue
            processed_decisions.add(dec_id)

            if decision.strategy != "masked" or not decision.expanded_rules:
                continue

            scope_member_ids = decision_member_sets.get(dec_id, set())

            for rule in decision.expanded_rules:
                matched_nodes = adapter.select(tree, rule.selector)
                for node in matched_nodes:
                    node_id = adapter.get_identity(node)
                    if node_id in scope_member_ids:
                        rule_index.setdefault(node_id, []).append(rule)

    # ── Step 3: Coverage index (unmatched, non-bulk, non-default_allow) ────────
    coverage_index: CoverageIndex = {}
    for node in adapter.iter_nodes(tree):
        node_id = adapter.get_identity(node)
        if node_id in rule_index:
            continue
        if _is_bulk(node_id) or _is_default_allow(node_id):
            continue
        coverage_index[node_id] = adapter.get_path(node)

    return rule_index, coverage_index
