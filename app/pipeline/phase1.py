"""Phase 1 — Index Building.

Evaluates every rule's selector against the tree and builds two indexes:

``rule_index``
    Maps node identity (int) → list of competing MaskingRule objects.

``coverage_index``
    Maps node identity (int) → path string for every node that was NOT
    matched by any rule.  This is what the auditor sees as "gaps".

No tree mutations happen here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.adapters.base import FormatAdapter
from app.policy.models import MaskingRule

# Type aliases for clarity
RuleIndex = Dict[int, List[MaskingRule]]      # node_id → [rules...]
CoverageIndex = Dict[int, str]                # node_id → path string (uncovered nodes)


def build_index(
    adapter: FormatAdapter,
    tree: Any,
    rules: List[MaskingRule],
) -> Tuple[RuleIndex, CoverageIndex]:
    """Evaluate every rule's selector and catalogue all nodes.

    Parameters
    ----------
    adapter:
        The format adapter for the document (XML / JSON / YAML).
    tree:
        The parsed document tree produced by ``adapter.parse()``.
    rules:
        The ordered list of masking rules from the policy.

    Returns
    -------
    rule_index:
        Maps each matched node's identity to the list of rules that
        selected it.  A node matched by two selectors gets two entries.
    coverage_index:
        Maps each *unmatched* node's identity to its path string.
    """
    # Step 1 — evaluate every rule's selector and record associations.
    rule_index: RuleIndex = {}
    for rule in rules:
        matched_nodes = adapter.select(tree, rule.selector)
        for node in matched_nodes:
            node_id = adapter.get_identity(node)
            rule_index.setdefault(node_id, []).append(rule)

    # Step 2 — iterate every node once to find uncovered ones.
    coverage_index: CoverageIndex = {}
    for node in adapter.iter_nodes(tree):
        node_id = adapter.get_identity(node)
        if node_id not in rule_index:
            coverage_index[node_id] = adapter.get_path(node)

    return rule_index, coverage_index
