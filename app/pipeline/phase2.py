"""Phase 2 — Conflict Resolution.

Consumes the rule index from Phase 1 and produces:

``decision_index``
    Maps node identity (int) → the single winning MaskingRule.

``conflict_log``
    A list of ConflictRecord dicts describing every multi-rule contest.

No tree mutations happen here.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.pipeline.phase1 import RuleIndex
from app.policy.models import MaskingRule

# Type aliases
DecisionIndex = Dict[int, MaskingRule]           # node_id → winning rule

ConflictRecord = Dict[str, Any]                   # structured conflict info
ConflictLog = List[ConflictRecord]


# ── Specificity scoring ───────────────────────────────────────────────────────

def score_selector(selector: str) -> int:
    """Compute a specificity score for *selector*.

    Works for both XPath and JSONPath strings.  Higher scores mean the
    selector is more precise.  The scoring components are:

    * +10 per explicit tag / field name (non-wildcard, non-recursive)
    * +5  per predicate / filter expression  (``[@…]`` or ``[?(…)]``)
    * +3  for being an absolute path (starts with ``/`` or ``$``)
    * −2  per recursive descent (``//`` or ``..``)
    * −1  per wildcard (``*`` standing alone as a path step)
    """
    score = 0

    # Absolute path bonus
    stripped = selector.strip()
    if stripped.startswith("/") or stripped.startswith("$"):
        score += 3

    # Count recursive descents (penalise vagueness)
    score -= 2 * (stripped.count("//") + stripped.count(".."))

    # Count predicates / filters
    score += 5 * len(re.findall(r"\[@[^\]]+\]|\[\?\([^\)]+\)\]|\[(?!\d+\])[^\]]+\]", stripped))

    # Tokenise on separators and count named steps vs wildcards
    # Strip predicates first to avoid counting bracket contents as names.
    no_predicates = re.sub(r"\[[^\]]*\]", "", stripped)
    # Split on / . [ ] and filter empty strings
    tokens = [t for t in re.split(r"[/.\[\]]+", no_predicates) if t]
    for token in tokens:
        if token == "*" or token == "**":
            score -= 1
        elif token and not token.isdigit() and token not in ("", "$", "@"):
            score += 10

    return score


# ── Conflict resolution ───────────────────────────────────────────────────────

def resolve_conflicts(
    rule_index: RuleIndex,
    rules: List[MaskingRule],
    node_paths: Optional[Dict[int, str]] = None,
) -> Tuple[DecisionIndex, ConflictLog]:
    """Resolve every multi-rule conflict and produce a decision index.

    Parameters
    ----------
    rule_index:
        Mapping from node identity to the list of rules that matched it
        (output of Phase 1).
    rules:
        The *ordered* rule list from the policy.  This ordering is the
        document-order tiebreaker when specificity scores are equal.
    node_paths:
        Optional mapping from node identity to path string, used to
        populate the conflict log.  May be omitted.

    Returns
    -------
    decision_index:
        Maps node identity to the single winning rule.
    conflict_log:
        Records every multi-rule contest with scores and winner.
    """
    decision_index: DecisionIndex = {}
    conflict_log: ConflictLog = []

    # Pre-compute document order positions for tiebreaking.
    rule_order: Dict[int, int] = {id(rule): i for i, rule in enumerate(rules)}

    for node_id, competing_rules in rule_index.items():
        if len(competing_rules) == 1:
            decision_index[node_id] = competing_rules[0]
            continue

        # Score each competing rule.
        scored = [
            (score_selector(r.selector), rule_order.get(id(r), 9999), r)
            for r in competing_rules
        ]
        # Higher specificity wins; lower document-order index breaks ties.
        scored.sort(key=lambda x: (-x[0], x[1]))
        winner = scored[0][2]
        decision_index[node_id] = winner

        # Build conflict record (no field values — paths only).
        path = (node_paths or {}).get(node_id, "<unknown>")
        conflict_log.append(
            {
                "node_path": path,
                "winner": {
                    "selector": winner.selector,
                    "technique": winner.technique,
                    "specificity": scored[0][0],
                },
                "losers": [
                    {
                        "selector": r.selector,
                        "technique": r.technique,
                        "specificity": sc,
                    }
                    for sc, _, r in scored[1:]
                ],
            }
        )

    return decision_index, conflict_log
