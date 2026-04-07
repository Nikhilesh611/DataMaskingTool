"""K-Anonymity Engine.

Runs after Phase 3 and only when the policy's k-anonymity block is enabled.
Iterates until every equivalence class has at least k members, or until all
quasi-identifier hierarchies are at their maximum level.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.adapters.base import FormatAdapter
from app.hierarchies.base import HIERARCHY_REGISTRY
from app.policy.models import KAnonConfig, MaskingPolicy


# ── Types ─────────────────────────────────────────────────────────────────────

QITuple = Tuple[str, ...]               # quasi-identifier values for one record
EquivClass = List[Any]                  # list of record nodes in one class

class KAnonReport:
    """Result of the k-anonymity engine run."""

    def __init__(
        self,
        *,
        achieved: bool,
        iterations: int,
        violating_classes: List[Dict[str, Any]],
        final_qi_levels: Dict[str, int],
    ) -> None:
        self.achieved = achieved
        self.iterations = iterations
        self.violating_classes = violating_classes
        self.final_qi_levels = final_qi_levels

    def to_dict(self) -> Dict[str, Any]:
        return {
            "achieved": self.achieved,
            "iterations": self.iterations,
            "violating_classes": self.violating_classes,
            "final_qi_levels": self.final_qi_levels,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_qi_tuple(
    adapter: FormatAdapter,
    record: Any,
    qi_selectors: List[str],
) -> QITuple:
    """Extract quasi-identifier values from one record node."""
    values: List[str] = []
    for sel in qi_selectors:
        matches = adapter.select(record, sel)
        if matches:
            v = adapter.get_value(matches[0])
            values.append(str(v) if v is not None else "*")
        else:
            values.append("*")
    return tuple(values)


def _group_by_qi(
    adapter: FormatAdapter,
    records: List[Any],
    qi_selectors: List[str],
) -> Dict[QITuple, EquivClass]:
    """Group record nodes by their QI tuple."""
    groups: Dict[QITuple, EquivClass] = {}
    for record in records:
        key = _extract_qi_tuple(adapter, record, qi_selectors)
        groups.setdefault(key, []).append(record)
    return groups


def _find_most_violating_qi(
    violating_classes: List[EquivClass],
    qi_selectors: List[str],
    adapter: FormatAdapter,
) -> int:
    """Return the index of the QI with the most distinct values across violating classes."""
    distinct_counts: List[int] = [0] * len(qi_selectors)
    for cls in violating_classes:
        # Collect distinct values per QI within this class.
        per_qi: List[set] = [set() for _ in qi_selectors]
        for record in cls:
            for i, sel in enumerate(qi_selectors):
                matches = adapter.select(record, sel)
                if matches:
                    v = adapter.get_value(matches[0])
                    per_qi[i].add(str(v) if v is not None else "*")
        for i, s in enumerate(per_qi):
            distinct_counts[i] += len(s)
    return distinct_counts.index(max(distinct_counts))


def _generalise_qi(
    adapter: FormatAdapter,
    records: List[Any],
    qi_selector: str,
    hierarchy_name: str,
    level: int,
) -> None:
    """Write the generalised value back into every record's QI node."""
    from app.hierarchies.base import HIERARCHY_REGISTRY
    h = HIERARCHY_REGISTRY.get(hierarchy_name)
    if h is None:
        return
    for record in records:
        for node in adapter.select(record, qi_selector):
            raw = adapter.get_value(node)
            new_val = h.generalise(str(raw) if raw is not None else "", level)
            adapter.set_value(node, new_val)


# ── Main entry point ──────────────────────────────────────────────────────────

def enforce_k_anonymity(
    adapter: FormatAdapter,
    tree: Any,
    policy: MaskingPolicy,
) -> Optional[KAnonReport]:
    """Run the k-anonymity engine.

    Returns *None* if k-anonymity is not configured or not enabled.
    Otherwise returns a ``KAnonReport`` describing the outcome.
    """
    if policy.k_anonymity is None or not policy.k_anonymity.enabled:
        return None

    cfg: KAnonConfig = policy.k_anonymity
    k = cfg.k
    qi_selectors = list(cfg.quasi_identifiers)

    # Map each QI selector to a hierarchy name and current level.
    # We assume each QI selector corresponds to a generalise rule in the policy
    # whose hierarchy we can look up.  If not found, we skip that QI.
    qi_hierarchies: Dict[int, str] = {}  # qi_index → hierarchy_name
    qi_levels: Dict[int, int] = {}       # qi_index → current level

    for i, sel in enumerate(qi_selectors):
        # Find a matching rule in the policy for this selector.
        for rule in policy.rules:
            if rule.technique == "generalize" and rule.selector == sel and rule.hierarchy:
                qi_hierarchies[i] = rule.hierarchy
                qi_levels[i] = rule.level or 0
                break
        else:
            # No matching generalise rule — pick a default if hierarchy exists.
            qi_levels[i] = 0

    # Locate record nodes using the record_root selector.
    records = adapter.select(tree, policy.record_root)
    if not records:
        return KAnonReport(
            achieved=True,
            iterations=0,
            violating_classes=[],
            final_qi_levels={qi_selectors[i]: qi_levels[i] for i in range(len(qi_selectors))},
        )

    max_iters = 50  # safety cap
    iterations = 0

    while iterations < max_iters:
        iterations += 1
        groups = _group_by_qi(adapter, records, qi_selectors)
        violating = [cls for cls in groups.values() if len(cls) < k]

        if not violating:
            return KAnonReport(
                achieved=True,
                iterations=iterations,
                violating_classes=[],
                final_qi_levels={qi_selectors[i]: qi_levels[i] for i in range(len(qi_selectors))},
            )

        # Find which QI to generalise next.
        qi_idx = _find_most_violating_qi(violating, qi_selectors, adapter)
        h_name = qi_hierarchies.get(qi_idx)

        if h_name is None:
            break

        h = HIERARCHY_REGISTRY.get(h_name)
        if h is None:
            break

        new_level = qi_levels[qi_idx] + 1
        if new_level > h.max_level:
            break  # Cannot generalise further.

        qi_levels[qi_idx] = new_level
        _generalise_qi(adapter, records, qi_selectors[qi_idx], h_name, new_level)

    # Could not achieve k-anonymity.
    groups = _group_by_qi(adapter, records, qi_selectors)
    violating = [cls for cls in groups.values() if len(cls) < k]
    violating_info = [
        {
            "size": len(cls),
            "qi_values": _extract_qi_tuple(adapter, cls[0], qi_selectors),
        }
        for cls in violating
    ]

    import logging
    logging.getLogger("app").warning(
        "k-anonymity could not be fully achieved. %d violating class(es) remain.",
        len(violating_info),
    )

    return KAnonReport(
        achieved=False,
        iterations=iterations,
        violating_classes=violating_info,
        final_qi_levels={qi_selectors[i]: qi_levels[i] for i in range(len(qi_selectors))},
    )
