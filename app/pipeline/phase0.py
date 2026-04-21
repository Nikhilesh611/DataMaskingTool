"""Phase 0 — Scope Evaluation.

Runs BEFORE Phase 1.  Reads ``MaskingPolicy.scopes``, selects the subtree
root nodes in the document, resolves the role-based strategy for each scope,
expands profile rules, and produces a ``ScopePlan`` that the subsequent
phases use to determine how every node in the document should be treated.

Key guarantees
--------------
* The document tree is never mutated here.
* Later scopes in the policy override earlier ones for nodes that belong to
  multiple scopes (outer→inner ordering: list outer scopes first, inner scopes
  last so that the more-specific inner scope wins).
* All subtree root nodes and member node IDs are recorded so that Phase 1,
  Phase 2, and Phase 3 never need to re-evaluate XPath/JSONPath expressions
  for scope membership.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from app.adapters.base import FormatAdapter
from app.policy.models import MaskingPolicy, MaskingRule


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ScopeDecision:
    """Resolved strategy and expanded rules for a single scope zone."""

    strategy: str
    """One of: ``"masked"``, ``"drop_subtree"``, ``"default_allow"``,
    ``"deep_redact"``, ``"synthesize"``.
    """

    expanded_rules: List[MaskingRule]
    """Profile + inline rules converted to full MaskingRule objects.
    Only relevant when ``strategy == "masked"``; empty for all others.
    """

    profile_name: Optional[str]
    """Name of the applied profile, or None if no profile was applied."""

    scope_path: str
    """The selector string that identified this scope's subtree root(s)."""


@dataclass
class ScopePlan:
    """Complete result of Phase 0."""

    members: Dict[int, ScopeDecision] = field(default_factory=dict)
    """Maps every node ID within any scope boundary to its ScopeDecision.
    For overlapping scopes the last-processed scope wins (outer→inner order).
    """

    subtree_roots: List[Tuple[Any, ScopeDecision]] = field(default_factory=list)
    """Ordered list of ``(subtree_root_node, decision)`` pairs.

    Phase 3 iterates this list to apply drop_subtree / deep_redact / synthesize
    bulk operations before running the per-node masking loop.
    """

    expansion_rule_ids: Set[int] = field(default_factory=set)
    """Python object IDs of MaskingRule objects created from profile / inline
    scope expansion.  Phase 2 adds +5 specificity to these rules so that
    scope-expanded rules beat global wildcards when both match the same node.
    """

    scope_events: List[Dict[str, str]] = field(default_factory=list)
    """Audit trail: one entry per scope per non-empty root selection.
    Captured in PipelineResult and surfaced as response headers.
    """


# ── Main entry point ──────────────────────────────────────────────────────────

def evaluate_scopes(
    adapter: FormatAdapter,
    tree: Any,
    policy: MaskingPolicy,
    role: str,
) -> ScopePlan:
    """Evaluate all scopes in *policy* for *role* and return a ``ScopePlan``.

    Parameters
    ----------
    adapter:
        Format adapter for the document.
    tree:
        Parsed document tree (not modified here).
    policy:
        Validated policy object (may have an empty ``scopes`` list).
    role:
        The resolved role string (e.g. ``"analyst"``).

    Returns
    -------
    ScopePlan
        Contains member mapping, subtree roots, expansion rule IDs, and
        audit scope events.  All fields are empty if the policy has no scopes.
    """
    plan = ScopePlan()

    if not policy.scopes:
        return plan

    for scope_rule in policy.scopes:
        # ── 1. Select subtree root nodes ───────────────────────────────────
        try:
            root_nodes = adapter.select(tree, scope_rule.path)
        except Exception:
            root_nodes = []

        if not root_nodes:
            continue

        # ── 2. Resolve strategy for this role ──────────────────────────────
        role_strat = scope_rule.roles.get(role)
        if role_strat:
            strategy = role_strat.strategy
            apply_profile = role_strat.profile
        else:
            default_strat = scope_rule.roles.get("default")
            if default_strat:
                strategy = default_strat.strategy
                apply_profile = default_strat.profile
            else:
                role_def = policy.roles.get(role)
                strategy = role_def.default_fallback if role_def else "default_allow"
                apply_profile = None

        # ── 3. Expand profile rules into full MaskingRule objects ───────────
        expanded_rules: List[MaskingRule] = []
        profile_name: Optional[str] = None

        if apply_profile:
            profile = policy.profiles.get(apply_profile)
            if profile:
                profile_name = apply_profile
                for prof_rule in profile.rules:
                    mr = prof_rule.to_masking_rule()
                    expanded_rules.append(mr)
                    plan.expansion_rule_ids.add(id(mr))

        # ── 4. Build the ScopeDecision ──────────────────────────────────────
        decision = ScopeDecision(
            strategy=strategy,
            expanded_rules=expanded_rules,
            profile_name=profile_name,
            scope_path=scope_rule.path,
        )

        # ── 5. Record audit event ───────────────────────────────────────────
        plan.scope_events.append({
            "path":     scope_rule.path,
            "profile":  profile_name or "",
            "strategy": strategy,
            "role":     role,
        })

        # ── 6. Populate members and subtree_roots ───────────────────────────
        for root_node in root_nodes:
            plan.subtree_roots.append((root_node, decision))

            # Walk every node in this subtree and map it to the decision.
            # Later scopes override earlier ones for overlapping nodes,
            # giving the inner (more-specific) scope the last word.
            for member_node in adapter.iter_subtree(root_node):
                member_id = adapter.get_identity(member_node)
                plan.members[member_id] = decision

    return plan
