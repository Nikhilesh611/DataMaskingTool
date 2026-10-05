"""Group Mapper — maps IdP groups to internal masking roles.

Design decisions
----------------

Separation of concerns:
    The policy YAML owns masking profiles and their rules.
    This module owns the mapping from enterprise identity (IdP group) to the
    masking service's internal authorization representation (masking role).
    These two concerns are deliberately kept separate so that:
      - IdP group assignments can change without touching masking logic.
      - The same masking profile can be reused by multiple IdP groups.
      - IdP admins do not need access to the policy YAML.

Translation chain:
    JWT claim "groups": ["finance-team"]
        → GroupMappingStore.resolve_role(["finance-team"])
        → "auditor"                              (masking service internal role)
        → policy.roles["auditor"]               (policy YAML)
        → scope.roles["auditor"].profile = "card_data"
        → masking pipeline applies card_data rules

    Multi-tenant chain (Phase 2):
        JWT claim "groups": ["finance-team"]
            → resolve_role_for_tenant(["finance-team"], tenant_id, db)
            → MaskingPolicy.name = "Finance Restricted" (stored in DB)
            → returned as internal_role to the masking pipeline

Multiple-group resolution:
    When a user belongs to multiple IdP groups, exactly one internal role must
    be selected.  The strategy is explicit priority ordering:
      - Each mapping has a ``priority`` integer (default 0).
      - Lower value = higher priority.
      - The mapping with the lowest priority value whose group is in the user's
        group list wins.
      - If two mappings share the same priority, the one that appears first in
        the mappings file (file order = list order) wins.
      - This is deterministic and not dependent on JWT claim order.

Fail-closed:
    If no group in the user's list has a mapping, both resolve_role() and
    resolve_role_for_tenant() return None.  The caller (auth layer) must treat
    None as HTTP 403 — not as a fallback to unmasked access.

Persistence:
    Single-tenant mode: mappings are stored in a JSON file (IDP_MAPPINGS_PATH).
    Multi-tenant mode: mappings are stored in the ``group_mappings`` DB table,
    keyed by ``tenant_id``.  The DB-backed path is used by Phase 2 routes.

    Phase 2 admin API can manage mappings at runtime without a server restart.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class GroupMapping:
    """Maps one IdP group name to one internal masking role.

    Attributes
    ----------
    group:
        The IdP group name exactly as it appears in the JWT claim
        (e.g. ``"finance-team"``).  Case-sensitive.
    internal_role:
        A key in ``policy.roles`` (e.g. ``"auditor"``).  This is the internal
        masking role that the pipeline consumes — not a masking profile name.
    priority:
        Lower value = higher priority.  Used for multi-group resolution.
        Default 0.  Must be a non-negative integer.
    """

    group: str
    internal_role: str
    priority: int = 0

    def __post_init__(self) -> None:
        if not self.group:
            raise ValueError("GroupMapping.group must not be empty.")
        if not self.internal_role:
            raise ValueError("GroupMapping.internal_role must not be empty.")
        if self.priority < 0:
            raise ValueError("GroupMapping.priority must be >= 0.")


# ── Store ─────────────────────────────────────────────────────────────────────

class GroupMappingStore:
    """In-memory group mapping store backed by a JSON file.

    Thread safety: FastAPI/uvicorn runs a single asyncio event loop per worker.
    Writes use a simple replacement pattern (replace list in memory, then
    write file) which is safe for this single-event-loop model.
    """

    def __init__(self) -> None:
        self._mappings: list[GroupMapping] = []

    # ── Persistence ───────────────────────────────────────────────────────────

    def load(self, path: str) -> None:
        """Load mappings from *path*.  Clears any existing in-memory state.

        Raises
        ------
        FileNotFoundError
            If *path* does not exist.
        ValueError
            If the file contains invalid JSON or an invalid mapping entry.
        """
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"IDP_MAPPINGS_PATH '{path}' does not exist. "
                "Create the file (even as an empty list '[]') before starting "
                "in enterprise_jwt mode."
            )
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, list):
            raise ValueError(
                f"group_mappings file at '{path}' must contain a JSON array."
            )
        self._mappings = [GroupMapping(**item) for item in raw]

    def save(self, path: str) -> None:
        """Write current mappings to *path* as JSON."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([asdict(m) for m in self._mappings], fh, indent=2)

    # ── Resolution ────────────────────────────────────────────────────────────

    def resolve_role(self, groups: list[str]) -> Optional[str]:
        """Return the internal masking role for the best-matching group.

        The best match is the mapping with the lowest ``priority`` value whose
        ``group`` is in *groups*.  Ties in priority are broken by list order
        (the mapping that appears first in the file wins).

        Returns None if no mapping matches — the caller must treat this as
        an authorization failure (HTTP 403), never as a fallback to unmasked
        access.
        """
        if not groups or not self._mappings:
            return None

        group_set = set(groups)
        candidates = [m for m in self._mappings if m.group in group_set]
        if not candidates:
            return None

        # Stable sort: primary key = priority (asc), secondary = original order.
        # Python's sort is stable, so equal-priority items retain file order.
        candidates.sort(key=lambda m: m.priority)
        return candidates[0].internal_role

    # ── CRUD (used by Phase 2 admin API) ──────────────────────────────────────

    def list_mappings(self) -> list[GroupMapping]:
        """Return a copy of all mappings in file order."""
        return list(self._mappings)

    def upsert(self, mapping: GroupMapping) -> None:
        """Add or replace the mapping for ``mapping.group``."""
        for i, existing in enumerate(self._mappings):
            if existing.group == mapping.group:
                self._mappings[i] = mapping
                return
        self._mappings.append(mapping)

    def delete(self, group: str) -> bool:
        """Remove the mapping for *group*.  Returns True if it existed."""
        before = len(self._mappings)
        self._mappings = [m for m in self._mappings if m.group != group]
        return len(self._mappings) < before

    def get(self, group: str) -> Optional[GroupMapping]:
        """Return the mapping for *group*, or None if not found."""
        return next((m for m in self._mappings if m.group == group), None)


# ── Module-level singleton ────────────────────────────────────────────────────
# Populated at startup by main.py when AUTH_MODE=enterprise_jwt.

_store: GroupMappingStore = GroupMappingStore()


def get_group_mapping_store() -> GroupMappingStore:
    return _store


def set_group_mapping_store(store: GroupMappingStore) -> None:
    """Replace the module-level store — used in tests."""
    global _store
    _store = store


# ── Multi-tenant DB-backed resolution (Phase 2) ────────────────────────────────

async def resolve_role_and_policy_for_tenant(
    groups: list[str],
    tenant_id: str,
    db: "AsyncSession",
) -> tuple[str, Any] | None:
    """Resolve both the internal role name and parsed MaskingPolicy for *groups*.

    Queries the ``group_mappings`` table joined with ``masking_policies`` filtered by *tenant_id*.
    Retrieves the parsed policy from L1 cache (key: ``tenant:<tenant_id>:policy:<policy_id>``)
    or compiles it from ``policy_yaml`` in the database and caches it.
    """
    if not groups:
        return None

    from sqlalchemy import select
    from app.db.models import GroupMapping, MaskingPolicy
    from app.cache.l1_cache import get_l1_cache
    from app.policy.loader import load_policy_from_string

    result = await db.execute(
        select(GroupMapping, MaskingPolicy)
        .join(MaskingPolicy, MaskingPolicy.id == GroupMapping.policy_id)
        .where(GroupMapping.tenant_id == tenant_id)
        .where(GroupMapping.external_group.in_(groups))
        .where(MaskingPolicy.is_active.is_(True))
        .order_by(GroupMapping.priority.asc(), GroupMapping.created_at.asc())
        .limit(1)
    )
    row = result.first()
    if row is None:
        return None

    mapping, policy_db = row
    parsed = None
    if policy_db.policy_yaml:
        try:
            cache_key = f"tenant:{tenant_id}:policy:{policy_db.id}"
            cache = get_l1_cache()
            parsed = cache.get(cache_key)
            if parsed is None:
                parsed = load_policy_from_string(policy_db.policy_yaml)
                cache.set(cache_key, parsed)
        except Exception:
            parsed = None

    # Determine internal role:
    # 1. Use explicit mapping.internal_role if set by admin
    # 2. Fall back to policy_db.name if it matches a role in policy.roles
    # 3. Fall back to the first defined role in policy.roles
    # 4. If policy has no roles defined (universal policy), use "default"
    assigned_role = mapping.internal_role
    if not assigned_role:
        if parsed and parsed.roles:
            if policy_db.name in parsed.roles:
                assigned_role = policy_db.name
            else:
                assigned_role = next(iter(parsed.roles.keys()))
        else:
            assigned_role = "default"

    return assigned_role, parsed


async def resolve_role_for_tenant(
    groups: list[str],
    tenant_id: str,
    db: "AsyncSession",
) -> Optional[str]:
    """Resolve the internal masking role for *groups* using the database.

    Queries the ``group_mappings`` table filtered strictly by *tenant_id*, then
    applies priority ordering.
    """
    res = await resolve_role_and_policy_for_tenant(groups, tenant_id, db)
    return res[0] if res else None
