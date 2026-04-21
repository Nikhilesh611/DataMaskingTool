"""Policy Pydantic v2 models — v2.0.

Validated once at startup; after that the policy is an immutable object
passed through the call stack by reference.

v2.0 additions
--------------
* ``TechniqueName`` gains ``"mask_pattern"`` (element-level partial reveal).
* ``MaskingRule`` gains optional ``pattern`` field (mask_pattern only).
* ``ProfileRule``   — a rule inside a named profile (selector is absolute).
* ``MaskingProfile`` — named, reusable collection of ProfileRules.
* ``RoleDefinition`` — globally defines a role and its default fallback strategy.
* ``RoleStrategy``  — per-role strategy for a scope (now contains `profile`).
* ``ScopeRule``     — path-bounded subtree with role strategies.
* ``MaskingPolicy`` gains ``roles`` dict for dynamic role registration.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ── Valid technique names ─────────────────────────────────────────────────────

TechniqueName = Literal[
    # v1.0 techniques
    "suppress",
    "nullify",
    "redact",
    "pseudonymize",
    "generalize",
    "format_preserve",
    "noise",
    # v2.0 techniques (element-level)
    "mask_pattern",   # partial reveal via a pattern string e.g. "****-{last4}"
]


# ── Individual masking rule ───────────────────────────────────────────────────

class MaskingRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    selector: str = Field(..., description="XPath (XML) or JSONPath (JSON/YAML) selector.")
    technique: TechniqueName
    # Technique-specific optional fields
    hierarchy: Optional[str] = None
    level: Optional[int] = None
    consistent: Optional[bool] = True   # pseudonymize only
    pattern: Optional[str] = None       # mask_pattern only (e.g. "****-****-****-{last4}")

    @model_validator(mode="after")
    def _validate_technique_params(self) -> "MaskingRule":
        if self.technique == "generalize":
            if self.hierarchy is None:
                raise ValueError(
                    "Rules using 'generalize' must specify 'hierarchy'."
                )
            if self.level is None:
                raise ValueError(
                    "Rules using 'generalize' must specify 'level'."
                )
            if self.level < 0:
                raise ValueError(
                    f"'level' must be a non-negative integer, got {self.level}."
                )
        if self.technique == "mask_pattern" and self.pattern is None:
            raise ValueError(
                "Rules using 'mask_pattern' must specify 'pattern'."
            )
        return self


# ── v2.0: Profile rule (selector is absolute, validated same as MaskingRule) ──

class ProfileRule(BaseModel):
    """A rule inside a MaskingProfile.

    Selectors are the same absolute XPath / JSONPath strings as global rules.
    Phase 1 evaluates them against the whole tree, then filters results to
    nodes that fall within the scope boundary.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    selector: str
    technique: TechniqueName
    hierarchy: Optional[str] = None
    level: Optional[int] = None
    consistent: Optional[bool] = True
    pattern: Optional[str] = None

    @model_validator(mode="after")
    def _validate(self) -> "ProfileRule":
        if self.technique == "generalize":
            if self.hierarchy is None:
                raise ValueError("ProfileRule using 'generalize' must specify 'hierarchy'.")
            if self.level is None:
                raise ValueError("ProfileRule using 'generalize' must specify 'level'.")
        if self.technique == "mask_pattern" and self.pattern is None:
            raise ValueError("ProfileRule using 'mask_pattern' must specify 'pattern'.")
        return self

    def to_masking_rule(self) -> "MaskingRule":
        """Convert to a full MaskingRule for use inside the pipeline."""
        return MaskingRule(
            selector=self.selector,
            technique=self.technique,
            hierarchy=self.hierarchy,
            level=self.level,
            consistent=self.consistent,
            pattern=self.pattern,
        )


# ── v2.0: Masking Profile ─────────────────────────────────────────────────────

class MaskingProfile(BaseModel):
    """Named, reusable collection of rules.  Applied inside scope boundaries."""
    model_config = ConfigDict(frozen=True)

    rules: List[ProfileRule] = Field(default_factory=list)


# ── v3.0: Role Definition ─────────────────────────────────────────────────────

class RoleDefinition(BaseModel):
    """Defines a role globally and sets its default fallback strategy."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    default_fallback: Literal[
        "masked",
        "drop_subtree",
        "default_allow",
        "deep_redact",
        "synthesize",
    ] = "default_allow"


# ── v3.0: Role strategy within a scope ───────────────────────────────────────

class RoleStrategy(BaseModel):
    """Defines how a specific role is handled inside a scope.

    Strategies
    ----------
    masked        Apply profile + inline rules to nodes within this scope as
                  normal element-level masking.
    drop_subtree  Remove the entire subtree from the document.
    default_allow Leave all nodes within the subtree entirely unchanged (no
                  masking, no auditor labelling).
    deep_redact   Keep the subtree structure but replace every leaf value with
                  ``[REDACTED]``.
    synthesize    Keep the subtree structure but replace every leaf value with
                  plausible synthetic data using field-name heuristics.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    strategy: Literal[
        "masked",
        "drop_subtree",
        "default_allow",
        "deep_redact",
        "synthesize",
    ] = "masked"
    profile: Optional[str] = None


# ── v3.0: Scope rule ─────────────────────────────────────────────────────────

class ScopeRule(BaseModel):
    """A path-bounded masking zone with role strategies.

    ``path``          XPath or JSONPath selector identifying the subtree root(s).
    ``roles``         Maps role name to ``RoleStrategy``.
    ``rules``         Inline rules merged with the profile's rules.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(..., description="Selector identifying the subtree root(s).")
    roles: Dict[str, RoleStrategy] = Field(default_factory=dict)
    rules: List[ProfileRule] = Field(default_factory=list)


# ── k-Anonymity configuration ─────────────────────────────────────────────────

class KAnonConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    k: int = Field(..., gt=1, description="Minimum equivalence class size; must be > 1.")
    quasi_identifiers: List[str] = Field(default_factory=list)


# ── Top-level policy ──────────────────────────────────────────────────────────

class MaskingPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    format: Optional[str] = None          # overrides file extension detection
    record_root: str | List[str]           # selector(s) that identify record boundaries
    rules: List[MaskingRule] = Field(default_factory=list)
    k_anonymity: Optional[KAnonConfig] = None

    # v3.0 additions
    roles: Dict[str, RoleDefinition] = Field(default_factory=dict)
    profiles: Dict[str, MaskingProfile] = Field(default_factory=dict)
    scopes: List[ScopeRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_all(self) -> "MaskingPolicy":
        """Combined validator: checks hierarchy names and profile references."""
        from app.hierarchies.base import HIERARCHY_REGISTRY  # late import avoids circular

        # Validate hierarchy names in global rules
        for i, rule in enumerate(self.rules):
            if rule.technique == "generalize" and rule.hierarchy is not None:
                if rule.hierarchy not in HIERARCHY_REGISTRY:
                    registered = sorted(HIERARCHY_REGISTRY.keys())
                    raise ValueError(
                        f"Rule {i}: hierarchy '{rule.hierarchy}' is not registered. "
                        f"Registered hierarchies: {registered}."
                    )

        # Validate hierarchy names in profile rules
        for prof_name, profile in self.profiles.items():
            for j, prule in enumerate(profile.rules):
                if prule.technique == "generalize" and prule.hierarchy is not None:
                    if prule.hierarchy not in HIERARCHY_REGISTRY:
                        registered = sorted(HIERARCHY_REGISTRY.keys())
                        raise ValueError(
                            f"Profile '{prof_name}' rule {j}: hierarchy "
                            f"'{prule.hierarchy}' is not registered. "
                            f"Registered: {registered}."
                        )

        # Validate profile references in scope role strategies and role existence
        for i, scope in enumerate(self.scopes):
            for role_name, role_strat in scope.roles.items():
                if role_name != "default" and role_name not in self.roles:
                    registered_roles = sorted(self.roles.keys())
                    raise ValueError(
                        f"Scope {i} (path='{scope.path}'): role '{role_name}' "
                        f"is not defined in the top-level 'roles' registry. "
                        f"Defined roles: {registered_roles}."
                    )
                if role_strat.profile and role_strat.profile not in self.profiles:
                    registered = sorted(self.profiles.keys())
                    raise ValueError(
                        f"Scope {i} (path='{scope.path}'), role '{role_name}': "
                        f"profile '{role_strat.profile}' is not defined in profiles. "
                        f"Defined profiles: {registered}."
                    )

        return self
