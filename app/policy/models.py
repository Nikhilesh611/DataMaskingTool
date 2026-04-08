"""Policy Pydantic v2 models.

Validated once at startup; after that the policy is an immutable object
passed through the call stack by reference.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ── Valid technique names ─────────────────────────────────────────────────────

TechniqueName = Literal[
    "suppress",
    "nullify",
    "redact",
    "pseudonymize",
    "generalize",
    "format_preserve",
    "noise",
]


# ── Individual masking rule ───────────────────────────────────────────────────

class MaskingRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    selector: str = Field(..., description="XPath (XML) or JSONPath (JSON/YAML) selector.")
    technique: TechniqueName
    # Technique-specific optional fields
    hierarchy: Optional[str] = None
    level: Optional[int] = None
    consistent: Optional[bool] = True  # pseudonymize only

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
        return self


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

    @model_validator(mode="after")
    def _validate_hierarchy_names(self) -> "MaskingPolicy":
        """Verify that every generalise rule names a registered hierarchy."""
        from app.hierarchies.base import HIERARCHY_REGISTRY  # late import avoids circular
        for i, rule in enumerate(self.rules):
            if rule.technique == "generalize" and rule.hierarchy is not None:
                if rule.hierarchy not in HIERARCHY_REGISTRY:
                    registered = sorted(HIERARCHY_REGISTRY.keys())
                    raise ValueError(
                        f"Rule {i}: hierarchy '{rule.hierarchy}' is not registered. "
                        f"Registered hierarchies: {registered}."
                    )
        return self
