"""Policy YAML loader.

Reads the policy file once at startup, validates it with Pydantic, and
caches the result.  Nothing else reads the file after startup.

If validation fails the loader collects *all* errors, prints them clearly
(with rule index and field), and raises ``PolicyValidationError`` so
``main.py`` can exit cleanly.
"""

from __future__ import annotations

import sys
from typing import Optional

import yaml
from pydantic import ValidationError

from app.exceptions import PolicyValidationError
from app.policy.models import MaskingPolicy

_policy: Optional[MaskingPolicy] = None


def load_policy(path: str) -> MaskingPolicy:
    """Load, validate, and cache the policy from *path*.

    Raises
    ------
    PolicyValidationError
        If the YAML is malformed or Pydantic validation fails.
    """
    global _policy

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        raise PolicyValidationError([f"Policy file not found: '{path}'."])
    except yaml.YAMLError as exc:
        raise PolicyValidationError([f"Policy YAML syntax error: {exc}"])

    if not isinstance(raw, dict):
        raise PolicyValidationError(["Policy must be a YAML mapping at the top level."])

    try:
        policy = MaskingPolicy.model_validate(raw)
    except ValidationError as exc:
        errors: list[str] = []
        for error in exc.errors():
            loc = " → ".join(str(l) for l in error["loc"])
            msg = error["msg"]
            errors.append(f"[{loc}] {msg}")
        raise PolicyValidationError(errors)

    _policy = policy
    return policy


def load_policy_from_string(yaml_text: str) -> MaskingPolicy:
    """Parse and validate a policy from a YAML string (used in tests).

    Raises
    ------
    PolicyValidationError
        If validation fails.
    """
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise PolicyValidationError([f"Policy YAML syntax error: {exc}"])

    if not isinstance(raw, dict):
        raise PolicyValidationError(["Policy must be a YAML mapping at the top level."])

    try:
        return MaskingPolicy.model_validate(raw)
    except ValidationError as exc:
        errors: list[str] = []
        for error in exc.errors():
            loc = " → ".join(str(l) for l in error["loc"])
            msg = error["msg"]
            errors.append(f"[{loc}] {msg}")
        raise PolicyValidationError(errors)


def get_policy() -> MaskingPolicy:
    """Return the cached policy singleton.

    Raises ``RuntimeError`` if called before ``load_policy``.
    """
    if _policy is None:
        raise RuntimeError("Policy has not been loaded. Call load_policy() at startup.")
    return _policy
