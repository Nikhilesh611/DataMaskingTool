"""Masking technique callables — v2.0.

v1.0 techniques (unchanged)
----------------------------
suppress, nullify, redact, pseudonymize, generalize, format_preserve, noise

v2.0 additions
--------------
mask_pattern        Partial reveal with a pattern string (element-level).
deep_redact_subtree Walk every leaf in a subtree and set it to [REDACTED].
synthesize_subtree  Walk every leaf in a subtree and replace it with
                    plausible synthetic data keyed by field name.

All functions accept a FormatAdapter instance so they are format-agnostic.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import uuid
from typing import Any, Optional

from app.adapters.base import FormatAdapter


# ── v1.0 techniques ───────────────────────────────────────────────────────────

def suppress(adapter: FormatAdapter, node: Any) -> None:
    """Detach *node* from the tree.  Descendants are implicitly removed."""
    adapter.remove_node(node)


def nullify(adapter: FormatAdapter, node: Any) -> None:
    """Replace the node value with *None* (null / empty in the output format)."""
    adapter.set_value(node, None)


def redact(adapter: FormatAdapter, node: Any) -> None:
    """Replace the node value with the literal string ``[REDACTED]``."""
    adapter.set_value(node, "[REDACTED]")


def pseudonymize(
    adapter: FormatAdapter,
    node: Any,
    *,
    consistent: bool = True,
) -> None:
    """Replace the node value with a pseudonym.

    When *consistent* is ``True`` (default) the pseudonym is the SHA-256
    digest of the original value, truncated to eight hex characters and
    prefixed with ``ANON_``.  The same input always produces the same output.

    When *consistent* is ``False`` a fresh random UUID-based token is
    generated each time.
    """
    if consistent:
        raw_value = adapter.get_value(node)
        text = str(raw_value) if raw_value is not None else ""
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
        token = f"ANON_{digest}"
    else:
        token = f"ANON_{uuid.uuid4().hex[:8]}"
    adapter.set_value(node, token)


def generalize(
    adapter: FormatAdapter,
    node: Any,
    *,
    hierarchy: str,
    level: int,
    coverage_log: Optional[list] = None,
    node_path: str = "",
) -> None:
    """Replace the node value with its generalised form."""
    from app.hierarchies.base import HIERARCHY_REGISTRY

    raw_value = adapter.get_value(node)
    value_str = str(raw_value) if raw_value is not None else ""

    h = HIERARCHY_REGISTRY.get(hierarchy)
    if h is None:
        adapter.set_value(node, "[REDACTED]")
        if coverage_log is not None:
            coverage_log.append(
                {"path": node_path, "reason": f"Hierarchy '{hierarchy}' not found; used [REDACTED]."}
            )
        return

    result = h.generalise(value_str, level)
    if result == "[REDACTED]" and coverage_log is not None:
        coverage_log.append(
            {
                "path": node_path,
                "reason": f"Hierarchy '{hierarchy}' could not process value at level {level}; used [REDACTED].",
            }
        )
    adapter.set_value(node, result)


def format_preserve(adapter: FormatAdapter, node: Any) -> None:
    """Scramble the node value while preserving character classes."""
    raw_value = adapter.get_value(node)
    text = str(raw_value) if raw_value is not None else ""
    result = []
    for ch in text:
        if ch.isdigit():
            result.append(random.choice(string.digits))
        elif ch.isupper():
            result.append(random.choice(string.ascii_uppercase))
        elif ch.islower():
            result.append(random.choice(string.ascii_lowercase))
        else:
            result.append(ch)
    adapter.set_value(node, "".join(result))


def noise(
    adapter: FormatAdapter,
    node: Any,
    *,
    percent: float = 10.0,
    coverage_log: Optional[list] = None,
    node_path: str = "",
) -> None:
    """Add up to ±*percent*% random noise to a numeric node value."""
    raw_value = adapter.get_value(node)
    try:
        f = float(str(raw_value))
    except (ValueError, TypeError):
        adapter.set_value(node, "[REDACTED]")
        if coverage_log is not None:
            coverage_log.append(
                {
                    "path": node_path,
                    "reason": f"noise: could not parse '{raw_value}' as float; used [REDACTED].",
                }
            )
        return

    band = abs(f) * (percent / 100.0)
    delta = random.uniform(-band, band)
    result = round(f + delta, 2)
    adapter.set_value(node, str(result))


# ── v2.0 element-level technique ─────────────────────────────────────────────

def mask_pattern(adapter: FormatAdapter, node: Any, *, pattern: str) -> None:
    """Partial reveal via a format pattern string.

    Supported placeholders
    ----------------------
    ``{last4}``   last 4 characters of the value
    ``{last2}``   last 2 characters
    ``{first4}``  first 4 characters
    ``{first2}``  first 2 characters

    Example: pattern ``"****-****-****-{last4}"`` on ``"4111-1111-1111-1234"``
    produces ``"****-****-****-1234"``.
    """
    raw = adapter.get_value(node)
    text = str(raw) if raw is not None else ""
    result = pattern
    if "{last4}" in result:
        result = result.replace("{last4}", text[-4:] if len(text) >= 4 else text)
    if "{last2}" in result:
        result = result.replace("{last2}", text[-2:] if len(text) >= 2 else text)
    if "{first4}" in result:
        result = result.replace("{first4}", text[:4] if len(text) >= 4 else text)
    if "{first2}" in result:
        result = result.replace("{first2}", text[:2] if len(text) >= 2 else text)
    adapter.set_value(node, result)


# ── v2.0 subtree-level operations ────────────────────────────────────────────

# Field-name → synthetic value lookup.  Keys are lowercase field name suffixes.
SYNTHETIC_VALUES: dict[str, str] = {
    "street":            "742 Evergreen Terrace",
    "city":              "Springfield",
    "zip":               "00000",
    "zipcode":           "00000",
    "postcode":          "00000",
    "email":             "anon@synthetic.invalid",
    "phone":             "+1-000-000-0000",
    "mobile":            "+1-000-000-0001",
    "name":              "[SYNTHETIC NAME]",
    "firstname":         "[SYNTHETIC]",
    "lastname":          "[SYNTHETIC]",
    "amount":            "0.00",
    "card_number":       "****-****-****-0000",
    "cvv":               "***",
    "cvc":               "***",
    "note":              "[SYNTHETIC NOTE]",
    "notes":             "[SYNTHETIC NOTES]",
    "admission_note":    "[SYNTHETIC NOTE]",
    "progress_note":     "[SYNTHETIC NOTE]",
    "discharge_summary": "[SYNTHETIC NOTE]",
    "ssn":               "***-**-****",
    "dob":               "1900-01-01",
    "address":           "[SYNTHETIC ADDRESS]",
}

DEFAULT_SYNTHETIC = "[SYNTHETIC]"


def _extract_field_name(adapter: FormatAdapter, node: Any) -> str:
    """Extract the leaf field name from a node's path string."""
    try:
        path = adapter.get_path(node)
        parts = re.split(r"[./\[\]@]+", path)
        parts = [p for p in parts if p and not p.isdigit() and p not in ("$", "")]
        return parts[-1].lower() if parts else ""
    except Exception:
        return ""


def deep_redact_subtree(adapter: FormatAdapter, subtree_root: Any) -> None:
    """Walk every leaf in *subtree_root* and set its value to ``[REDACTED]``.

    Container nodes (dict / list / XML elements with children) are left
    structurally intact; only scalar leaf values are overwritten.
    """
    for node in adapter.iter_subtree(subtree_root):
        if adapter.is_leaf_node(node):
            adapter.set_value(node, "[REDACTED]")


def synthesize_subtree(adapter: FormatAdapter, subtree_root: Any) -> None:
    """Walk every leaf in *subtree_root* and replace it with synthetic data.

    Field-name heuristics from ``SYNTHETIC_VALUES`` are used; unknown fields
    fall back to ``DEFAULT_SYNTHETIC``.  Container structure is preserved.
    """
    for node in adapter.iter_subtree(subtree_root):
        if not adapter.is_leaf_node(node):
            continue
        key = _extract_field_name(adapter, node)
        synthetic = SYNTHETIC_VALUES.get(key, DEFAULT_SYNTHETIC)
        adapter.set_value(node, synthetic)
