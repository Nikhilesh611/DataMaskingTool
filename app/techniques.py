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


def redact(adapter: FormatAdapter, node: Any, *, strict_types: bool = True) -> None:
    """Replace the node value with the literal string ``[REDACTED]``.

    When *strict_types* is ``True`` (default), integer and float values are
    replaced with the type-compatible default (``0`` / ``0.0``) rather than
    the string ``"[REDACTED]"``.  This prevents schema validation failures in
    downstream systems that expect numeric fields.
    """
    if strict_types:
        raw = adapter.get_value(node)
        if isinstance(raw, int):
            adapter.set_value(node, 0)
            return
        if isinstance(raw, float):
            adapter.set_value(node, 0.0)
            return
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

_SYNTHETIC_STREET_NAMES = [
    "Maple", "Oak", "Cedar", "Pine", "Highland", "Lincoln", "Washington",
    "Sunset", "Lexington", "River", "Park", "Meadow", "Hillside", "Forest",
    "Beacon", "Canyon", "Summit", "Fairview", "Willow", "Magnolia"
]
_SYNTHETIC_STREET_SUFFIXES = [
    "Avenue", "Street", "Boulevard", "Drive", "Way", "Court", "Lane", "Road", "Terrace", "Circle"
]
_SYNTHETIC_CITIES = [
    "Seattle", "Portland", "Austin", "Denver", "Chicago", "Boston", "Atlanta",
    "San Diego", "Charlotte", "Minneapolis", "Dallas", "Phoenix", "Nashville",
    "Columbus", "Salt Lake City", "Raleigh"
]
_SYNTHETIC_STATES = [
    "WA", "OR", "TX", "CO", "IL", "MA", "GA", "CA", "NC", "MN", "FL", "NY"
]
_SYNTHETIC_FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Sam", "Chris", "Casey", "Avery",
    "Cameron", "Quinn", "Riley", "Logan", "Kendall", "Skyler", "Reese"
]
_SYNTHETIC_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Vance", "Mercer",
    "Campbell", "Hawthorne", "Sterling", "Hayward"
]

def generate_synthetic_value(field_name: str, original_val: Any = None) -> Any:
    """Generate realistic, diverse synthetic data dynamically based on field semantics and original value hash."""
    seed_str = f"{field_name}:{original_val}" if original_val is not None else field_name
    h = int(hashlib.sha256(seed_str.encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(h)

    key = field_name.lower().replace("-", "_")

    if any(k in key for k in ("street", "address_line", "line1", "address1")):
        bldg = rng.randint(100, 9899)
        name = rng.choice(_SYNTHETIC_STREET_NAMES)
        suf = rng.choice(_SYNTHETIC_STREET_SUFFIXES)
        return f"{bldg} {name} {suf}"

    if "city" in key:
        return rng.choice(_SYNTHETIC_CITIES)

    if any(k in key for k in ("zip", "postal", "postcode")):
        return f"{rng.randint(10001, 99950):05d}"

    if any(k in key for k in ("state", "province")):
        return rng.choice(_SYNTHETIC_STATES)

    if any(k in key for k in ("first_name", "firstname", "fname")):
        return rng.choice(_SYNTHETIC_FIRST_NAMES)

    if any(k in key for k in ("last_name", "lastname", "lname", "surname")):
        return rng.choice(_SYNTHETIC_LAST_NAMES)

    if any(k in key for k in ("name", "full_name", "patient_name", "client_name")):
        first = rng.choice(_SYNTHETIC_FIRST_NAMES)
        last = rng.choice(_SYNTHETIC_LAST_NAMES)
        return f"{first} {last}"

    if "email" in key:
        first = rng.choice(_SYNTHETIC_FIRST_NAMES).lower()
        last = rng.choice(_SYNTHETIC_LAST_NAMES).lower()
        num = rng.randint(10, 99)
        return f"{first}.{last}{num}@synthetic-health.invalid"

    if any(k in key for k in ("phone", "mobile", "tel", "cell")):
        area = rng.randint(200, 989)
        exchange = rng.randint(200, 899)
        subscriber = rng.randint(1000, 9999)
        return f"+1-{area}-{exchange}-{subscriber:04d}"

    if any(k in key for k in ("card", "cc_num", "credit_card")):
        return f"4{rng.randint(100, 999):03d}-{rng.randint(1000, 9999):04d}-{rng.randint(1000, 9999):04d}-{rng.randint(1000, 9999):04d}"

    if any(k in key for k in ("cvv", "cvc", "security_code")):
        return f"{rng.randint(100, 999):03d}"

    if any(k in key for k in ("ssn", "social_security")):
        return f"{rng.randint(100, 999):03d}-{rng.randint(10, 99):02d}-{rng.randint(1000, 9999):04d}"

    if any(k in key for k in ("dob", "birth_date", "birthdate")):
        year = rng.randint(1950, 2005)
        month = rng.randint(1, 12)
        day = rng.randint(1, 28)
        return f"{year:04d}-{month:02d}-{day:02d}"

    if any(k in key for k in ("note", "notes", "admission", "prognosis", "summary")):
        return "[SYNTHESIZED OBSERVATION: Vital signs within standard synthetic baseline.]"

    return f"[SYNTHETIC {field_name.upper()}]"


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
    """Walk every leaf in *subtree_root* and replace it with realistic, dynamic synthetic data."""
    for node in adapter.iter_subtree(subtree_root):
        if not adapter.is_leaf_node(node):
            continue
        key = _extract_field_name(adapter, node)
        orig_val = adapter.get_value(node)
        synthetic = generate_synthetic_value(key, orig_val)
        adapter.set_value(node, synthetic)
