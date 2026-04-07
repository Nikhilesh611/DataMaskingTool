"""Seven standalone masking technique callables.

Each technique accepts an adapter instance and a node object (plus optional
keyword parameters) and modifies the node in place via the adapter interface.
Techniques are importable and callable in complete isolation — no pipeline
state or server context is required.
"""

from __future__ import annotations

import hashlib
import random
import string
import uuid
from typing import Any, Optional

from app.adapters.base import FormatAdapter


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
    """Replace the node value with its generalised form.

    Looks up *hierarchy* in the hierarchy registry and calls ``generalise``
    with the current value and *level*.  Falls back to ``[REDACTED]`` when
    the value cannot be processed, recording the fallback in *coverage_log*
    if supplied.
    """
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
    """Scramble the node value while preserving character classes.

    Digits → random digits, uppercase → random uppercase, lowercase →
    random lowercase, all other characters pass through unchanged.
    """
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
    """Add up to ±*percent*% random noise to a numeric node value.

    Falls back to ``[REDACTED]`` if the value cannot be parsed as a float,
    recording the fallback in *coverage_log* if supplied.
    """
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
