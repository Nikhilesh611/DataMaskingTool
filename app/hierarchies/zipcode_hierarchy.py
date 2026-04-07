"""Postal-code generalisation hierarchy.

Each level replaces one additional trailing character with ``*``.
Works for any postal code length (not just five-digit US ZIP codes).

Level 0  →  exact code          (e.g. ``10001``)
Level 1  →  last char masked    (e.g. ``1000*``)
Level 2  →  last 2 chars masked (e.g. ``100**``)
…
Level N  →  fully masked        (e.g. ``*****``)

``max_level`` is defined as a large constant; generalise saturates at full
masking regardless of the actual code length passed in.
"""

from __future__ import annotations

from app.hierarchies.base import Hierarchy, register_hierarchy

_MAX = 20  # generous upper bound; actual saturation depends on code length


class ZipCodeHierarchy(Hierarchy):
    @property
    def max_level(self) -> int:
        return _MAX

    def generalise(self, value: str, level: int) -> str:
        if level <= 0:
            return value
        code = str(value).strip()
        if not code:
            return "*"
        n = min(level, len(code))
        return code[: len(code) - n] + "*" * n


# Auto-register.
register_hierarchy("zipcode", ZipCodeHierarchy())
