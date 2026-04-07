"""Date generalisation hierarchy.

Level 0  →  exact ISO date  (e.g. ``1985-07-23``)
Level 1  →  month-year      (e.g. ``1985-07``)
Level 2  →  year only       (e.g. ``1985``)
Level 3  →  decade          (e.g. ``1980*``)
Level 4  →  fully suppressed  (``*``)

Values that cannot be parsed as an ISO date pass through ``[REDACTED]`` at
level > 0 so the caller can log the fallback.
"""

from __future__ import annotations

from datetime import date

from app.hierarchies.base import Hierarchy, register_hierarchy


class DateHierarchy(Hierarchy):
    @property
    def max_level(self) -> int:
        return 4

    def generalise(self, value: str, level: int) -> str:
        if level <= 0:
            return value
        if level >= 4:
            return "*"

        try:
            d = date.fromisoformat(value.strip())
        except (ValueError, AttributeError):
            return "[REDACTED]"

        if level == 1:
            return d.strftime("%Y-%m")
        if level == 2:
            return str(d.year)
        if level == 3:
            decade = (d.year // 10) * 10
            return f"{decade}*"

        return "*"  # unreachable but safe


# Auto-register when this module is imported.
register_hierarchy("date", DateHierarchy())
