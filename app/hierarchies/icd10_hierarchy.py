"""ICD-10 diagnosis-code generalisation hierarchy.

Level 0  →  exact code          (e.g. ``J18.9``)
Level 1  →  3-char category     (e.g. ``J18``)
Level 2  →  chapter wildcard    (e.g. ``J**``)
Level 3  →  fully suppressed    (``***``)

Values that do not look like ICD-10 codes (at least one letter followed by
two digits) fall through to ``[REDACTED]`` at level > 0.
"""

from __future__ import annotations

import re

from app.hierarchies.base import Hierarchy, register_hierarchy

_ICD10_RE = re.compile(r"^([A-Za-z])(\d{2})(.*)$")


class ICD10Hierarchy(Hierarchy):
    @property
    def max_level(self) -> int:
        return 3

    def generalise(self, value: str, level: int) -> str:
        if level <= 0:
            return value
        if level >= 3:
            return "***"

        code = str(value).strip().upper()
        m = _ICD10_RE.match(code)
        if not m:
            return "[REDACTED]"

        letter, digits, _ = m.groups()

        if level == 1:
            return f"{letter}{digits}"
        if level == 2:
            return f"{letter}**"

        return "***"


# Auto-register.
register_hierarchy("icd10", ICD10Hierarchy())
