"""Hierarchy abstract base class and registry.

The registry pattern mirrors the adapter registry: call ``register_hierarchy``
to add a new hierarchy without modifying any existing code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict


class Hierarchy(ABC):
    """Contract that all generalisation hierarchies must satisfy."""

    @abstractmethod
    def generalise(self, value: str, level: int) -> str:
        """Return *value* generalised to *level*.

        Level 0 is the most specific (usually the original value).
        Higher levels are progressively more general.
        If *level* exceeds ``max_level`` the implementation must return
        the most generalised form (not raise).
        """

    @property
    @abstractmethod
    def max_level(self) -> int:
        """Maximum supported generalisation level (inclusive)."""


# ── Registry ──────────────────────────────────────────────────────────────────

HIERARCHY_REGISTRY: Dict[str, Hierarchy] = {}


def register_hierarchy(name: str, instance: Hierarchy) -> None:
    """Register *instance* under *name*.  Existing entries are overwritten."""
    HIERARCHY_REGISTRY[name] = instance


def get_hierarchy(name: str) -> Hierarchy:
    """Return the hierarchy registered as *name*.

    Raises ``KeyError`` if not found — callers that need a soft error should
    catch ``KeyError`` and fall back to ``[REDACTED]``.
    """
    return HIERARCHY_REGISTRY[name]
