"""Declarative base for all SQLAlchemy ORM models.

All models must inherit from ``Base``.  Importing this module registers
them in ``Base.metadata`` so ``create_all()`` picks them up.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Project-wide SQLAlchemy declarative base."""
    pass
