"""Format adapter registry and format detection.

Accessing an unsupported format raises ``UnsupportedFormatError`` so the web
layer can immediately return HTTP 400 without touching the pipeline.

Registering a new adapter requires only calling ``register_adapter`` — no
existing code needs modification.
"""

from __future__ import annotations

from typing import Dict

from app.adapters.base import FormatAdapter
from app.adapters.json_adapter import JSONAdapter
from app.adapters.xml_adapter import XMLAdapter
from app.adapters.yaml_adapter import YAMLAdapter
from app.exceptions import UnsupportedFormatError

# ── Extension → canonical format name ────────────────────────────────────────

_EXT_MAP: Dict[str, str] = {
    ".xml": "xml",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
}

# ── Adapter registry ──────────────────────────────────────────────────────────

_REGISTRY: Dict[str, FormatAdapter] = {
    "xml": XMLAdapter(),
    "json": JSONAdapter(),
    "yaml": YAMLAdapter(),
}


def register_adapter(fmt: str, adapter: FormatAdapter) -> None:
    """Register a new adapter without modifying any existing code.

    Parameters
    ----------
    fmt:
        Canonical format name (e.g. ``"toml"``).
    adapter:
        An instance of a class that satisfies the ``FormatAdapter`` interface.
    """
    _REGISTRY[fmt] = adapter


def get_adapter(fmt: str) -> FormatAdapter:
    """Return the adapter for *fmt*, raising ``UnsupportedFormatError`` on miss."""
    try:
        return _REGISTRY[fmt]
    except KeyError:
        raise UnsupportedFormatError(fmt)


def detect_format(filename: str) -> str:
    """Derive the canonical format string from *filename*'s extension.

    Raises ``UnsupportedFormatError`` for unrecognised extensions.
    """
    import os
    _, ext = os.path.splitext(filename.lower())
    try:
        return _EXT_MAP[ext]
    except KeyError:
        raise UnsupportedFormatError(filename)


def supported_formats() -> list[str]:
    """Return the list of registered format names."""
    return sorted(_REGISTRY.keys())
