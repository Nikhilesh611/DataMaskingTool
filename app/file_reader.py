"""Safe file reader with path-traversal protection.

Returns raw bytes and the detected format string.  All parsing is
deferred to the format adapter — this module only reads bytes.
"""

from __future__ import annotations

import os
from typing import Tuple

from app.exceptions import (
    FileNotFoundError,
    PathTraversalError,
    UnsupportedFormatError,
)

# Extension → canonical format name
_EXT_TO_FORMAT: dict[str, str] = {
    ".xml": "xml",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
}


def _detect_format(filename: str) -> str:
    _, ext = os.path.splitext(filename.lower())
    try:
        return _EXT_TO_FORMAT[ext]
    except KeyError:
        raise UnsupportedFormatError(filename)


def read_file(filename: str, base_dir: str) -> Tuple[bytes, str]:
    """Read *filename* from *base_dir* and return (raw_bytes, format_string).

    Security guarantees
    -------------------
    * Resolves the absolute path of *filename* relative to *base_dir*.
    * Resolves any symbolic links via ``os.path.realpath``.
    * Verifies the resolved path starts with the resolved *base_dir* prefix,
      including a trailing separator to prevent prefix-collision attacks.

    Raises
    ------
    PathTraversalError
        If the resolved path escapes *base_dir* (via ``..`` segments,
        symlinks, or any other mechanism).
    UnsupportedFormatError
        If the file extension is not in the supported set.
    FileNotFoundError
        If the file does not exist or is not a regular file.
    """
    # Reject suspicious filenames immediately (fast path).
    if "\x00" in filename:
        raise PathTraversalError(filename)

    fmt = _detect_format(filename)

    real_base = os.path.realpath(os.path.abspath(base_dir))
    # Ensure the base anchor always ends with a separator.
    base_anchor = real_base if real_base.endswith(os.sep) else real_base + os.sep

    # Build candidate path — use only the basename to prevent absolute injection.
    # If the caller passes a path with subdirs, keep only the final component.
    safe_name = os.path.basename(filename)
    candidate = os.path.join(real_base, safe_name)
    real_candidate = os.path.realpath(os.path.abspath(candidate))

    # The resolved path must start with the base anchor.
    if not (real_candidate + os.sep).startswith(base_anchor) and real_candidate != real_base:
        # Also allow exact match to real_base (edge case: base itself is a file)
        if not real_candidate.startswith(base_anchor):
            raise PathTraversalError(filename)

    if not os.path.isfile(real_candidate):
        raise FileNotFoundError(filename)

    with open(real_candidate, "rb") as fh:
        raw_bytes = fh.read()

    return raw_bytes, fmt
