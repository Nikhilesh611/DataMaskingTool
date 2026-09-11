"""Custom exception hierarchy for the masking API.

Every exception carries enough context to produce a useful HTTP error response.
HTTP status mapping is registered centrally in main.py — no endpoint handler
should catch these exceptions directly.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class MaskingAPIError(Exception):
    """Base class for all application-level exceptions."""

    def __init__(self, message: str, detail: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class PathTraversalError(MaskingAPIError):
    """Requested path escapes the allowed base directory. → HTTP 403"""

    def __init__(self, requested: str) -> None:
        super().__init__(
            f"Access denied: '{requested}' resolves outside the permitted data directory.",
            detail={"requested": requested},
        )


class FileNotFoundError(MaskingAPIError):  # noqa: A001 — intentional shadowing
    """Requested file does not exist. → HTTP 404"""

    def __init__(self, filename: str) -> None:
        super().__init__(
            f"File not found: '{filename}'.",
            detail={"filename": filename},
        )


class UnsupportedFormatError(MaskingAPIError):
    """File extension is not in the supported set. → HTTP 400"""

    SUPPORTED = (".xml", ".json", ".yaml", ".yml")

    def __init__(self, filename: str) -> None:
        super().__init__(
            f"Unsupported file format for '{filename}'. "
            f"Supported extensions: {', '.join(self.SUPPORTED)}.",
            detail={"filename": filename, "supported": list(self.SUPPORTED)},
        )


class ParseError(MaskingAPIError):
    """File content could not be parsed by its format adapter. → HTTP 422"""

    def __init__(self, filename: str, fmt: str, reason: str, location: Optional[str] = None) -> None:
        loc_part = f" (at {location})" if location else ""
        super().__init__(
            f"Failed to parse '{filename}' as {fmt}{loc_part}: {reason}.",
            detail={"filename": filename, "format": fmt, "reason": reason, "location": location},
        )


class PolicyValidationError(MaskingAPIError):
    """Policy YAML is structurally invalid. → HTTP 500 (startup failure)"""

    def __init__(self, errors: List[str]) -> None:
        summary = "\n".join(f"  • {e}" for e in errors)
        super().__init__(
            f"Policy validation failed with {len(errors)} error(s):\n{summary}",
            detail={"errors": errors},
        )


class AuditLogWriteError(MaskingAPIError):
    """Audit log entry could not be written. → HTTP 500"""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Failed to write audit log entry: {reason}. Request aborted.",
            detail={"reason": reason},
        )


class UnknownRoleError(MaskingAPIError):
    """Role string is not recognised. This is a programming error. → HTTP 500"""

    def __init__(self, role: str) -> None:
        super().__init__(
            f"Unknown role '{role}'. Valid roles are: analyst, operator, auditor.",
            detail={"role": role},
        )


class AuthenticationError(MaskingAPIError):
    """Missing or invalid API token. → HTTP 401"""

    def __init__(self, reason: str = "Missing or invalid X-API-Token header.") -> None:
        super().__init__(reason, detail={"reason": reason})


class AuthorizationError(MaskingAPIError):
    """Token is valid but the role is not permitted for this endpoint. → HTTP 403"""

    def __init__(self, role: str, endpoint: str) -> None:
        super().__init__(
            f"Role '{role}' is not authorised to access {endpoint}.",
            detail={"role": role, "endpoint": endpoint},
        )


class JWKSFetchError(MaskingAPIError):
    """JWKS endpoint is unreachable or returned an error. → HTTP 503

    This is a service-level failure (the IdP is down), not a caller error.
    The service must not fall back to returning unmasked data.
    """

    def __init__(self, jwks_uri: str, reason: str) -> None:
        super().__init__(
            f"Failed to fetch JWKS from '{jwks_uri}': {reason}. "
            "The IdP may be temporarily unreachable.",
            detail={"jwks_uri": jwks_uri, "reason": reason},
        )


class JWKSKeyNotFoundError(MaskingAPIError):
    """JWT's kid does not match any key in the JWKS after a refresh. → HTTP 401

    This indicates the token was signed with an unknown or revoked key.
    """

    def __init__(self, kid: str, jwks_uri: str) -> None:
        super().__init__(
            f"No key with kid='{kid}' found in JWKS at '{jwks_uri}'. "
            "The token may have been issued with a revoked or unknown key.",
            detail={"kid": kid, "jwks_uri": jwks_uri},
        )
