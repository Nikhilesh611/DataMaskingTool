"""Security utilities for user authentication, password hashing, and session tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt

_SECRET_KEY = os.environ.get("SECRET_KEY", "dm-enterprise-master-session-signing-key-32b!")
_ALGORITHM = "HS256"
_SESSION_EXPIRY_DAYS = 7


def hash_password(password: str) -> Tuple[str, str]:
    """Hash a password using PBKDF2-HMAC-SHA256 with a cryptographically secure salt.

    Returns:
        (password_hash, salt_hex)
    """
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    )
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify a plain password against the stored PBKDF2-HMAC-SHA256 hash."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    )
    return hmac.compare_digest(dk.hex(), password_hash)


def create_session_token(
    user_id: str,
    email: str,
    role: str,
    tenant_id: str,
    tenant_slug: str,
    account_type: str,
    expires_in_days: int = _SESSION_EXPIRY_DAYS,
) -> str:
    """Create a signed JWT session token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "tenant_id": tenant_id,
        "tenant_slug": tenant_slug,
        "account_type": account_type,
        "iat": now,
        "exp": now + timedelta(days=expires_in_days),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def decode_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and cryptographically verify a JWT session token.

    Returns payload dict if valid, None if expired or invalid.
    """
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        return payload
    except Exception:
        return None
