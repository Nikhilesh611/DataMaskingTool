"""Admin Authentication & Authorization Subsystem.

Provides authentication logic for the Tool Admin Control Plane.
Supports both:
  1. Username & Password UI login (issues a session token).
  2. Static Admin API Key (via X-Admin-API-Key or Bearer token header).

Tool Admin authentication is completely decoupled from Data Masking API authorization.
"""

from __future__ import annotations

import uuid
from typing import Set

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import get_settings

# Simple in-memory session store for UI admin logins
_active_admin_sessions: Set[str] = set()

security_bearer = HTTPBearer(auto_error=False)


def authenticate_admin_credentials(username: str, password: str) -> str | None:
    """Validate username & password against configuration.

    Returns a new session token string on success, or None on failure.
    """
    settings = get_settings()
    if username == settings.admin_username and password == settings.admin_password:
        token = f"admin_session_{uuid.uuid4().hex}"
        _active_admin_sessions.add(token)
        return token
    return None


def invalidate_admin_session(token: str) -> bool:
    """Logout/revoke an admin session token."""
    if token in _active_admin_sessions:
        _active_admin_sessions.remove(token)
        return True
    return False


def verify_admin_token(token: str) -> bool:
    """Check if token is a valid active session or matches ADMIN_TOKEN."""
    if not token:
        return False

    settings = get_settings()
    # Check if matches configured static API key
    if settings.admin_token and token == settings.admin_token:
        return True

    # Check if in active session store
    return token in _active_admin_sessions


async def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
) -> str:
    """FastAPI dependency enforcing admin access for /api/v1/admin/* routes.

    Checks:
      1. Bearer token in Authorization header
      2. X-Admin-API-Key header
    """
    token: str | None = None

    if credentials and credentials.credentials:
        token = credentials.credentials
    elif "x-admin-api-key" in request.headers:
        token = request.headers["x-admin-api-key"]

    if not token or not verify_admin_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token
