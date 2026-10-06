"""Public Authentication Routes for Solo Developers and Enterprise Administrators.

Endpoints:
- POST /api/v1/auth/signup  — Register new developer or enterprise tenant + user
- POST /api/v1/auth/login   — Authenticate with email/password, sets session cookie
- POST /api/v1/auth/logout  — Clears session cookie
- GET  /api/v1/auth/me      — Retrieves active authenticated session context
"""

from __future__ import annotations

import re
import secrets
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Header, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import (
    create_session_token,
    decode_session_token,
    hash_password,
    verify_password,
)
from app.db.models import ApiKey, MaskingPolicy, Tenant, User
from app.db.session import get_session

auth_router = APIRouter(prefix="/api/v1/auth", tags=["Public Authentication"])

_COOKIE_NAME = "dm_session"
_COOKIE_MAX_AGE = 7 * 24 * 3600  # 7 days


# ── Schemas ───────────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=6)
    full_name: str = ""
    account_type: str = Field("developer", pattern="^(developer|enterprise)$")
    organization_name: str = Field(..., min_length=2, max_length=100)


class LoginRequest(BaseModel):
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    tenant_id: str
    tenant_name: str
    tenant_slug: str
    account_type: str


class AuthResponse(BaseModel):
    success: bool
    user: UserResponse
    api_key: Optional[str] = None
    token: str


# ── Dependency: Get Active Session ────────────────────────────────────────────

async def get_current_user_session(
    dm_session: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_session),
) -> tuple[User, Tenant]:
    """Extract and validate the active session from cookie or Bearer token."""
    token = dm_session
    if not token and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
        )

    payload = decode_session_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please sign in again.",
        )

    user_id = payload.get("sub")
    stmt = (
        select(User, Tenant)
        .join(Tenant, User.tenant_id == Tenant.id)
        .where(User.id == user_id)
        .where(User.is_active.is_(True))
    )
    result = await db.execute(stmt)
    row = result.first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or deactivated.",
        )

    user, tenant = row
    return user, tenant


# ── Routes ────────────────────────────────────────────────────────────────────

@auth_router.post("/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    req: SignupRequest,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> AuthResponse:
    """Public registration for Solo Developers and Enterprise Customers."""
    # 1. Check if user already exists
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    # 2. Generate slug for tenant
    base_slug = re.sub(r"[^a-z0-9]+", "-", req.organization_name.lower()).strip("-") or "workspace"
    slug = base_slug
    counter = 1
    while True:
        s_check = await db.execute(select(Tenant).where(Tenant.slug == slug))
        if not s_check.scalar_one_or_none():
            break
        slug = f"{base_slug}-{counter}"
        counter += 1

    # 3. Create Tenant
    tenant = Tenant(
        name=req.organization_name,
        slug=slug,
        account_type=req.account_type,
        is_active=True,
    )
    db.add(tenant)
    await db.flush()

    # 4. Hash password & create User
    pw_hash, salt = hash_password(req.password)
    user_role = "enterprise_admin" if req.account_type == "enterprise" else "developer"
    user = User(
        tenant_id=tenant.id,
        email=req.email,
        password_hash=pw_hash,
        salt=salt,
        role=user_role,
        full_name=req.full_name or req.organization_name,
        is_active=True,
    )
    db.add(user)

    # 5. Automatically provision standard initial policy
    if req.account_type == "enterprise":
        # Enterprise admins configure their own unified multi-role policy.
        # No misleading dummy single-role policies are preloaded.
        pass
    else:
        # Solo Developer standard starter policy
        dev_yaml = """# Developer Default Masking Policy

rules:
  - selector: "$..ssn"
    technique: "redact"

  - selector: "$..credit_card"
    technique: "mask_pattern"
    pattern: "****-****-****-{last4}"

  - selector: "$..salary"
    technique: "noise"

  - selector: "$..email"
    technique: "pseudonymize"
    consistent: true
"""
        p = MaskingPolicy(tenant_id=tenant.id, name="default", policy_yaml=dev_yaml, is_active=True)
        db.add(p)

    # 6. Generate initial API key for the workspace
    import hashlib
    raw_secret = f"dm_live_{secrets.token_urlsafe(32)}"
    key_prefix = raw_secret[:12]
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
    api_key_obj = ApiKey(
        tenant_id=tenant.id,
        name=f"{req.organization_name} Primary Key",
        key_prefix=key_prefix,
        key_hash=key_hash,
        role="analyst",
        is_active=True,
    )
    db.add(api_key_obj)

    await db.commit()
    await db.refresh(user)
    await db.refresh(tenant)

    # 7. Create JWT session token
    session_token = create_session_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        account_type=tenant.account_type,
    )

    response.set_cookie(
        key=_COOKIE_NAME,
        value=session_token,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )

    return AuthResponse(
        success=True,
        token=session_token,
        api_key=raw_secret,
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            tenant_slug=tenant.slug,
            account_type=tenant.account_type,
        ),
    )


@auth_router.post("/login", response_model=AuthResponse)
async def login(
    req: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> AuthResponse:
    """Authenticate Solo Developer or Enterprise Admin via email and password."""
    stmt = (
        select(User, Tenant)
        .join(Tenant, User.tenant_id == Tenant.id)
        .where(User.email == req.email)
        .where(User.is_active.is_(True))
    )
    res = await db.execute(stmt)
    row = res.first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    user, tenant = row
    if not verify_password(req.password, user.password_hash, user.salt):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    session_token = create_session_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        account_type=tenant.account_type,
    )

    response.set_cookie(
        key=_COOKIE_NAME,
        value=session_token,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )

    return AuthResponse(
        success=True,
        token=session_token,
        api_key=None,
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            tenant_slug=tenant.slug,
            account_type=tenant.account_type,
        ),
    )


@auth_router.post("/logout")
async def logout(response: Response) -> dict:
    """Sign out and clear session cookie."""
    response.delete_cookie(key=_COOKIE_NAME)
    return {"success": True, "message": "Successfully logged out."}


@auth_router.get("/me")
async def me(
    session_data: tuple[User, Tenant] = Depends(get_current_user_session),
) -> dict:
    """Return active user and tenant workspace context."""
    user, tenant = session_data
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "tenant_id": tenant.id,
            "tenant_name": tenant.name,
            "tenant_slug": tenant.slug,
            "account_type": tenant.account_type,
        },
    }
