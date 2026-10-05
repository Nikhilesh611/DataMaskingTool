"""Multi-tenant SQLAlchemy ORM models.

Tables
------
Tenant          — Organisation entity (one row per enterprise customer).
AuthProvider    — IdP trust configuration per tenant (OIDC / LDAP).
MaskingPolicy   — YAML masking policy stored per tenant.
GroupMapping    — Group → policy binding with priority ordering.
AuditEvent      — Append-only request audit ledger (zero-PII).

Tenant Isolation
----------------
All tables that store tenant-specific data include a ``tenant_id`` FK with
``CASCADE`` delete.  Application queries MUST filter by ``tenant_id`` on
every SELECT — this is the software-level enforcement of Row-Level Security
(RLS).  PostgreSQL advisory RLS policies can be added later as a second layer.

Encryption
----------
``AuthProvider.encrypted_bind_creds`` stores LDAP bind passwords / client
secrets encrypted with AES-256-GCM via ``app.core.crypto``.  Plaintext
credentials are NEVER persisted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


# ── Helpers ────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Tenant ─────────────────────────────────────────────────────────────────────

class Tenant(Base):
    """Root entity representing one enterprise customer."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    account_type: Mapped[str] = mapped_column(
        String(50), default="developer", nullable=False
    )

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User", back_populates="tenant", cascade="all, delete-orphan"
    )
    auth_providers: Mapped[list[AuthProvider]] = relationship(
        "AuthProvider", back_populates="tenant", cascade="all, delete-orphan"
    )
    masking_policies: Mapped[list[MaskingPolicy]] = relationship(
        "MaskingPolicy", back_populates="tenant", cascade="all, delete-orphan"
    )
    group_mappings: Mapped[list[GroupMapping]] = relationship(
        "GroupMapping", back_populates="tenant", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        "AuditEvent", back_populates="tenant", cascade="all, delete-orphan"
    )
    api_keys: Mapped[list[ApiKey]] = relationship(
        "ApiKey", back_populates="tenant", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Tenant id={self.id!r} slug={self.slug!r} type={self.account_type!r}>"


# ── User ───────────────────────────────────────────────────────────────────────

class User(Base):
    """User account for Solo Developers and Enterprise Administrators."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    salt: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50), default="developer", nullable=False
    )
    full_name: Mapped[str] = mapped_column(
        String(255), default="", nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="users")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id!r} email={self.email!r} role={self.role!r}>"


# ── ApiKey ─────────────────────────────────────────────────────────────────────

class ApiKey(Base):
    """Direct API Key for developer access, automated microservices, and solo users."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    role: Mapped[str] = mapped_column(String(50), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="api_keys")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ApiKey id={self.id!r} name={self.name!r} prefix={self.key_prefix!r}>"


# ── AuthProvider ───────────────────────────────────────────────────────────────

class AuthProvider(Base):
    """Identity Provider trust record for one tenant.

    ``provider_type`` is either ``"oidc"`` or ``"ldap"``.

    For OIDC:
        ``issuer_url`` — used to look up tenant by JWT ``iss`` claim and to
                         auto-discover the JWKS endpoint.
        ``jwks_uri``   — explicit JWKS URI (optional; overrides OIDC discovery).
        ``audience``   — JWT ``aud`` claim value to validate.

    For LDAP:
        ``encrypted_bind_creds`` — AES-256-GCM ciphertext of bind DN & password.
    """

    __tablename__ = "auth_providers"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_type: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # "oidc" | "ldap"
    issuer_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    jwks_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    audience: Mapped[str | None] = mapped_column(String(255), nullable=True)
    groups_claim: Mapped[str] = mapped_column(
        String(100), default="groups", nullable=False
    )
    # AES-256-GCM encrypted LDAP bind credentials (JSON → encrypt → hex)
    encrypted_bind_creds: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="auth_providers")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AuthProvider id={self.id!r} tenant={self.tenant_id!r} "
            f"type={self.provider_type!r}>"
        )


# ── MaskingPolicy ──────────────────────────────────────────────────────────────

class MaskingPolicy(Base):
    """Named masking policy belonging to one tenant.

    ``policy_yaml`` — raw YAML text (the policy definition).
    ``compiled_rules`` — optional JSON cache of compiled rule objects for fast
                         evaluation (populated lazily; can be NULL).
    """

    __tablename__ = "masking_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_policy_tenant_name"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    compiled_rules: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    tenant: Mapped[Tenant] = relationship(
        "Tenant", back_populates="masking_policies"
    )
    group_mappings: Mapped[list[GroupMapping]] = relationship(
        "GroupMapping", back_populates="policy", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MaskingPolicy id={self.id!r} name={self.name!r} tenant={self.tenant_id!r}>"


# ── GroupMapping ───────────────────────────────────────────────────────────────

class GroupMapping(Base):
    """Maps an external IdP group to a MaskingPolicy for one tenant.

    ``priority`` — lower number wins when a user belongs to multiple groups.
                   Mirrors the in-memory ``GroupMappingStore`` behaviour.
    ``external_group`` — the group name exactly as it appears in the JWT claim.
    """

    __tablename__ = "group_mappings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "external_group", name="uq_group_mapping_tenant_group"
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    external_group: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("masking_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    internal_role: Mapped[str | None] = mapped_column(
        String(64), nullable=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="group_mappings")
    policy: Mapped[MaskingPolicy] = relationship(
        "MaskingPolicy", back_populates="group_mappings"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<GroupMapping group={self.external_group!r} "
            f"policy={self.policy_id!r} priority={self.priority}>"
        )


# ── AuditEvent ─────────────────────────────────────────────────────────────────

class AuditEvent(Base):
    """Append-only audit record for each masking request.

    Design constraints:
    - ZERO PII: raw payload data is NEVER stored here.
    - Immutable: rows are INSERT-only; no UPDATE or DELETE from application.
    - ``user_id`` is an opaque identifier (e.g. JWT ``sub`` claim) — not a
      human-readable name or email address.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Opaque user identifier from JWT sub claim — not PII by itself
    user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Comma-separated list of IdP groups resolved at request time
    groups_snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    format: Mapped[str | None] = mapped_column(String(10), nullable=True)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="audit_events")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AuditEvent id={self.id!r} tenant={self.tenant_id!r} "
            f"policy={self.policy_name!r} ts={self.timestamp!r}>"
        )
