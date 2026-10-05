"""Phase 5 — Pydantic schemas for the Enterprise Control Plane Admin API.

Covers:
- Tenant creation & responses
- Identity Provider (OIDC / LDAP) configuration & testing
- Group-to-role / group-to-policy mapping management
- Masking policy CRUD with validation
- Live dry-run masking sandbox simulation
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


# ── Tenant Schemas ─────────────────────────────────────────────────────────────

class TenantCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Enterprise customer name")
    slug: str = Field(
        ...,
        min_length=2,
        max_length=100,
        pattern=r"^[a-z0-9-]+$",
        description="Unique URL-safe slug, e.g. acme-corp",
    )
    is_active: bool = Field(default=True, description="Whether the tenant is active")


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    is_active: bool
    created_at: datetime


# ── Auth Provider (IdP) Schemas ───────────────────────────────────────────────

class AuthProviderCreateRequest(BaseModel):
    provider_type: Literal["oidc", "ldap"] = Field(
        default="oidc", description="IdP protocol type"
    )
    issuer_url: Optional[str] = Field(
        None, max_length=512, description="OIDC issuer URL (e.g. https://idp.example.com/realms/corp)"
    )
    jwks_uri: Optional[str] = Field(
        None, max_length=512, description="Explicit JWKS URI (optional if issuer_url supports .well-known)"
    )
    audience: Optional[str] = Field(
        None, max_length=255, description="Expected aud claim in JWT"
    )
    groups_claim: str = Field(
        default="groups", max_length=100, description="JWT claim name containing user group memberships"
    )
    is_active: bool = Field(default=True, description="Whether this provider is enabled")


class AuthProviderResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    provider_type: str
    issuer_url: Optional[str]
    jwks_uri: Optional[str]
    audience: Optional[str]
    groups_claim: str
    is_active: bool
    created_at: datetime


class IdPTestRequest(BaseModel):
    issuer_url: Optional[str] = Field(None, description="OIDC issuer URL to test")
    jwks_uri: Optional[str] = Field(None, description="JWKS URI to test directly")


class IdPTestResponse(BaseModel):
    success: bool
    discovered_jwks_uri: Optional[str] = None
    keys_found: int = 0
    message: str


# ── Group Mapping Schemas ──────────────────────────────────────────────────────

class GroupMappingCreateRequest(BaseModel):
    external_group: str = Field(
        ..., min_length=1, max_length=255, description="External IdP group name from token"
    )
    policy_id: str = Field(..., description="MaskingPolicy UUID to associate")
    internal_role: Optional[str] = Field(
        None, description="Specific role inside the policy to assign (e.g. analyst, auditor). If omitted, policy applies universally or uses default."
    )
    priority: int = Field(
        default=100, ge=1, le=1000, description="Priority weight (lower number = higher priority)"
    )


class GroupMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    external_group: str
    policy_id: str
    policy_name: Optional[str] = None
    internal_role: Optional[str] = None
    priority: int
    created_at: datetime


# ── Masking Policy Schemas ─────────────────────────────────────────────────────

class MaskingPolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Unique policy name per tenant")
    policy_yaml: str = Field(..., min_length=10, description="YAML policy definition text")
    is_active: bool = Field(default=True, description="Whether the policy is active")


class MaskingPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    policy_yaml: str
    is_active: bool
    available_roles: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


# ── Simulation & Sandbox Schemas ───────────────────────────────────────────────

class SimulateMaskRequest(BaseModel):
    format: Literal["json", "xml", "yaml"] = Field(
        default="json", description="Payload format: json | xml | yaml"
    )
    data: Any = Field(..., description="Raw string or JSON object/list to mask")
    role: str = Field(
        default="analyst", description="Role to simulate (e.g. analyst, auditor, operator)"
    )
    custom_policy_yaml: Optional[str] = Field(
        None, description="Optional custom policy YAML to test in sandbox. If omitted, uses active tenant policy."
    )


class SimulateMaskResponse(BaseModel):
    format: str
    role: str
    masked_output: Any
    elapsed_ms: float
    conflict_count: int = 0
    uncovered_count: int = 0
    k_achieved: bool = True
    profiles_applied: List[str] = Field(default_factory=list)


# ── API Key Schemas ────────────────────────────────────────────────────────────

class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Friendly label for the API Key")
    role: str = Field(default="analyst", max_length=50, description="Internal masking role assigned to this key")


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    key_prefix: str
    role: str
    is_active: bool
    created_at: datetime
    api_key: Optional[str] = Field(None, description="Plaintext API key (only returned once upon creation)")


# ── Audit Event Schemas ────────────────────────────────────────────────────────

class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    user_id: Optional[str] = None
    policy_name: Optional[str] = None
    format: Optional[str] = None
    execution_time_ms: Optional[int] = None
    request_id: Optional[str] = None
    timestamp: datetime

