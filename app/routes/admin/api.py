"""Phase 5 — Control Plane Admin REST API.

Provides endpoints for:
- Tenant management (/api/v1/admin/tenants)
- IdP (OIDC/LDAP) configuration & connectivity testing (/api/v1/admin/tenants/{id}/idp)
- Group mapping administration (/api/v1/admin/tenants/{id}/mappings)
- Masking policy configuration (/api/v1/admin/tenants/{id}/policies)
- Live interactive masking sandbox simulation (/api/v1/admin/tenants/{id}/simulate)
"""

from __future__ import annotations

import json
import time
from typing import Any, List, Optional
import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

import hashlib
import secrets
from app.cache import get_l1_cache, get_pubsub_mesh
from app.db.models import ApiKey, AuditEvent, AuthProvider, GroupMapping, MaskingPolicy, Tenant
from app.db.session import get_session
from app.idp.jwks_client import get_jwks_cache
from app.logging_config import get_app_logger
from app.pipeline.runner import run_pipeline
from app.policy.loader import get_policy, load_policy_from_string
from app.policy.models import MaskingPolicy as PolicyModel
from app.schemas.admin import (
    ApiKeyCreateRequest,
    ApiKeyResponse,
    AuditEventResponse,
    AuthProviderCreateRequest,
    AuthProviderResponse,
    GroupMappingCreateRequest,
    GroupMappingResponse,
    IdPTestRequest,
    IdPTestResponse,
    MaskingPolicyCreateRequest,
    MaskingPolicyResponse,
    SimulateMaskRequest,
    SimulateMaskResponse,
    TenantCreateRequest,
    TenantResponse,
)

logger = get_app_logger()

api_router = APIRouter(prefix="/api/v1/admin", tags=["Control Plane Admin"])


# ── Helper: Cache Invalidation ────────────────────────────────────────────────

async def _invalidate_tenant_caches(tenant_id: str) -> None:
    """Evict tenant from local L1 & JWKS caches and broadcast via Pub/Sub."""
    pubsub = get_pubsub_mesh()
    await pubsub.broadcast_invalidation(tenant_id)


# ── Tenant Management ─────────────────────────────────────────────────────────

@api_router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new enterprise tenant",
)
async def create_tenant(
    body: TenantCreateRequest,
    db: AsyncSession = Depends(get_session),
) -> TenantResponse:
    # Check for existing slug
    stmt = select(Tenant).where(Tenant.slug == body.slug)
    res = await db.execute(stmt)
    if res.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Tenant with slug '{body.slug}' already exists.",
        )

    tenant = Tenant(name=body.name, slug=body.slug, is_active=body.is_active)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    logger.info("Admin created tenant: %s (id=%s)", tenant.slug, tenant.id)
    return TenantResponse.model_validate(tenant)


@api_router.get(
    "/tenants",
    response_model=List[TenantResponse],
    summary="List all enterprise tenants",
)
async def list_tenants(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_session),
) -> List[TenantResponse]:
    stmt = select(Tenant).offset(skip).limit(limit).order_by(Tenant.created_at.desc())
    res = await db.execute(stmt)
    tenants = res.scalars().all()
    return [TenantResponse.model_validate(t) for t in tenants]


@api_router.get(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    summary="Get tenant details",
)
async def get_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
) -> TenantResponse:
    stmt = select(Tenant).where(Tenant.id == tenant_id)
    res = await db.execute(stmt)
    tenant = res.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found.",
        )
    return TenantResponse.model_validate(tenant)


@api_router.delete(
    "/tenants/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a tenant",
)
async def delete_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
) -> Response:
    stmt = select(Tenant).where(Tenant.id == tenant_id)
    res = await db.execute(stmt)
    tenant = res.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found.",
        )
    await db.delete(tenant)
    await db.commit()
    await _invalidate_tenant_caches(tenant_id)
    logger.info("Admin deleted tenant: %s", tenant_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Identity Provider (AuthProvider) Management ──────────────────────────────

@api_router.post(
    "/tenants/{tenant_id}/idp",
    response_model=AuthProviderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register or update Identity Provider config for a tenant",
)
async def configure_idp(
    tenant_id: str,
    body: AuthProviderCreateRequest,
    db: AsyncSession = Depends(get_session),
) -> AuthProviderResponse:
    # Verify tenant exists
    stmt_t = select(Tenant).where(Tenant.id == tenant_id)
    res_t = await db.execute(stmt_t)
    if res_t.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found.",
        )

    provider = AuthProvider(
        tenant_id=tenant_id,
        provider_type=body.provider_type,
        issuer_url=body.issuer_url,
        jwks_uri=body.jwks_uri,
        audience=body.audience,
        groups_claim=body.groups_claim,
        is_active=body.is_active,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)

    await _invalidate_tenant_caches(tenant_id)
    logger.info("Admin configured IdP for tenant %s: %s", tenant_id, body.issuer_url)
    return AuthProviderResponse.model_validate(provider)


@api_router.get(
    "/tenants/{tenant_id}/idp",
    response_model=List[AuthProviderResponse],
    summary="Get IdP configurations for a tenant",
)
async def get_idp_configs(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
) -> List[AuthProviderResponse]:
    stmt = select(AuthProvider).where(AuthProvider.tenant_id == tenant_id)
    res = await db.execute(stmt)
    providers = res.scalars().all()
    return [AuthProviderResponse.model_validate(p) for p in providers]


@api_router.post(
    "/idp/test-connection",
    response_model=IdPTestResponse,
    summary="Test connectivity to an OIDC issuer or JWKS endpoint",
)
async def test_idp_connection(body: IdPTestRequest) -> IdPTestResponse:
    """Validate that an OIDC issuer or JWKS endpoint can be reached and has valid keys."""
    import httpx

    target_jwks_uri = body.jwks_uri

    # If issuer_url is provided without explicit jwks_uri, attempt OIDC discovery
    if not target_jwks_uri and body.issuer_url:
        disco_url = f"{body.issuer_url.rstrip('/')}/.well-known/openid-configuration"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(disco_url)
                if r.status_code == 200:
                    disco_data = r.json()
                    target_jwks_uri = disco_data.get("jwks_uri")
                else:
                    return IdPTestResponse(
                        success=False,
                        message=f"OIDC discovery at '{disco_url}' returned HTTP {r.status_code}.",
                    )
        except Exception as exc:
            return IdPTestResponse(
                success=False,
                message=f"Connection to OIDC discovery endpoint failed: {str(exc)}",
            )

    if not target_jwks_uri:
        return IdPTestResponse(
            success=False,
            message="No JWKS URI provided or discovered from issuer URL.",
        )

    # Test JWKS endpoint
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(target_jwks_uri)
            if r.status_code != 200:
                return IdPTestResponse(
                    success=False,
                    discovered_jwks_uri=target_jwks_uri,
                    message=f"JWKS endpoint returned HTTP {r.status_code}",
                )
            jwks = r.json()
            keys = jwks.get("keys", [])
            return IdPTestResponse(
                success=True,
                discovered_jwks_uri=target_jwks_uri,
                keys_found=len(keys),
                message=f"Successfully connected to JWKS endpoint. Found {len(keys)} public key(s).",
            )
    except Exception as exc:
        return IdPTestResponse(
            success=False,
            discovered_jwks_uri=target_jwks_uri,
            message=f"Failed to fetch JWKS from '{target_jwks_uri}': {str(exc)}",
        )


# ── Group Mapping Management ──────────────────────────────────────────────────

@api_router.get(
    "/tenants/{tenant_id}/mappings",
    response_model=List[GroupMappingResponse],
    summary="List all group-to-policy mappings for a tenant",
)
async def list_group_mappings(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
) -> List[GroupMappingResponse]:
    stmt = (
        select(GroupMapping, MaskingPolicy.name.label("policy_name"))
        .outerjoin(MaskingPolicy, GroupMapping.policy_id == MaskingPolicy.id)
        .where(GroupMapping.tenant_id == tenant_id)
        .order_by(GroupMapping.priority.asc(), GroupMapping.created_at.asc())
    )
    res = await db.execute(stmt)
    rows = res.all()

    output = []
    for mapping, pol_name in rows:
        resp = GroupMappingResponse(
            id=mapping.id,
            tenant_id=mapping.tenant_id,
            external_group=mapping.external_group,
            policy_id=mapping.policy_id,
            policy_name=pol_name or "Unknown Policy",
            internal_role=mapping.internal_role,
            priority=mapping.priority,
            created_at=mapping.created_at,
        )
        output.append(resp)
    return output


@api_router.post(
    "/tenants/{tenant_id}/mappings",
    response_model=GroupMappingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a group-to-policy mapping",
)
async def create_group_mapping(
    tenant_id: str,
    body: GroupMappingCreateRequest,
    db: AsyncSession = Depends(get_session),
) -> GroupMappingResponse:
    # Verify policy exists and belongs to this tenant
    stmt_p = (
        select(MaskingPolicy)
        .where(MaskingPolicy.id == body.policy_id)
        .where(MaskingPolicy.tenant_id == tenant_id)
    )
    res_p = await db.execute(stmt_p)
    pol = res_p.scalar_one_or_none()
    if pol is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Masking policy '{body.policy_id}' not found for tenant '{tenant_id}'.",
        )

    # Check unique constraint on (tenant_id, external_group)
    stmt_exist = (
        select(GroupMapping)
        .where(GroupMapping.tenant_id == tenant_id)
        .where(GroupMapping.external_group == body.external_group)
    )
    res_exist = await db.execute(stmt_exist)
    existing = res_exist.scalar_one_or_none()

    if existing:
        # Update existing mapping
        existing.policy_id = body.policy_id
        existing.priority = body.priority
        existing.internal_role = body.internal_role
        await db.commit()
        await db.refresh(existing)
        mapping = existing
    else:
        # Create new mapping
        mapping = GroupMapping(
            tenant_id=tenant_id,
            external_group=body.external_group,
            policy_id=body.policy_id,
            internal_role=body.internal_role,
            priority=body.priority,
        )
        db.add(mapping)
        await db.commit()
        await db.refresh(mapping)

    await _invalidate_tenant_caches(tenant_id)
    logger.info(
        "Admin updated group mapping: tenant=%s group=%s -> policy=%s (role=%s)",
        tenant_id, mapping.external_group, pol.name, mapping.internal_role,
    )

    return GroupMappingResponse(
        id=mapping.id,
        tenant_id=mapping.tenant_id,
        external_group=mapping.external_group,
        policy_id=mapping.policy_id,
        policy_name=pol.name,
        internal_role=mapping.internal_role,
        priority=mapping.priority,
        created_at=mapping.created_at,
    )


@api_router.delete(
    "/tenants/{tenant_id}/mappings/{mapping_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a group mapping",
)
async def delete_group_mapping(
    tenant_id: str,
    mapping_id: str,
    db: AsyncSession = Depends(get_session),
) -> Response:
    stmt = (
        select(GroupMapping)
        .where(GroupMapping.id == mapping_id)
        .where(GroupMapping.tenant_id == tenant_id)
    )
    res = await db.execute(stmt)
    mapping = res.scalar_one_or_none()
    if mapping is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group mapping '{mapping_id}' not found.",
        )
    await db.delete(mapping)
    await db.commit()
    await _invalidate_tenant_caches(tenant_id)
    logger.info("Admin deleted group mapping: %s", mapping_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Masking Policy Management ─────────────────────────────────────────────────

def _extract_roles_from_yaml(policy_yaml: str) -> List[str]:
    try:
        data = yaml.safe_load(policy_yaml)
        if isinstance(data, dict) and "roles" in data and isinstance(data["roles"], dict):
            return list(data["roles"].keys())
    except Exception:
        pass
    return []


@api_router.get(
    "/tenants/{tenant_id}/policies",
    response_model=List[MaskingPolicyResponse],
    summary="List all policies for a tenant",
)
async def list_policies(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
) -> List[MaskingPolicyResponse]:
    stmt = select(MaskingPolicy).where(MaskingPolicy.tenant_id == tenant_id)
    res = await db.execute(stmt)
    policies = res.scalars().all()
    output = []
    for p in policies:
        roles = _extract_roles_from_yaml(p.policy_yaml)
        output.append(
            MaskingPolicyResponse(
                id=p.id,
                tenant_id=p.tenant_id,
                name=p.name,
                policy_yaml=p.policy_yaml,
                is_active=p.is_active,
                available_roles=roles,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
        )
    return output


@api_router.post(
    "/tenants/{tenant_id}/policies",
    response_model=MaskingPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a masking policy with semantic validation",
)
async def create_or_update_policy(
    tenant_id: str,
    body: MaskingPolicyCreateRequest,
    db: AsyncSession = Depends(get_session),
) -> MaskingPolicyResponse:
    # Verify tenant exists
    stmt_t = select(Tenant).where(Tenant.id == tenant_id)
    res_t = await db.execute(stmt_t)
    if res_t.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found.",
        )

    # Validate YAML syntax and structure
    try:
        parsed_yaml = yaml.safe_load(body.policy_yaml)
        if not isinstance(parsed_yaml, dict):
            raise ValueError("Policy YAML root must be a dictionary / mapping.")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid policy YAML format: {str(exc)}",
        )

    # Check for existing policy by (tenant_id, name)
    stmt_exist = (
        select(MaskingPolicy)
        .where(MaskingPolicy.tenant_id == tenant_id)
        .where(MaskingPolicy.name == body.name)
    )
    res_exist = await db.execute(stmt_exist)
    existing = res_exist.scalar_one_or_none()

    if existing:
        existing.policy_yaml = body.policy_yaml
        existing.is_active = body.is_active
        await db.commit()
        await db.refresh(existing)
        policy = existing
    else:
        policy = MaskingPolicy(
            tenant_id=tenant_id,
            name=body.name,
            policy_yaml=body.policy_yaml,
            is_active=body.is_active,
        )
        db.add(policy)
        await db.commit()
        await db.refresh(policy)

    await _invalidate_tenant_caches(tenant_id)
    logger.info("Admin saved masking policy: tenant=%s name=%s", tenant_id, body.name)
    roles = _extract_roles_from_yaml(policy.policy_yaml)
    return MaskingPolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        name=policy.name,
        policy_yaml=policy.policy_yaml,
        is_active=policy.is_active,
        available_roles=roles,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@api_router.delete(
    "/tenants/{tenant_id}/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a masking policy",
)
async def delete_policy(
    tenant_id: str,
    policy_id: str,
    db: AsyncSession = Depends(get_session),
) -> Response:
    stmt = (
        select(MaskingPolicy)
        .where(MaskingPolicy.id == policy_id)
        .where(MaskingPolicy.tenant_id == tenant_id)
    )
    res = await db.execute(stmt)
    policy = res.scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Masking policy '{policy_id}' not found.",
        )
    await db.delete(policy)
    await db.commit()
    await _invalidate_tenant_caches(tenant_id)
    logger.info("Admin deleted masking policy: %s", policy_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Live Masking Sandbox / Simulator ──────────────────────────────────────────

@api_router.post(
    "/tenants/{tenant_id}/simulate",
    response_model=SimulateMaskResponse,
    summary="Simulate data masking on test payload without writing audit logs",
)
async def simulate_masking(
    tenant_id: str,
    body: SimulateMaskRequest,
    db: AsyncSession = Depends(get_session),
) -> SimulateMaskResponse:
    """Executes a dry-run masking pipeline on the provided payload in memory.

    Accepts custom policy YAML or looks up the tenant's active policy from DB,
    falling back to the default policy if not found.
    """
    # Prepare policy model
    active_policy: PolicyModel
    if body.custom_policy_yaml:
        try:
            active_policy = load_policy_from_string(body.custom_policy_yaml)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to parse custom policy YAML: {str(exc)}",
            )
    else:
        # Fetch active policy from DB for tenant
        stmt = (
            select(MaskingPolicy)
            .where(MaskingPolicy.tenant_id == tenant_id)
            .where(MaskingPolicy.is_active.is_(True))
            .limit(1)
        )
        res = await db.execute(stmt)
        db_policy = res.scalar_one_or_none()
        if db_policy:
            try:
                active_policy = load_policy_from_string(db_policy.policy_yaml)
            except Exception:
                active_policy = get_policy()
        else:
            active_policy = get_policy()

    # Convert data to raw bytes
    fmt = body.format.lower()
    raw_bytes: bytes
    if isinstance(body.data, (dict, list)):
        raw_bytes = json.dumps(body.data).encode("utf-8")
    elif isinstance(body.data, str):
        raw_bytes = body.data.encode("utf-8")
    else:
        raw_bytes = str(body.data).encode("utf-8")

    start_time = time.perf_counter()

    try:
        result = run_pipeline(
            raw_bytes=raw_bytes,
            fmt=fmt,
            policy=active_policy,
            role=body.role,
            request_id="sim-" + str(int(time.time() * 1000)),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Simulation error: {str(exc)}",
        )

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Parse output back to friendly structure if JSON
    masked_data: Any
    if fmt == "json":
        try:
            masked_data = json.loads(result.output_bytes.decode("utf-8"))
        except Exception:
            masked_data = result.output_bytes.decode("utf-8", errors="replace")
    else:
        masked_data = result.output_bytes.decode("utf-8", errors="replace")

    return SimulateMaskResponse(
        format=fmt,
        role=body.role,
        masked_output=masked_data,
        elapsed_ms=round(elapsed_ms, 2),
        conflict_count=result.conflict_count,
        uncovered_count=result.uncovered_count,
        k_achieved=result.k_achieved,
        profiles_applied=result.profiles_applied,
    )


# ── Demo Seeder Endpoint ──────────────────────────────────────────────────────

@api_router.post(
    "/seed-demo",
    summary="Seed demo enterprise tenant with IdP, policies, and group mappings",
)
async def seed_demo_enterprise(db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Seed ready-to-use 'Acme Financial Services' enterprise configuration."""
    stmt = select(Tenant).where(Tenant.slug == "acme-financial")
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()
    if existing is not None:
        return {"status": "already_exists", "tenant_id": existing.id, "slug": existing.slug}

    tenant = Tenant(name="Acme Financial Services", slug="acme-financial", is_active=True)
    db.add(tenant)
    await db.flush()

    provider = AuthProvider(
        tenant_id=tenant.id,
        provider_type="oidc",
        issuer_url="https://acme.okta.com/oauth2/default",
        audience="masking-service",
        groups_claim="groups",
        is_active=True,
    )
    db.add(provider)

    analyst_yaml = """version: "3.0"
record_root: "$"
roles:
  analyst: {}
rules:
  - selector: "$..ssn"
    technique: "suppress"
  - selector: "$..salary"
    technique: "redact"
  - selector: "$..credit_card"
    technique: "mask_pattern"
    pattern: "****-****-****-{last4}"
  - selector: "$..email"
    technique: "redact"
  - selector: "//ssn"
    technique: "suppress"
  - selector: "//salary"
    technique: "redact"
"""
    pol_analyst = MaskingPolicy(
        tenant_id=tenant.id,
        name="analyst",
        policy_yaml=analyst_yaml,
        is_active=True,
    )
    db.add(pol_analyst)

    auditor_yaml = """version: "3.0"
record_root: "$"
roles:
  auditor: {}
rules:
  - selector: "$..ssn"
    technique: "pseudonymize"
    consistent: true
  - selector: "$..salary"
    technique: "redact"
  - selector: "$..credit_card"
    technique: "mask_pattern"
    pattern: "XXXX-XXXX-XXXX-{last4}"
  - selector: "$..email"
    technique: "pseudonymize"
    consistent: true
  - selector: "//ssn"
    technique: "pseudonymize"
"""
    pol_auditor = MaskingPolicy(
        tenant_id=tenant.id,
        name="auditor",
        policy_yaml=auditor_yaml,
        is_active=True,
    )
    db.add(pol_auditor)
    await db.flush()

    gm_auditor = GroupMapping(
        tenant_id=tenant.id,
        external_group="acme-compliance-auditors",
        policy_id=pol_auditor.id,
        priority=1,
    )
    gm_analyst = GroupMapping(
        tenant_id=tenant.id,
        external_group="acme-data-analysts",
        policy_id=pol_analyst.id,
        priority=10,
    )
    db.add_all([gm_auditor, gm_analyst])

    demo_key_raw = "dm_live_demo_analyst_key"
    demo_key_hash = hashlib.sha256(demo_key_raw.encode("utf-8")).hexdigest()
    await db.execute(delete(ApiKey).where(ApiKey.key_hash == demo_key_hash))

    api_key_obj = ApiKey(
        tenant_id=tenant.id,
        name="Default Developer Key",
        key_prefix="dm_live_demo",
        key_hash=demo_key_hash,
        role="analyst",
        is_active=True,
    )
    db.add(api_key_obj)

    await db.commit()

    return {
        "status": "created",
        "tenant_id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "demo_api_key": demo_key_raw,
    }


# ── API Key Management Endpoints ──────────────────────────────────────────────

@api_router.get(
    "/tenants/{tenant_id}/api-keys",
    response_model=List[ApiKeyResponse],
    summary="List active API keys for a tenant",
)
async def list_api_keys(
    tenant_id: str,
    db: AsyncSession = Depends(get_session),
) -> List[ApiKeyResponse]:
    stmt = (
        select(ApiKey)
        .where(ApiKey.tenant_id == tenant_id)
        .order_by(ApiKey.created_at.desc())
    )
    res = await db.execute(stmt)
    keys = res.scalars().all()
    return [ApiKeyResponse.model_validate(k) for k in keys]


@api_router.post(
    "/tenants/{tenant_id}/api-keys",
    response_model=ApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new direct API key for developers or microservices",
)
async def create_api_key(
    tenant_id: str,
    body: ApiKeyCreateRequest,
    db: AsyncSession = Depends(get_session),
) -> ApiKeyResponse:
    # Verify tenant exists
    t_stmt = select(Tenant).where(Tenant.id == tenant_id)
    t_res = await db.execute(t_stmt)
    if not t_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found.",
        )

    # Generate secure random key: dm_live_<32_hex>
    raw_secret = f"dm_live_{secrets.token_hex(16)}"
    key_prefix = raw_secret[:12]
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

    key_obj = ApiKey(
        tenant_id=tenant_id,
        name=body.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        role=body.role,
        is_active=True,
    )
    db.add(key_obj)
    await db.commit()
    await db.refresh(key_obj)

    resp = ApiKeyResponse.model_validate(key_obj)
    resp.api_key = raw_secret
    return resp


@api_router.delete(
    "/tenants/{tenant_id}/api-keys/{key_id}",
    summary="Revoke an API key",
)
async def revoke_api_key(
    tenant_id: str,
    key_id: str,
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
    res = await db.execute(stmt)
    key_obj = res.scalar_one_or_none()
    if not key_obj:
        raise HTTPException(status_code=404, detail="API Key not found.")

    await db.delete(key_obj)
    await db.commit()
    return {"status": "deleted", "key_id": key_id}


# ── Audit Log Query Endpoint ──────────────────────────────────────────────────

@api_router.get(
    "/tenants/{tenant_id}/audit-logs",
    response_model=List[AuditEventResponse],
    summary="Get recent audit ledger events for a tenant",
)
async def get_audit_logs(
    tenant_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_session),
) -> List[AuditEventResponse]:
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
    )
    res = await db.execute(stmt)
    events = res.scalars().all()
    return [AuditEventResponse.model_validate(e) for e in events]


