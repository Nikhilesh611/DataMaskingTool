"""FastAPI application entry point.

Startup sequence:
1. Load settings from env vars (exits on any missing required var).
2. Import hierarchies package to auto-register all built-in hierarchies.
3. Load and validate the masking policy (exits on validation failure).
4. Configure logging.
5. Mount middleware and exception handlers.
6. Register routers.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import get_settings, init_settings
from app.exceptions import (
    AuditLogWriteError,
    AuthenticationError,
    AuthorizationError,
    FileNotFoundError,
    JWKSFetchError,
    JWKSKeyNotFoundError,
    MaskingAPIError,
    ParseError,
    PathTraversalError,
    PolicyValidationError,
    UnknownRoleError,
    UnsupportedFormatError,
)
from app.idp.oidc_discovery import OIDCDiscoveryError
from app.middleware import RequestIDMiddleware


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1 — Settings
    settings = init_settings()

    # 2 — Auto-register all hierarchies
    import app.hierarchies  # noqa: F401

    # 3 — Policy loading:
    # Multi-tenant policies are resolved dynamically from database per tenant.
    # A local policy file is loaded as fallback only if configured and present.
    import os
    from app.policy.loader import load_policy
    if settings.policy_path and os.path.exists(settings.policy_path):
        try:
            load_policy(settings.policy_path)
        except PolicyValidationError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)

    # 4 — Configure logging
    from app.logging_config import configure_logging
    configure_logging(
        app_log_level=settings.app_log_level,
        audit_log_path=settings.audit_log_path,
    )

    from app.logging_config import get_app_logger
    logger = get_app_logger()

    # 5 — Initialise async database (creates tables if they don't exist)
    from app.db.session import init_db
    try:
        await init_db()
        logger.info("Database initialised (tables created/verified).")
    except Exception as exc:  # pragma: no cover
        print(f"[FATAL] Database init failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # 6 — Enterprise Multi-Tenant Engine initialized
    logger.info("Multi-Tenant Dynamic Engine initialized (Federated IdP & DB-backed RLS).")

    # 7 — Redis L2 Cache & Pub/Sub Invalidation Mesh
    from app.cache import get_pubsub_mesh, get_redis_manager
    redis_mgr = get_redis_manager()
    await redis_mgr.connect()
    if redis_mgr.is_connected:
        get_pubsub_mesh().start_listener()

    # 8 — Phase 6: Async Zero-PII Audit Ledger Worker
    from app.audit import get_audit_ledger
    get_audit_ledger().start_worker()

    yield

    # Shutdown — stop audit ledger, listener and disconnect Redis
    await get_audit_ledger().stop_worker()
    await get_pubsub_mesh().stop_listener()
    await get_redis_manager().disconnect()

    # Dispose DB engine connection pool.
    from app.db.session import dispose_engine
    await dispose_engine()
    logger.info("Database engine disposed.")


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Enterprise Data Masking Platform",
    description=(
        "Multi-tenant, enterprise-grade data masking service. "
        "Supports JSON, XML, and YAML payloads with JWT-based IdP federation, "
        "priority group-to-policy mapping, and a structured audit trail."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(RequestIDMiddleware)


# ── Exception handlers ────────────────────────────────────────────────────────

def _error_response(status: int, message: str, detail=None) -> JSONResponse:
    body = {"error": message}
    if detail is not None:
        body["detail"] = detail
    return JSONResponse(status_code=status, content=body)


@app.exception_handler(AuthenticationError)
async def handle_auth(req: Request, exc: AuthenticationError) -> JSONResponse:
    return _error_response(401, exc.message, exc.detail)


@app.exception_handler(AuthorizationError)
async def handle_authz(req: Request, exc: AuthorizationError) -> JSONResponse:
    return _error_response(403, exc.message, exc.detail)


@app.exception_handler(PathTraversalError)
async def handle_traversal(req: Request, exc: PathTraversalError) -> JSONResponse:
    return _error_response(403, exc.message, exc.detail)


@app.exception_handler(FileNotFoundError)
async def handle_not_found(req: Request, exc: FileNotFoundError) -> JSONResponse:
    return _error_response(404, exc.message, exc.detail)


@app.exception_handler(UnsupportedFormatError)
async def handle_bad_format(req: Request, exc: UnsupportedFormatError) -> JSONResponse:
    return _error_response(400, exc.message, exc.detail)


@app.exception_handler(ParseError)
async def handle_parse(req: Request, exc: ParseError) -> JSONResponse:
    return _error_response(422, exc.message, exc.detail)


@app.exception_handler(PolicyValidationError)
async def handle_policy(req: Request, exc: PolicyValidationError) -> JSONResponse:
    return _error_response(500, exc.message, exc.detail)


@app.exception_handler(AuditLogWriteError)
async def handle_audit_write(req: Request, exc: AuditLogWriteError) -> JSONResponse:
    return _error_response(500, exc.message, exc.detail)


@app.exception_handler(UnknownRoleError)
async def handle_unknown_role(req: Request, exc: UnknownRoleError) -> JSONResponse:
    return _error_response(500, exc.message, exc.detail)


@app.exception_handler(MaskingAPIError)
async def handle_generic(req: Request, exc: MaskingAPIError) -> JSONResponse:
    return _error_response(500, exc.message, exc.detail)


@app.exception_handler(JWKSFetchError)
async def handle_jwks_fetch(req: Request, exc: JWKSFetchError) -> JSONResponse:
    return _error_response(503, exc.message, exc.detail)


@app.exception_handler(OIDCDiscoveryError)
async def handle_oidc_discovery(req: Request, exc: OIDCDiscoveryError) -> JSONResponse:
    return _error_response(503, exc.message, exc.detail)


@app.exception_handler(JWKSKeyNotFoundError)
async def handle_jwks_key_not_found(req: Request, exc: JWKSKeyNotFoundError) -> JSONResponse:
    return _error_response(401, exc.message, exc.detail)


from app.cache import RateLimitExceededError


@app.exception_handler(RateLimitExceededError)
async def handle_rate_limit(req: Request, exc: RateLimitExceededError) -> JSONResponse:
    resp = _error_response(429, exc.message, exc.detail)
    resp.headers["Retry-After"] = str(exc.retry_after)
    return resp


# ── Routers ───────────────────────────────────────────────────────────────────

from app.routes.health import router as health_router
from app.routes.v1.mask import router as v1_mask_router, unversioned_router as mask_router

# Modern On-The-Fly Multi-Tenant Streaming Masking Endpoints (/v1/mask, /v1/mask/file, /mask, /mask/file)
app.include_router(v1_mask_router)
app.include_router(mask_router)
app.include_router(health_router)

# Phase 5: enterprise control plane admin dashboard & API
from app.routes.admin import api_router as admin_api_router, ui_router as admin_ui_router
app.include_router(admin_api_router)
app.include_router(admin_ui_router)

# Public authentication (Solo Developers and Enterprise Customers)
from app.routes.auth import auth_router
app.include_router(auth_router)

# Phase 6: Prometheus metrics route
from app.routes.metrics import metrics_router
app.include_router(metrics_router)

# Mount Frontend Static Assets
import os
from fastapi.staticfiles import StaticFiles
_dist_assets = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist", "assets"))
if os.path.exists(_dist_assets):
    app.mount("/assets", StaticFiles(directory=_dist_assets), name="assets")

