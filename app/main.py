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

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import get_settings, init_settings
from app.exceptions import (
    AuditLogWriteError,
    AuthenticationError,
    AuthorizationError,
    FileNotFoundError,
    MaskingAPIError,
    ParseError,
    PathTraversalError,
    PolicyValidationError,
    UnknownRoleError,
    UnsupportedFormatError,
)
from app.middleware import RequestIDMiddleware


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1 — Settings
    settings = init_settings()

    # 2 — Auto-register all hierarchies
    import app.hierarchies  # noqa: F401

    # 3 — Load policy
    from app.policy.loader import load_policy
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
    get_app_logger().info("Server started. Policy loaded. Data dir: %s", settings.data_dir)

    yield
    # Shutdown — nothing to clean up for now.


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Multi-Format Data Masking API",
    description="Privacy-preserving middleware for XML, JSON, and YAML data files.",
    version="1.0.0",
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


# ── Routers ───────────────────────────────────────────────────────────────────

from app.routes.audit import router as audit_router
from app.routes.health import router as health_router
from app.routes.mask import router as mask_router
from app.routes.policy import router as policy_router

app.include_router(mask_router)
app.include_router(audit_router)
app.include_router(policy_router)
app.include_router(health_router)
