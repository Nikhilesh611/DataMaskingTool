"""Modern Customer SaaS Portal & Control Plane (/admin and /).

Serves the production-built Vite + React single-page application from frontend/dist:
- Real login / signup flows for Solo Developers and Enterprise Customers
- Dedicated Solo Developer Workspace (My Masking Policy, Secret API Keys, Live Console)
- Dedicated Enterprise Admin Workspace (Okta/Azure AD SSO, AD Group Mappings RBAC, Compliance Ledger)
- Instant Light/Dark mode switching with zero-flicker client-side rendering
"""

import os
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

ui_router = APIRouter(tags=["Customer Portal & Admin UI"])

_FRONTEND_DIST = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "frontend", "dist")
)
_INDEX_HTML = os.path.join(_FRONTEND_DIST, "index.html")


@ui_router.get("/admin", response_class=HTMLResponse, summary="Enterprise Control Plane Portal")
@ui_router.get("/admin/{rest_of_path:path}", response_class=HTMLResponse)
@ui_router.get("/", response_class=HTMLResponse, summary="Customer Portal Root")
async def get_admin_dashboard() -> HTMLResponse:
    """Serve the modern Vite + React single page application."""
    if os.path.exists(_INDEX_HTML):
        return FileResponse(_INDEX_HTML)
    return HTMLResponse(
        """<!DOCTYPE html>
        <html>
        <head><title>Data Masking Platform</title></head>
        <body style="font-family:sans-serif;text-align:center;padding:3rem;">
          <h2>Portal Bundle Building</h2>
          <p>Please wait while the frontend bundle compiles...</p>
        </body>
        </html>""",
        status_code=200,
    )
