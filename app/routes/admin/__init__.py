"""Admin control plane routes package."""

from app.routes.admin.api import api_router
from app.routes.admin.ui import ui_router

__all__ = ["api_router", "ui_router"]
