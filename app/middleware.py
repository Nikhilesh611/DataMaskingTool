"""Request-ID injection middleware.

Generates a UUID4 per incoming request, stores it in the ``request_id_var``
context variable so all loggers stamp it automatically, and appends it as
``X-Request-ID`` to every response.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.logging_config import request_id_var


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        rid = str(uuid.uuid4())
        token = request_id_var.set(rid)
        try:
            response: Response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response
