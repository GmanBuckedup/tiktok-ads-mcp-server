"""ASGI middleware that validates an Entra ID bearer token on every request
to the MCP transport and stashes the user's `oid` on request.state for tool
handlers to read via the MCP request context.
"""

from __future__ import annotations

import logging
from typing import Iterable

import jwt
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .entra import EntraValidator

logger = logging.getLogger(__name__)


class EntraBearerMiddleware:
    """Reject any request to a protected path that doesn't carry a valid
    Entra ID bearer token. On success, stashes the decoded claims and the
    user's `oid` on the ASGI scope's `state` dict so the MCP transport
    sees them via Request.state in tool handlers.

    `protected_path_prefixes` lets us pass /tiktok/callback and /healthz
    through unauthenticated (TikTok hits the callback with no Entra token).
    """

    def __init__(
        self,
        app: ASGIApp,
        validator: EntraValidator,
        protected_path_prefixes: Iterable[str] = ("/mcp",),
        resource_metadata_url: str | None = None,
    ):
        self.app = app
        self.validator = validator
        self.protected_prefixes = tuple(protected_path_prefixes)
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if not any(path.startswith(p) for p in self.protected_prefixes):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            await self._unauthorized(scope, receive, send, "Missing bearer token")
            return

        token = auth_header.split(" ", 1)[1].strip()
        try:
            claims = self.validator.validate(token)
        except jwt.PyJWTError as e:
            logger.info("Entra token rejected: %s", e)
            await self._unauthorized(scope, receive, send, f"Invalid token: {e}")
            return

        # ASGI spec: scope["state"] is a per-request dict starlette merges
        # into Request.state. The MCP transport builds its own Request from
        # this same scope, so anything we put here is visible to handlers.
        state = scope.setdefault("state", {})
        state["entra_claims"] = claims
        state["oid"] = claims["oid"]

        await self.app(scope, receive, send)

    async def _unauthorized(self, scope: Scope, receive: Receive, send: Send, detail: str) -> None:
        # RFC 9728 §5.1: point clients at our protected-resource metadata.
        headers = {}
        if self.resource_metadata_url:
            headers["WWW-Authenticate"] = (
                f'Bearer realm="mcp", '
                f'resource_metadata="{self.resource_metadata_url}"'
            )
        response = JSONResponse(
            {"error": "unauthorized", "detail": detail},
            status_code=401,
            headers=headers,
        )
        await response(scope, receive, send)
