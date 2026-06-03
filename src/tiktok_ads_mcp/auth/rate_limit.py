"""Lightweight per-IP rate limiting for the unauthenticated OAuth endpoints.

A fixed set of paths (the OAuth proxy + token endpoints) are throttled per
client IP using an in-memory sliding window. This is process-local — with
multiple replicas each enforces its own limit — but it still blunts brute-force
and abuse from a single source. The MCP transport (/mcp) is intentionally not
throttled here; it is already gated by a valid Entra bearer token.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Iterable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

_WINDOW_SECONDS = 60.0


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        limited_path_prefixes: Iterable[str],
        max_requests_per_minute: int,
    ):
        self.app = app
        self.limited_prefixes = tuple(limited_path_prefixes)
        self.max_requests = max_requests_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if not any(path.startswith(p) for p in self.limited_prefixes):
            await self.app(scope, receive, send)
            return

        client_ip = self._client_ip(scope)
        if self._is_rate_limited(client_ip):
            logger.warning("Rate limit exceeded for %s on %s", client_ip, path)
            response = JSONResponse(
                {"error": "rate_limited",
                 "error_description": "Too many requests. Please retry shortly."},
                status_code=429,
                headers={"Retry-After": str(int(_WINDOW_SECONDS))},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    def _client_ip(self, scope: Scope) -> str:
        # Behind Azure Container Apps ingress the real client is in
        # X-Forwarded-For (first hop). Fall back to the socket peer.
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for" and value:
                return value.decode("latin-1").split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - _WINDOW_SECONDS
        hits = self._hits[client_ip]
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return True
        hits.append(now)
        # Opportunistically drop empty buckets to bound memory.
        if not hits:
            self._hits.pop(client_ip, None)
        return False
