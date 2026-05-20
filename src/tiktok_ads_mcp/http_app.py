"""Starlette ASGI app that hosts:

  - `/mcp`                : the MCP Streamable HTTP transport, gated by an
                            Entra ID bearer token validated in middleware.
  - `/tiktok/callback`    : OAuth redirect target. Exchanges the `code` for
                            a TikTok access token and stores it against the
                            user identified by the `state` parameter.
  - `/healthz`            : unauthenticated health check.

Environment:
  TIKTOK_APP_ID           - the org's TikTok For Business app ID
  TIKTOK_APP_SECRET       - the org's TikTok For Business app secret
  TIKTOK_REDIRECT_URI     - public URL of /tiktok/callback (must match the
                            redirect URI configured in the TikTok app)
  ENTRA_TENANT_ID         - Entra tenant the MCP accepts tokens from
  ENTRA_AUDIENCE          - the audience claim required on incoming tokens
                            (usually the Entra app registration's client ID,
                            or `api://<client-id>`)
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import AsyncIterator

from dotenv import load_dotenv
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Mount, Route

from . import server as mcp_server
from .auth.entra import EntraConfig, EntraValidator
from .auth.middleware import EntraBearerMiddleware
from .oauth_simple import TikTokOAuth
from .token_store import TokenStore

logger = logging.getLogger(__name__)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


def create_app() -> Starlette:
    load_dotenv()

    app_id = _required_env("TIKTOK_APP_ID")
    app_secret = _required_env("TIKTOK_APP_SECRET")
    redirect_uri = _required_env("TIKTOK_REDIRECT_URI")
    entra_tenant = _required_env("ENTRA_TENANT_ID")
    entra_audience = _required_env("ENTRA_AUDIENCE")

    token_store = TokenStore(app_id=app_id, app_secret=app_secret)
    oauth = TikTokOAuth(app_id=app_id, app_secret=app_secret, redirect_uri=redirect_uri)
    mcp_server.configure(token_store=token_store, oauth=oauth)

    session_manager = StreamableHTTPSessionManager(app=mcp_server.app)
    entra_validator = EntraValidator(EntraConfig(tenant_id=entra_tenant, audience=entra_audience))

    async def handle_mcp(scope, receive, send):
        await session_manager.handle_request(scope, receive, send)

    async def tiktok_callback(request: Request) -> HTMLResponse:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return HTMLResponse(
                _callback_html(
                    title="TikTok auth failed",
                    body="Missing code or state parameter on the redirect.",
                ),
                status_code=400,
            )

        oid = token_store.consume_pending_state(state)
        if oid is None:
            return HTMLResponse(
                _callback_html(
                    title="TikTok auth failed",
                    body=(
                        "Authorization session expired or unknown. Re-run "
                        "<code>tiktok_ads_login</code> from your MCP client."
                    ),
                ),
                status_code=400,
            )

        result = await oauth.exchange_code_for_token(code)
        if "error_message" in result:
            return HTMLResponse(
                _callback_html(
                    title="TikTok auth failed",
                    body=f"Token exchange failed: {result['error_message']}",
                ),
                status_code=400,
            )

        await token_store.set_token(
            oid=oid,
            access_token=result["access_token"],
            advertiser_ids=result["advertiser_ids"],
        )

        return HTMLResponse(
            _callback_html(
                title="TikTok authorization complete",
                body=(
                    "You can close this tab and return to your MCP client. "
                    "Run <code>tiktok_ads_auth_status</code> to confirm."
                ),
            )
        )

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            logger.info("TikTok Ads MCP server started")
            yield

    starlette_app = Starlette(
        debug=False,
        routes=[
            Mount("/mcp", app=handle_mcp),
            Route("/tiktok/callback", tiktok_callback, methods=["GET"]),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        lifespan=lifespan,
    )

    # Gate /mcp behind Entra; /tiktok/callback and /healthz pass through.
    starlette_app.add_middleware(EntraBearerMiddleware, validator=entra_validator)

    return starlette_app


def _callback_html(*, title: str, body: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem;color:#222}}h1{{font-size:1.25rem}}code{{background:#f4f4f4;padding:0 .25rem;border-radius:.2rem}}</style>
</head><body><h1>{title}</h1><p>{body}</p></body></html>"""
