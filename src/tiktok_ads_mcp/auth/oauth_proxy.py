"""OAuth 2.1 / RFC 9728 proxy in front of Microsoft Entra ID.

Claude.ai's custom-connector OAuth flow expects authorization endpoints on
the MCP server's own host (it does not follow `authorization_servers` URLs to
a third-party AS). The `resource` parameter Claude sends also doesn't match
what Entra wants. So we sit between Claude and Entra:

  Claude ↔ /authorize  /token  /register  /.well-known/*  ↔ proxy ↔ Entra

PKCE is chained: Claude does PKCE with the proxy; the proxy does its own
PKCE with Entra. Both halves are validated.

State (per in-flight auth attempt, plus per issued code) lives in-memory.
A container restart invalidates in-flight flows, which is fine — the user
just retries.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response


logger = logging.getLogger(__name__)


_PENDING_TTL = 10 * 60      # /authorize → Entra → /oauth/callback window
_CODE_TTL = 5 * 60          # /oauth/callback → /token window


@dataclass
class _Pending:
    """In-flight state from Claude's /authorize until Entra redirects back."""
    claude_redirect_uri: str
    claude_state: Optional[str]
    claude_code_challenge: str
    claude_code_challenge_method: str
    entra_code_verifier: str
    scope: str
    created_at: float = field(default_factory=time.time)


@dataclass
class _IssuedCode:
    """After Entra returns a code, we hand it through to Claude and stash
    everything /token will need to complete the exchange with Entra."""
    entra_code: str
    entra_code_verifier: str
    claude_code_challenge: str
    claude_code_challenge_method: str
    claude_redirect_uri: str
    created_at: float = field(default_factory=time.time)


class OAuthProxy:
    def __init__(
        self,
        *,
        public_base_url: str,
        entra_tenant_id: str,
        entra_client_id: str,
        entra_audience: str,
        entra_scope_name: str = "access_as_user",
    ):
        self.public_base_url = public_base_url.rstrip("/")
        self.entra_tenant_id = entra_tenant_id
        self.entra_client_id = entra_client_id
        self.entra_audience = entra_audience
        self.entra_scope_name = entra_scope_name
        self._pending: dict[str, _Pending] = {}
        self._issued: dict[str, _IssuedCode] = {}

    # ---- URLs ----

    @property
    def _entra_authorize_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/oauth2/v2.0/authorize"

    @property
    def _entra_token_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/oauth2/v2.0/token"

    @property
    def _proxy_callback_url(self) -> str:
        return f"{self.public_base_url}/oauth/callback"

    @property
    def _full_entra_scope(self) -> str:
        # Entra issues tokens with our custom audience when this scope is requested.
        return f"{self.entra_audience}/{self.entra_scope_name}"

    # ---- discovery: RFC 9728 + RFC 8414 ----

    async def protected_resource_metadata(self, _: Request) -> JSONResponse:
        return JSONResponse({
            "resource": f"{self.public_base_url}/mcp",
            "authorization_servers": [self.public_base_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [self.entra_scope_name],
        })

    async def authorization_server_metadata(self, _: Request) -> JSONResponse:
        return JSONResponse({
            "issuer": self.public_base_url,
            "authorization_endpoint": f"{self.public_base_url}/authorize",
            "token_endpoint": f"{self.public_base_url}/token",
            "registration_endpoint": f"{self.public_base_url}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [self.entra_scope_name],
        })

    # ---- DCR: pretend-register, hand back the static Entra client id ----

    async def register(self, request: Request) -> JSONResponse:
        body = await request.json() if (await request.body()) else {}
        redirect_uris = body.get("redirect_uris") or []
        return JSONResponse({
            "client_id": self.entra_client_id,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
        }, status_code=201)

    # ---- /authorize: Claude → proxy → Entra ----

    async def authorize(self, request: Request) -> Response:
        params = request.query_params
        claude_redirect_uri = params.get("redirect_uri")
        claude_code_challenge = params.get("code_challenge")
        claude_method = params.get("code_challenge_method", "S256")
        if not claude_redirect_uri or not claude_code_challenge:
            return JSONResponse(
                {"error": "invalid_request",
                 "error_description": "redirect_uri and code_challenge are required"},
                status_code=400,
            )

        # Our own PKCE pair for the proxy↔Entra leg.
        verifier = _b64url(secrets.token_bytes(64))
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())

        # `state` we send to Entra is the lookup key for /oauth/callback.
        proxy_state = secrets.token_urlsafe(32)

        self._sweep()
        self._pending[proxy_state] = _Pending(
            claude_redirect_uri=claude_redirect_uri,
            claude_state=params.get("state"),
            claude_code_challenge=claude_code_challenge,
            claude_code_challenge_method=claude_method,
            entra_code_verifier=verifier,
            scope=params.get("scope") or self.entra_scope_name,
        )

        entra_params = {
            "client_id": self.entra_client_id,
            "response_type": "code",
            "redirect_uri": self._proxy_callback_url,
            "response_mode": "query",
            "scope": f"{self._full_entra_scope} offline_access openid profile",
            "state": proxy_state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = f"{self._entra_authorize_url}?{urllib.parse.urlencode(entra_params)}"
        return RedirectResponse(url, status_code=302)

    # ---- /oauth/callback: Entra → proxy → Claude ----

    async def oauth_callback(self, request: Request) -> Response:
        params = request.query_params
        proxy_state = params.get("state") or ""
        entra_code = params.get("code")
        entra_error = params.get("error")

        pending = self._pending.pop(proxy_state, None)
        if pending is None or (time.time() - pending.created_at) > _PENDING_TTL:
            return JSONResponse(
                {"error": "invalid_state",
                 "error_description": "Authorization session expired or unknown."},
                status_code=400,
            )

        if entra_error or not entra_code:
            # Surface Entra's error back to Claude's callback.
            return _redirect_to_claude(
                pending.claude_redirect_uri,
                {"error": entra_error or "server_error",
                 "error_description": params.get("error_description") or "Entra returned no code",
                 "state": pending.claude_state},
            )

        # Hold everything /token needs to finish the exchange with Entra.
        self._issued[entra_code] = _IssuedCode(
            entra_code=entra_code,
            entra_code_verifier=pending.entra_code_verifier,
            claude_code_challenge=pending.claude_code_challenge,
            claude_code_challenge_method=pending.claude_code_challenge_method,
            claude_redirect_uri=pending.claude_redirect_uri,
        )

        return _redirect_to_claude(
            pending.claude_redirect_uri,
            {"code": entra_code, "state": pending.claude_state} if pending.claude_state
            else {"code": entra_code},
        )

    # ---- /token: Claude exchanges code → proxy exchanges with Entra → returns token to Claude ----

    async def token(self, request: Request) -> Response:
        form = await request.form()
        grant_type = form.get("grant_type")

        if grant_type == "refresh_token":
            return await self._refresh(form)
        if grant_type != "authorization_code":
            return JSONResponse(
                {"error": "unsupported_grant_type"}, status_code=400,
            )

        code = form.get("code")
        verifier = form.get("code_verifier")
        if not code or not verifier:
            return JSONResponse(
                {"error": "invalid_request",
                 "error_description": "code and code_verifier are required"},
                status_code=400,
            )

        self._sweep()
        issued = self._issued.pop(code, None)
        if issued is None or (time.time() - issued.created_at) > _CODE_TTL:
            return JSONResponse(
                {"error": "invalid_grant",
                 "error_description": "Authorization code expired or unknown."},
                status_code=400,
            )

        if not _verify_pkce(verifier, issued.claude_code_challenge, issued.claude_code_challenge_method):
            return JSONResponse(
                {"error": "invalid_grant",
                 "error_description": "PKCE verifier does not match."},
                status_code=400,
            )

        entra_response = await self._exchange_code_with_entra(
            entra_code=issued.entra_code,
            entra_code_verifier=issued.entra_code_verifier,
        )
        return _passthrough_entra_token(entra_response)

    async def _refresh(self, form) -> Response:
        refresh_token = form.get("refresh_token")
        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request",
                 "error_description": "refresh_token is required"},
                status_code=400,
            )
        data = {
            "client_id": self.entra_client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": f"{self._full_entra_scope} offline_access openid profile",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(self._entra_token_url, data=data)
        return _passthrough_entra_token(r)

    async def _exchange_code_with_entra(
        self, *, entra_code: str, entra_code_verifier: str
    ) -> httpx.Response:
        data = {
            "client_id": self.entra_client_id,
            "grant_type": "authorization_code",
            "code": entra_code,
            "code_verifier": entra_code_verifier,
            "redirect_uri": self._proxy_callback_url,
            "scope": f"{self._full_entra_scope} offline_access openid profile",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await client.post(self._entra_token_url, data=data)

    def _sweep(self) -> None:
        now = time.time()
        for k, v in list(self._pending.items()):
            if now - v.created_at > _PENDING_TTL:
                self._pending.pop(k, None)
        for k, v in list(self._issued.items()):
            if now - v.created_at > _CODE_TTL:
                self._issued.pop(k, None)


# ---- helpers ----

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if method.upper() != "S256":
        # Plain is allowed in OAuth 2.1 only for legacy; we require S256.
        return False
    return _b64url(hashlib.sha256(verifier.encode()).digest()) == challenge


def _redirect_to_claude(claude_redirect_uri: str, params: dict) -> RedirectResponse:
    # Append params to whatever query already exists on the URI.
    parsed = urllib.parse.urlparse(claude_redirect_uri)
    existing = dict(urllib.parse.parse_qsl(parsed.query))
    existing.update({k: v for k, v in params.items() if v is not None})
    new_query = urllib.parse.urlencode(existing)
    url = urllib.parse.urlunparse(parsed._replace(query=new_query))
    return RedirectResponse(url, status_code=302)


def _passthrough_entra_token(r: httpx.Response) -> Response:
    # Forward Entra's JSON body and status, with a few hop headers stripped.
    body = r.content
    media_type = r.headers.get("content-type", "application/json")
    return Response(content=body, status_code=r.status_code, media_type=media_type)
