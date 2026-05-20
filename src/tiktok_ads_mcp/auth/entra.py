"""Entra ID (Azure AD) JWT validation.

Validates bearer tokens issued by Entra against:
  - signature (via the tenant's JWKS, cached)
  - audience (the registered app's client ID, or `api://<client-id>`)
  - issuer (must be the configured tenant)
  - expiration
And extracts the `oid` claim, which is stable per user within the tenant
and is what we key the per-user TikTok token store on.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import httpx
import jwt
from jwt import PyJWKClient


@dataclass
class EntraConfig:
    tenant_id: str
    audience: str  # e.g., the app registration's client ID, or "api://<client-id>"

    @property
    def issuer_v2(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def issuer_v1(self) -> str:
        return f"https://sts.windows.net/{self.tenant_id}/"

    @property
    def jwks_uri(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"


class EntraValidator:
    def __init__(self, config: EntraConfig):
        self.config = config
        # PyJWKClient handles HTTP fetch + caching of signing keys keyed by `kid`.
        self._jwks_client = PyJWKClient(config.jwks_uri)

    def validate(self, bearer_token: str) -> dict:
        """Validate the JWT and return the decoded claims.

        Raises jwt.PyJWTError (or subclasses) on any validation failure.
        """
        signing_key = self._jwks_client.get_signing_key_from_jwt(bearer_token).key
        # Accept both v1 and v2 issuers — Entra issues both depending on the
        # token version negotiated with the app registration.
        valid_issuers = [self.config.issuer_v1, self.config.issuer_v2]

        claims = jwt.decode(
            bearer_token,
            signing_key,
            algorithms=["RS256"],
            audience=self.config.audience,
            issuer=valid_issuers,
            options={"require": ["exp", "iss", "aud"]},
        )

        if claims.get("tid") != self.config.tenant_id:
            raise jwt.InvalidIssuerError(
                f"Token tid {claims.get('tid')!r} does not match expected tenant"
            )

        if not claims.get("oid"):
            raise jwt.InvalidTokenError("Token has no `oid` claim")

        return claims
