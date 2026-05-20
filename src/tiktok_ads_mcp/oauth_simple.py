"""TikTok For Business OAuth helpers.

Stateless: just builds the authorize URL and exchanges codes for tokens.
Token persistence lives in TokenStore. There is no longer any
file-based cache or local browser flow — the MCP server is hosted and
TikTok redirects back to its own /tiktok/callback endpoint.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class TikTokOAuth:
    AUTHORIZATION_URL = "https://business-api.tiktok.com/portal/auth"
    TOKEN_URL = "https://business-api.tiktok.com/open_api/v1.3/oauth2/access_token/"

    def __init__(self, app_id: str, app_secret: str, redirect_uri: str):
        self.app_id = app_id
        self.app_secret = app_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self, state: str) -> str:
        params = {
            "app_id": self.app_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
        }
        return f"{self.AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"

    async def exchange_code_for_token(self, auth_code: str) -> dict:
        """Exchange an authorization code for an access token.

        Returns a dict with either:
          {access_token, advertiser_ids, primary_advertiser_id}
        on success, or {"error_message": "..."} on failure.
        """
        data = {
            "app_id": self.app_id,
            "secret": self.app_secret,
            "auth_code": auth_code,
        }
        headers = {"Content-Type": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.TOKEN_URL, json=data, headers=headers)
                response.raise_for_status()
                result = response.json()
        except Exception as e:
            logger.exception("TikTok token exchange request failed")
            return {"error_message": str(e)}

        if result.get("code") != 0:
            error_msg = result.get("message", "Unknown error from TikTok")
            logger.error("Token exchange failed: %s", error_msg)
            return {"error_message": error_msg}

        token_data = result.get("data", {}) or {}
        access_token: Optional[str] = token_data.get("access_token")
        advertiser_ids: list[str] = token_data.get("advertiser_ids", []) or []
        if not access_token:
            return {"error_message": "TikTok returned no access_token"}

        return {
            "access_token": access_token,
            "advertiser_ids": advertiser_ids,
            "primary_advertiser_id": advertiser_ids[0] if advertiser_ids else None,
        }
