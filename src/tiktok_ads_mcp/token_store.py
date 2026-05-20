"""In-memory, per-user TikTok token store.

Keyed by the Entra ID `oid` claim. Holds the user's access token, the
advertiser IDs the token is scoped to, and a cached TikTokAdsClient so we
don't rebuild it on every tool call. Pending OAuth `state` values are tracked
here too, with a TTL, so the /tiktok/callback can map the redirect back to
the user who initiated the flow.

Process-local only. Container restart drops everything and users reauth.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from .tiktok_client import TikTokAdsClient


# How long an unused OAuth `state` lives before we drop it.
_PENDING_STATE_TTL_SECONDS = 15 * 60


@dataclass
class UserToken:
    access_token: str
    advertiser_ids: list[str]
    primary_advertiser_id: Optional[str]
    obtained_at: int
    client: Optional[TikTokAdsClient] = None


@dataclass
class PendingAuth:
    oid: str
    created_at: float = field(default_factory=time.time)


class TokenStore:
    def __init__(self, app_id: str, app_secret: str):
        self._app_id = app_id
        self._app_secret = app_secret
        self._users: dict[str, UserToken] = {}
        self._pending: dict[str, PendingAuth] = {}
        self._lock = asyncio.Lock()

    # ---- user tokens ----

    def get(self, oid: str) -> Optional[UserToken]:
        return self._users.get(oid)

    async def set_token(
        self,
        oid: str,
        access_token: str,
        advertiser_ids: list[str],
    ) -> UserToken:
        primary = advertiser_ids[0] if advertiser_ids else None
        record = UserToken(
            access_token=access_token,
            advertiser_ids=advertiser_ids,
            primary_advertiser_id=primary,
            obtained_at=int(time.time()),
        )
        if primary:
            record.client = TikTokAdsClient(
                app_id=self._app_id,
                app_secret=self._app_secret,
                access_token=access_token,
                advertiser_id=primary,
                available_advertiser_ids=advertiser_ids,
            )
        async with self._lock:
            self._users[oid] = record
        return record

    async def switch_advertiser(self, oid: str, advertiser_id: str) -> UserToken:
        record = self._users.get(oid)
        if record is None:
            raise KeyError(f"No token for user {oid}")
        record.primary_advertiser_id = advertiser_id
        record.client = TikTokAdsClient(
            app_id=self._app_id,
            app_secret=self._app_secret,
            access_token=record.access_token,
            advertiser_id=advertiser_id,
            available_advertiser_ids=record.advertiser_ids,
        )
        return record

    def forget(self, oid: str) -> None:
        self._users.pop(oid, None)

    # ---- pending OAuth states ----

    def new_pending_state(self, oid: str) -> str:
        # Unguessable token tying the TikTok redirect back to this user.
        self._sweep_pending()
        state = secrets.token_urlsafe(32)
        self._pending[state] = PendingAuth(oid=oid)
        return state

    def consume_pending_state(self, state: str) -> Optional[str]:
        # One-shot: returns the oid and removes the mapping.
        self._sweep_pending()
        pending = self._pending.pop(state, None)
        return pending.oid if pending else None

    def _sweep_pending(self) -> None:
        cutoff = time.time() - _PENDING_STATE_TTL_SECONDS
        expired = [s for s, p in self._pending.items() if p.created_at < cutoff]
        for s in expired:
            self._pending.pop(s, None)
