"""TikTok Ads MCP Server — multi-user, HTTP-transport edition.

The MCP `Server` instance and its tool handlers live here. Tool handlers
resolve the calling user from the per-request context (the Entra `oid`
populated by EntraBearerMiddleware), look up that user's TikTok token in
the shared TokenStore, and dispatch to the per-user TikTokAdsClient.

http_app.py owns construction and calls `configure(...)` to inject the
TokenStore + OAuth client + the public callback URL.
"""

from __future__ import annotations

import json
import logging
from typing import Any, List, Optional

from mcp.server import Server
from mcp.types import TextContent, Tool

from .oauth_simple import TikTokOAuth
from .token_store import TokenStore, UserToken
from .tools import (
    AudienceTools,
    CampaignTools,
    CreativeTools,
    PerformanceTools,
    ReportingTools,
)

logger = logging.getLogger(__name__)

app = Server("tiktok-ads-mcp")

# Injected by http_app.configure() at startup. None until then.
_token_store: Optional[TokenStore] = None
_oauth: Optional[TikTokOAuth] = None


def configure(token_store: TokenStore, oauth: TikTokOAuth) -> None:
    global _token_store, _oauth
    _token_store = token_store
    _oauth = oauth


# ---------- per-request user resolution ----------

def _current_oid() -> Optional[str]:
    """Pull the calling user's Entra `oid` out of the MCP request context."""
    try:
        ctx = app.request_context
    except LookupError:
        return None
    request = getattr(ctx, "request", None)
    if request is None:
        return None
    state = getattr(request, "state", None)
    return getattr(state, "oid", None) if state is not None else None


def _require_user_token() -> tuple[Optional[str], Optional[UserToken], Optional[str]]:
    """Returns (oid, token_record, error_message). On error, the first two
    are populated where available and the third is the message to send back
    to the caller."""
    if _token_store is None or _oauth is None:
        return None, None, "Server is not configured."
    oid = _current_oid()
    if oid is None:
        return None, None, (
            "No authenticated user on request. Entra bearer token is required."
        )
    record = _token_store.get(oid)
    if record is None or record.client is None:
        return oid, None, (
            "Not yet authenticated with TikTok. Call `tiktok_ads_login` to "
            "get an authorization URL, complete it in your browser, then "
            "call `tiktok_ads_auth_status` to confirm."
        )
    return oid, record, None


def _text(payload: Any) -> List[TextContent]:
    if isinstance(payload, str):
        return [TextContent(type="text", text=payload)]
    return [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]


# ---------- tool list ----------

@app.list_tools()
async def list_tools() -> List[Tool]:
    tools: List[Tool] = []

    tools.extend([
        Tool(
            name="tiktok_ads_login",
            description=(
                "Begin TikTok Ads OAuth for the calling user. Returns an "
                "authorization URL — open it in a browser, grant access, and "
                "TikTok will redirect to the server-hosted callback which "
                "completes the flow. Then call `tiktok_ads_auth_status` to "
                "confirm and discover advertiser IDs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "force_reauth": {
                        "type": "boolean",
                        "description": (
                            "If true, return a fresh authorize URL even if a "
                            "token is already stored for this user."
                        ),
                    }
                },
                "additionalProperties": False,
            },
        ),
        Tool(
            name="tiktok_ads_auth_status",
            description="Check whether the calling user has a stored TikTok token.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
        Tool(
            name="tiktok_ads_switch_ad_account",
            description=(
                "Switch the active advertiser account for the calling user. "
                "Only call when the user explicitly asks to switch."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "advertiser_id": {
                        "type": "string",
                        "description": "The advertiser ID to switch to",
                    }
                },
                "required": ["advertiser_id"],
                "additionalProperties": False,
            },
        ),
    ])

    tools.extend([
        Tool(
            name="tiktok_ads_get_campaigns",
            description="Retrieve all campaigns for the advertiser account",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": [
                            "STATUS_ALL", "STATUS_NOT_DELETE", "STATUS_NOT_DELIVERY",
                            "STATUS_DELIVERY_OK", "STATUS_DISABLE", "STATUS_DELETE",
                        ],
                        "description": "Filter campaigns by status",
                    },
                    "limit": {"type": "integer", "default": 10},
                },
            },
        ),
        Tool(
            name="tiktok_ads_get_campaign_details",
            description="Get detailed information about a specific campaign",
            inputSchema={
                "type": "object",
                "properties": {"campaign_id": {"type": "string"}},
                "required": ["campaign_id"],
            },
        ),
        Tool(
            name="tiktok_ads_get_adgroups",
            description="Retrieve ad groups for a campaign",
            inputSchema={
                "type": "object",
                "properties": {
                    "campaign_id": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": [
                            "STATUS_ALL", "STATUS_NOT_DELETE", "STATUS_NOT_DELIVERY",
                            "STATUS_DELIVERY_OK", "STATUS_DISABLE", "STATUS_DELETE",
                        ],
                    },
                },
                "required": ["campaign_id"],
            },
        ),
        Tool(
            name="tiktok_ads_get_campaign_performance",
            description="Get performance metrics for campaigns",
            inputSchema={
                "type": "object",
                "properties": {
                    "campaign_ids": {"type": "array", "items": {"type": "string"}},
                    "date_range": {
                        "type": "string",
                        "enum": ["today", "yesterday", "last_7_days", "last_14_days", "last_30_days"],
                    },
                    "metrics": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["campaign_ids", "date_range"],
            },
        ),
        Tool(
            name="tiktok_ads_get_adgroup_performance",
            description="Get performance metrics for ad groups",
            inputSchema={
                "type": "object",
                "properties": {
                    "adgroup_ids": {"type": "array", "items": {"type": "string"}},
                    "date_range": {
                        "type": "string",
                        "enum": ["today", "yesterday", "last_7_days", "last_14_days", "last_30_days"],
                    },
                    "breakdowns": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["adgroup_ids", "date_range"],
            },
        ),
    ])

    return tools


# ---------- tool dispatch ----------

@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> List[TextContent]:
    try:
        if _token_store is None or _oauth is None:
            return _text({"success": False, "error": "Server is not configured."})

        # Auth tools have their own resolution paths.
        if name == "tiktok_ads_login":
            return _text(await _handle_login(bool(arguments.get("force_reauth"))))
        if name == "tiktok_ads_auth_status":
            return _text(_handle_auth_status())
        if name == "tiktok_ads_switch_ad_account":
            return _text(await _handle_switch(arguments.get("advertiser_id")))

        # Data tools — require a TikTok token for the caller.
        oid, record, err = _require_user_token()
        if err is not None:
            return _text({"success": False, "error": err})
        assert record is not None and record.client is not None

        client = record.client
        if name == "tiktok_ads_get_campaigns":
            result = await CampaignTools(client).get_campaigns(**arguments)
        elif name == "tiktok_ads_get_campaign_details":
            result = await CampaignTools(client).get_campaign_details(**arguments)
        elif name == "tiktok_ads_get_adgroups":
            result = await CampaignTools(client).get_adgroups(**arguments)
        elif name == "tiktok_ads_get_campaign_performance":
            result = await PerformanceTools(client).get_campaign_performance(**arguments)
        elif name == "tiktok_ads_get_adgroup_performance":
            result = await PerformanceTools(client).get_adgroup_performance(**arguments)
        elif name == "tiktok_ads_get_ad_creatives":
            result = await CreativeTools(client).get_ad_creatives(**arguments)
        elif name == "tiktok_ads_upload_image":
            result = await CreativeTools(client).upload_image(**arguments)
        elif name == "tiktok_ads_get_custom_audiences":
            result = await AudienceTools(client).get_custom_audiences(**arguments)
        elif name == "tiktok_ads_get_targeting_options":
            result = await AudienceTools(client).get_targeting_options(**arguments)
        elif name == "tiktok_ads_generate_report":
            result = await ReportingTools(client).generate_report(**arguments)
        else:
            return _text({"success": False, "error": f"Unknown tool '{name}'"})

        return _text(result)

    except Exception as e:
        logger.exception("Error executing tool %s", name)
        return _text({"success": False, "error": f"Error executing {name}: {e}"})


# ---------- auth tool implementations ----------

async def _handle_login(force_reauth: bool) -> dict[str, Any]:
    oid = _current_oid()
    if oid is None:
        return {"success": False, "error": "No Entra `oid` on request."}
    assert _token_store is not None and _oauth is not None

    if not force_reauth:
        existing = _token_store.get(oid)
        if existing is not None and existing.client is not None:
            return {
                "success": True,
                "data": {
                    "status": "already_authenticated",
                    "primary_advertiser_id": existing.primary_advertiser_id,
                    "available_advertiser_ids": existing.advertiser_ids,
                },
            }

    state = _token_store.new_pending_state(oid)
    auth_url = _oauth.get_authorization_url(state)
    return {
        "success": True,
        "data": {
            "status": "auth_started",
            "auth_url": auth_url,
            "message": (
                "Open the auth_url in a browser to grant the TikTok app access "
                "to your ad accounts. After TikTok redirects, call "
                "`tiktok_ads_auth_status` to confirm."
            ),
        },
    }


def _handle_auth_status() -> dict[str, Any]:
    oid = _current_oid()
    if oid is None:
        return {"success": False, "error": "No Entra `oid` on request."}
    assert _token_store is not None
    record = _token_store.get(oid)
    if record is None:
        return {
            "success": True,
            "data": {
                "status": "not_authenticated",
                "message": "No TikTok token on file. Call `tiktok_ads_login`.",
            },
        }
    return {
        "success": True,
        "data": {
            "status": "authenticated",
            "primary_advertiser_id": record.primary_advertiser_id,
            "available_advertiser_ids": record.advertiser_ids,
        },
    }


async def _handle_switch(advertiser_id: Optional[str]) -> dict[str, Any]:
    if not advertiser_id:
        return {"success": False, "error": "advertiser_id is required."}
    oid = _current_oid()
    if oid is None:
        return {"success": False, "error": "No Entra `oid` on request."}
    assert _token_store is not None
    record = _token_store.get(oid)
    if record is None:
        return {"success": False, "error": "Not authenticated. Call `tiktok_ads_login` first."}

    warning = ""
    if advertiser_id not in record.advertiser_ids:
        warning = (
            f" Warning: advertiser {advertiser_id} is not in this user's "
            "available list; the API call may fail."
        )

    await _token_store.switch_advertiser(oid, advertiser_id)
    return {
        "success": True,
        "data": {
            "message": f"Switched to advertiser {advertiser_id}.{warning}",
            "current_advertiser_id": advertiser_id,
            "available_advertiser_ids": record.advertiser_ids,
        },
    }
