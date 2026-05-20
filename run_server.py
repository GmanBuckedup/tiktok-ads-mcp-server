#!/usr/bin/env python3
"""Entry point for the TikTok Ads MCP Server (Streamable HTTP)."""

import os
import sys
from pathlib import Path

# Make the in-tree package importable when running this script directly.
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

import uvicorn  # noqa: E402

from tiktok_ads_mcp.http_app import create_app  # noqa: E402

# `uvicorn run_server:app` is also supported by Azure Container Apps etc.
app = create_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=os.getenv("LOG_LEVEL", "info"))
