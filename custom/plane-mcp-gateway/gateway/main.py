"""Process entry point: reads the configuration from the environment and serves the bridge with uvicorn."""
from __future__ import annotations

import os
import sys

import uvicorn

from gateway.app import DEFAULT_REDIRECT_PATTERNS, Config, create_app
from gateway.store import Store


def require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"{name} is not set")
    return value


def build():
    from plane_mcp.server import get_header_mcp

    plane_base = require("PLANE_INTERNAL_BASE_URL")
    os.environ.setdefault("PLANE_BASE_URL", plane_base)
    extra = [p.strip() for p in os.environ.get("MCP_EXTRA_REDIRECT_URIS", "").split(",") if p.strip()]
    config = Config(
        public_base=require("PUBLIC_BASE_URL").rstrip("/"),
        prefix=os.environ.get("MCP_PATH_PREFIX", "/mcp"),
        workspace_slug=require("PLANE_WORKSPACE_SLUG"),
        plane_base_url=plane_base,
        redirect_patterns=[*DEFAULT_REDIRECT_PATTERNS, *extra],
    )
    store = Store(os.environ.get("GATEWAY_DB", "/data/gateway.db"), require("GATEWAY_ENCRYPTION_KEY"))
    header_app = get_header_mcp().http_app(path=config.prefix, stateless_http=True)
    return create_app(config, store, header_app)


if __name__ == "__main__":
    uvicorn.run(build(), host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), proxy_headers=True, forwarded_allow_ips="*", access_log=False)
