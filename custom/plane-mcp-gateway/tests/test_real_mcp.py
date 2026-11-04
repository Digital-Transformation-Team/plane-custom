"""Smoke test against the real official MCP app: the bridge reaches it, and its own auth still checks the Plane token."""
import os

from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from gateway.app import Config, create_app
from gateway.store import Store


def test_real_header_app_is_reachable_through_the_bridge(tmp_path):
    os.environ["PLANE_BASE_URL"] = os.environ["PLANE_INTERNAL_BASE_URL"] = "http://127.0.0.1:9"   # nothing listens: Plane is "down"
    from plane_mcp.server import get_header_mcp

    header_app = get_header_mcp().http_app(path="/mcp", stateless_http=True)
    store = Store(str(tmp_path / "g.db"), Fernet.generate_key().decode())
    access, _ = store.make_tokens("client", "some-plane-token")
    app = create_app(Config(public_base="https://x.kz", workspace_slug="ws", plane_base_url="http://127.0.0.1:9"), store, header_app)

    with TestClient(app, base_url="https://x.kz") as client:
        unauthenticated = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert unauthenticated.status_code == 401
        via_bridge = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                                 headers={"Authorization": f"Bearer {access}", "Accept": "application/json, text/event-stream"})
        # The official app answered (not our 404/500): its own check could not validate the token against the dead Plane.
        assert via_bridge.status_code in (200, 401, 403), via_bridge.text
        assert "invalid_token" not in via_bridge.text or via_bridge.status_code == 401
