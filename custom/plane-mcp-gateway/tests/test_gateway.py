import base64
import hashlib
import re
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from gateway.app import Config, create_app, pkce_ok, redirect_allowed
from gateway.store import Store

REDIRECT = "https://chatgpt.com/connector/oauth/abc123"


class FakeMcp:
    """Stands in for the official MCP app: records the headers it receives."""

    def __init__(self):
        self.seen = []

    async def __call__(self, scope, receive, send):
        self.seen.append({k.decode(): v.decode() for k, v in scope["headers"]})
        await receive()                                   # a real MCP app reads the request body
        body = b'{"ok":true}'
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})


class FakeSession:
    """Stands in for Plane's session endpoints: one signed-in cookie, and a switch for token creation."""

    def __init__(self):
        self.cookie = "plane-session-cookie"
        self.created = []
        self.can_create = True

    async def who(self, cookie):
        return {"name": "Анна Иванова", "email": "anna@narxoz.kz"} if cookie == self.cookie else None

    async def create_token(self, cookie, label, expires_days=90):
        self.created.append((cookie, label, expires_days))
        return "good-token" if self.can_create and cookie == self.cookie else None


@pytest.fixture
def env(tmp_path):
    now = [1000.0]
    store = Store(str(tmp_path / "g.db"), Fernet.generate_key().decode(), clock=lambda: now[0])
    mcp = FakeMcp()
    valid = {"good-token"}

    async def validate(pat):
        return pat in valid

    config = Config(public_base="https://jira-idtai.narxoz.kz", workspace_slug="narxoz", plane_base_url="http://plane")
    session = FakeSession()
    app = create_app(config, store, mcp, validate_pat=validate, clock=lambda: now[0], plane_session=session)
    return type("Env", (), {"client": TestClient(app, base_url="https://jira-idtai.narxoz.kz"), "store": store, "mcp": mcp, "now": now, "config": config, "session": session})


def challenge_for(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def register(env, uris=None):
    r = env.client.post("/mcp/oauth/register", json={"redirect_uris": uris or [REDIRECT], "client_name": "ChatGPT"})
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def login(env, client_id, token="good-token", verifier="v" * 50, state="xyz"):
    params = {"client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code", "code_challenge": challenge_for(verifier), "code_challenge_method": "S256", "state": state}
    page = env.client.get("/mcp/oauth/authorize", params=params)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return env.client.post("/mcp/oauth/authorize", params=params, data={"csrf": csrf, "token": token}, follow_redirects=False), verifier


def test_discovery_documents_point_at_this_server(env):
    meta = env.client.get("/.well-known/oauth-authorization-server/mcp").json()
    assert meta["issuer"] == "https://jira-idtai.narxoz.kz/mcp"
    assert meta["token_endpoint"] == "https://jira-idtai.narxoz.kz/mcp/oauth/token"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    resource = env.client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource["resource"] == "https://jira-idtai.narxoz.kz/mcp"
    assert env.client.get("/.well-known/oauth-authorization-server").status_code == 200


def test_mcp_without_a_token_answers_401_with_the_resource_metadata_pointer(env):
    r = env.client.post("/mcp", json={})
    assert r.status_code == 401
    assert 'resource_metadata="https://jira-idtai.narxoz.kz/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]
    assert env.mcp.seen == []


def test_registration_accepts_known_client_redirects_only(env):
    assert env.client.post("/mcp/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]}).status_code == 400
    assert env.client.post("/mcp/oauth/register", json={"redirect_uris": ["http://chatgpt.com/connector/oauth/x"]}).status_code == 400
    assert env.client.post("/mcp/oauth/register", json={"redirect_uris": []}).status_code == 400
    assert env.client.post("/mcp/oauth/register", content=b"not json").status_code == 400
    assert env.client.post("/mcp/oauth/register", json={"redirect_uris": ["http://localhost:8123/callback"]}).status_code == 201


def test_redirect_allow_rules():
    patterns = ["https://claude.ai/*", "http://localhost:*"]
    assert redirect_allowed("https://claude.ai/api/mcp/auth_callback", patterns)
    assert redirect_allowed("http://localhost:5555", patterns)
    assert not redirect_allowed("http://claude.ai/x", patterns)
    assert not redirect_allowed("https://claude.ai.evil.com/x", patterns)
    assert not redirect_allowed("https://claude.ai/x#frag", patterns)


def test_full_flow_swaps_the_oauth_token_for_the_users_plane_token(env):
    client_id = register(env)
    response, verifier = login(env, client_id)
    assert response.status_code == 303
    location = urlparse(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    query = parse_qs(location.query)
    assert query["state"] == ["xyz"]

    tokens = env.client.post("/mcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id, "code": query["code"][0], "redirect_uri": REDIRECT, "code_verifier": verifier})
    assert tokens.status_code == 200
    access = tokens.json()["access_token"]
    assert tokens.headers["cache-control"] == "no-store"

    result = env.client.post("/mcp", json={"jsonrpc": "2.0"}, headers={"Authorization": f"Bearer {access}", "X-Workspace-Slug": "attacker", "X-Api-Key": "other"})
    assert result.status_code == 200
    seen = env.mcp.seen[-1]
    assert seen["authorization"] == "Bearer good-token"
    assert seen["x-workspace-slug"] == "narxoz"
    assert "x-api-key" not in seen


def test_a_wrong_plane_token_is_refused_and_no_code_is_issued(env):
    client_id = register(env)
    response, _ = login(env, client_id, token="bad-token")
    assert response.status_code == 401
    assert "location" not in response.headers


def test_the_form_needs_its_csrf_cookie(env):
    client_id = register(env)
    params = {"client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code", "code_challenge": "c" * 43, "code_challenge_method": "S256"}
    env.client.get("/mcp/oauth/authorize", params=params)
    r = env.client.post("/mcp/oauth/authorize", params=params, data={"csrf": "forged", "token": "good-token"})
    assert r.status_code == 400


def test_authorize_rejects_unknown_clients_unregistered_redirects_and_missing_pkce(env):
    client_id = register(env)
    base = {"client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code", "code_challenge": "c" * 43, "code_challenge_method": "S256"}
    assert env.client.get("/mcp/oauth/authorize", params={**base, "client_id": "nope"}).status_code == 400
    assert env.client.get("/mcp/oauth/authorize", params={**base, "redirect_uri": "https://claude.ai/other"}).status_code == 400
    assert env.client.get("/mcp/oauth/authorize", params={k: v for k, v in base.items() if k != "code_challenge"}).status_code == 400
    assert env.client.get("/mcp/oauth/authorize", params={**base, "code_challenge_method": "plain"}).status_code == 400


def test_the_code_works_once_and_only_with_the_right_verifier(env):
    client_id = register(env)
    response, verifier = login(env, client_id)
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    data = {"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": REDIRECT}

    assert env.client.post("/mcp/oauth/token", data={**data, "code_verifier": "w" * 50}).status_code == 400   # wrong verifier burns the code
    assert env.client.post("/mcp/oauth/token", data={**data, "code_verifier": verifier}).status_code == 400   # already consumed


def test_codes_expire_after_five_minutes(env):
    client_id = register(env)
    response, verifier = login(env, client_id)
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    env.now[0] += 301

    r = env.client.post("/mcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier})

    assert r.status_code == 400


def test_access_tokens_expire_and_refresh_tokens_rotate(env):
    client_id = register(env)
    response, verifier = login(env, client_id)
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    first = env.client.post("/mcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier}).json()

    env.now[0] += 3601
    assert env.client.post("/mcp", json={}, headers={"Authorization": f"Bearer {first['access_token']}"}).status_code == 401

    second = env.client.post("/mcp/oauth/token", data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    assert env.client.post("/mcp", json={}, headers={"Authorization": f"Bearer {second.json()['access_token']}"}).status_code == 200
    assert env.client.post("/mcp/oauth/token", data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": first["refresh_token"]}).status_code == 400   # old one is gone


def test_a_token_of_one_client_cannot_be_refreshed_by_another(env):
    a, b = register(env), register(env)
    response, verifier = login(env, a)
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    tokens = env.client.post("/mcp/oauth/token", data={"grant_type": "authorization_code", "client_id": a, "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier}).json()

    assert env.client.post("/mcp/oauth/token", data={"grant_type": "refresh_token", "client_id": b, "refresh_token": tokens["refresh_token"]}).status_code == 400


def test_too_many_wrong_tokens_lock_the_address_for_ten_minutes(env):
    client_id = register(env)
    for _ in range(10):
        assert login(env, client_id, token="bad")[0].status_code == 401
    assert login(env, client_id, token="good-token")[0].status_code == 429
    env.now[0] += 601
    assert login(env, client_id, token="good-token")[0].status_code == 303


def test_plane_tokens_are_stored_encrypted_and_codes_hashed(env, tmp_path):
    client_id = register(env)
    login(env, client_id)
    raw = (tmp_path / "g.db").read_bytes()
    assert b"good-token" not in raw


def test_pkce_check():
    assert pkce_ok("v" * 50, challenge_for("v" * 50))
    assert not pkce_ok("x" * 50, challenge_for("v" * 50))


def authorize_params(client_id, verifier="v" * 50):
    return {"client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code", "code_challenge": challenge_for(verifier), "code_challenge_method": "S256", "state": "s1"}


def csrf_of(page):
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def test_signed_in_visitor_sees_who_they_are_and_continues_without_a_token(env):
    client_id = register(env)
    env.client.cookies.set("session-id", env.session.cookie)
    params = authorize_params(client_id)
    page = env.client.get("/mcp/oauth/authorize", params=params)
    assert "Анна Иванова" in page.text and "Разрешить" in page.text

    response = env.client.post("/mcp/oauth/authorize", params=params, data={"csrf": csrf_of(page), "mode": "session"}, follow_redirects=False)

    assert response.status_code == 303
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    assert env.session.created == [("plane-session-cookie", "MCP: ChatGPT", 90)]
    tokens = env.client.post("/mcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": REDIRECT, "code_verifier": "v" * 50}).json()
    env.client.post("/mcp", json={}, headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert env.mcp.seen[-1]["authorization"] == "Bearer good-token"
    assert "plane-session-cookie" not in response.headers.get("location", "")   # the session cookie never leaves


def test_a_visitor_who_is_not_signed_in_gets_a_link_to_plane_not_a_code(env):
    client_id = register(env)
    page = env.client.get("/mcp/oauth/authorize", params=authorize_params(client_id))
    assert "Войти в Plane" in page.text
    assert "next_path=" in page.text
    assert 'name="mode"' not in page.text      # there is no "continue as" button without a session


def test_continue_as_fails_cleanly_when_plane_refuses_to_make_a_token(env):
    client_id = register(env)
    env.session.can_create = False
    env.client.cookies.set("session-id", env.session.cookie)
    params = authorize_params(client_id)
    page = env.client.get("/mcp/oauth/authorize", params=params)

    response = env.client.post("/mcp/oauth/authorize", params=params, data={"csrf": csrf_of(page), "mode": "session"}, follow_redirects=False)

    assert response.status_code == 401
    assert "location" not in response.headers


def test_continue_as_without_a_session_cookie_cannot_mint_a_code(env):
    client_id = register(env)
    params = authorize_params(client_id)
    page = env.client.get("/mcp/oauth/authorize", params=params)

    response = env.client.post("/mcp/oauth/authorize", params=params, data={"csrf": csrf_of(page), "mode": "session"}, follow_redirects=False)

    assert response.status_code == 401


def test_continue_as_needs_the_csrf_token_too(env):
    client_id = register(env)
    env.client.cookies.set("session-id", env.session.cookie)
    params = authorize_params(client_id)
    env.client.get("/mcp/oauth/authorize", params=params)

    response = env.client.post("/mcp/oauth/authorize", params=params, data={"csrf": "forged", "mode": "session"}, follow_redirects=False)

    assert response.status_code == 400
    assert env.session.created == []


def test_every_mcp_call_is_logged_without_secrets(env, caplog):
    import logging as _l
    caplog.set_level(_l.INFO, logger="gateway")
    client_id = register(env)
    response, verifier = login(env, client_id)
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    tokens = env.client.post("/mcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier}).json()

    env.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Authorization": f"Bearer {tokens['access_token']}"})
    env.client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "initialize"})

    lines = [r.message for r in caplog.records if r.name == "gateway"]
    assert any('"rpc": "tools/list"' in l and '"status": 200' in l for l in lines)
    assert any('"status": 401' in l for l in lines)
    assert not any(tokens["access_token"] in l or "good-token" in l for l in lines)
