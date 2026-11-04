"""OAuth 2.1 bridge in front of Plane's MCP server, for connectors that insist on OAuth (ChatGPT, claude.ai).

Plane Community Edition has no OAuth provider, so this service is its own small authorization server whose
"login" step is the user pasting their personal Plane API token. The token is validated against Plane, kept
encrypted, and swapped in for the opaque OAuth access token on every MCP call: the user acts in Plane with exactly
their own rights. Nothing here can do more than the user's Plane token can.

Flow:  /mcp (401 + resource metadata)  ->  /.well-known/...  ->  POST /mcp/oauth/register  ->  /mcp/oauth/authorize
       (token form)  ->  redirect with a code  ->  POST /mcp/oauth/token (PKCE)  ->  /mcp with Bearer <access token>.
"""
from __future__ import annotations

import base64
import fnmatch
import logging
import hashlib
import html
import json
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urlencode, urlparse

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route

from gateway.store import Store

DEFAULT_REDIRECT_PATTERNS = [
    "http://localhost:*", "http://localhost:*/*", "http://127.0.0.1:*", "http://127.0.0.1:*/*",
    "https://claude.ai/*", "https://claude.com/*",
    "https://chatgpt.com/connector/oauth/*", "https://chatgpt.com/connector_platform_oauth_redirect",
    "cursor://anysphere.cursor-mcp/oauth/*", "https://vscode.dev/redirect", "https://insiders.vscode.dev/redirect",
]

ValidatePat = Callable[[str], Awaitable[bool]]
log = logging.getLogger("gateway")


@dataclass
class Config:
    public_base: str                      # https://jira-idtai.narxoz.kz  (no trailing slash)
    prefix: str = "/mcp"
    workspace_slug: str = ""
    plane_base_url: str = ""              # internal URL of Plane's API, e.g. http://192.168.4.96:6767
    redirect_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_REDIRECT_PATTERNS))
    max_failed_logins: int = 10           # per client address and 10 minutes
    session_cookie_name: str = "session-id"
    token_days: int = 90                  # lifetime of the Plane API token the bridge creates for a user

    @property
    def issuer(self) -> str:
        return self.public_base + self.prefix

    @property
    def resource_metadata_url(self) -> str:
        return f"{self.public_base}/.well-known/oauth-protected-resource{self.prefix}"


def redirect_allowed(uri: str, patterns: list[str]) -> bool:
    parsed = urlparse(uri)
    if parsed.fragment or not parsed.scheme:
        return False
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
        return False                      # plain http only for loopback
    return any(fnmatch.fnmatchcase(uri, pattern) for pattern in patterns)


def pkce_ok(verifier: str, challenge: str) -> bool:
    computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return secrets.compare_digest(computed, challenge)


class PlaneSession:
    """Acts on Plane with the visitor's own session cookie (Plane and this bridge share one host, so the browser sends it).

    `who` tells who is signed in; `create_token` makes a personal API token for that person, exactly what the "API tokens"
    page of Plane does. The cookie is used for these two calls only and is never stored."""

    def __init__(self, config: Config):
        self.base = config.plane_base_url.rstrip("/")
        self.origin = config.public_base
        self.cookie_name = config.session_cookie_name

    def _headers(self, cookie: str) -> dict[str, str]:
        # Plane checks Origin/Referer of state-changing requests against its own web address.
        return {"Cookie": f"{self.cookie_name}={cookie}", "Origin": self.origin, "Referer": self.origin + "/", "Accept": "application/json"}

    async def who(self, cookie: str) -> dict | None:
        if not cookie:
            return None
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{self.base}/api/users/me/", headers=self._headers(cookie))
            if r.status_code != 200:
                return None
            data = r.json()
            return {"name": data.get("display_name") or data.get("email") or "", "email": data.get("email", "")}
        except (httpx.HTTPError, ValueError):
            return None

    async def create_token(self, cookie: str, label: str, expires_days: int = 90) -> str | None:
        expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expires_days * 86400))
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(f"{self.base}/api/users/api-tokens/", headers=self._headers(cookie),
                                      json={"label": label[:100], "description": "Создан шлюзом MCP при входе через Plane. Можно отозвать здесь.", "expired_at": expires})
            return r.json().get("token") if r.status_code == 201 else None
        except (httpx.HTTPError, ValueError):
            return None


def plane_validator(config: Config) -> ValidatePat:
    async def validate(pat: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                me = await client.get(f"{config.plane_base_url.rstrip('/')}/api/v1/users/me/", headers={"x-api-key": pat})
                if me.status_code != 200:
                    return False
                if config.workspace_slug:
                    ws = await client.get(f"{config.plane_base_url.rstrip('/')}/api/v1/workspaces/{config.workspace_slug}/members/", headers={"x-api-key": pat})
                    return ws.status_code == 200
                return True
        except httpx.HTTPError:
            return False
    return validate


CONSENT = """<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Доступ к Plane</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem}}
button{{padding:.7rem 1.2rem;font:inherit;margin-top:1rem;cursor:pointer}}details{{margin-top:2rem}}input{{width:100%;padding:.6rem;font:inherit;box-sizing:border-box}}.err{{color:#b00020}}a{{color:#0b57d0}}</style></head>
<body><h1>Доступ к Plane</h1><p>Приложение <strong>{client}</strong> просит разрешение читать и менять задачи в Plane от вашего имени.</p>
{body}
<details><summary>Или вставить личный API-токен вручную</summary><form method="post"><input type="hidden" name="csrf" value="{csrf}">
<p><label for="t">API-токен Plane (Profile settings → API tokens)</label></p><input id="t" name="token" type="password" autocomplete="off"><button type="submit">Разрешить с токеном</button></form></details>
</body></html>"""

SIGNED_IN = """<p>Вы вошли в Plane как <strong>{who}</strong>.</p>
<form method="post"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="mode" value="session">
<button type="submit">Разрешить</button></form>
<p>Приложение получит те же права, что у вас в Plane, не больше. Доступ можно отозвать в Plane: Profile settings → API tokens.</p>"""

SIGN_IN = """{error}<p>Сначала войдите в Plane в этом браузере, потом вернитесь на эту страницу.</p>
<p><a href="{login}" target="_blank" rel="noopener">Войти в Plane</a> (откроется в новой вкладке), затем <a href="">обновите эту страницу</a>.</p>"""

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
PAGE_HEADERS = {**NO_STORE, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://localhost:* http://127.0.0.1:* cursor:; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}


def create_app(config: Config, store: Store, header_app, validate_pat: ValidatePat | None = None, clock=time.time, plane_session=None) -> Starlette:
    validate = validate_pat or plane_validator(config)
    session = plane_session or PlaneSession(config)
    failures: dict[str, list[float]] = {}

    def too_many(ip: str) -> bool:
        now = clock()
        recent = [t for t in failures.get(ip, []) if now - t < 600]
        failures[ip] = recent
        return len(recent) >= config.max_failed_logins

    def oauth_error(status: int, code: str, description: str) -> JSONResponse:
        return JSONResponse({"error": code, "error_description": description}, status_code=status, headers=NO_STORE)

    async def protected_resource(_: Request) -> JSONResponse:
        return JSONResponse({"resource": config.issuer, "authorization_servers": [config.issuer], "bearer_methods_supported": ["header"]})

    async def auth_server(_: Request) -> JSONResponse:
        base = config.issuer + "/oauth"
        return JSONResponse({
            "issuer": config.issuer, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
            "registration_endpoint": base + "/register", "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        })

    async def register(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return oauth_error(400, "invalid_client_metadata", "JSON body expected")
        uris = body.get("redirect_uris") if isinstance(body, dict) else None
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) and redirect_allowed(u, config.redirect_patterns) for u in uris):
            return oauth_error(400, "invalid_redirect_uri", "redirect_uris must be allowed https addresses of a known client")
        client = store.add_client(uris, str(body.get("client_name") or "MCP client"))
        return JSONResponse({"client_id": client.client_id, "redirect_uris": client.redirect_uris, "client_name": client.name,
                             "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]},
                            status_code=201, headers=NO_STORE)

    def authorize_params(request: Request):
        q = request.query_params
        client = store.client(q.get("client_id", ""))
        redirect_uri = q.get("redirect_uri", "")
        if not client or redirect_uri not in client.redirect_uris:
            return None, "Неизвестное приложение или адрес возврата."
        if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            return None, "Нужен response_type=code и PKCE (S256)."
        return (client, redirect_uri, q.get("code_challenge", ""), q.get("state", "")), None

    def page(client_name: str, body: str, csrf: str, status: int = 200) -> HTMLResponse:
        return HTMLResponse(CONSENT.format(client=html.escape(client_name), body=body, csrf=csrf), status_code=status, headers=PAGE_HEADERS)

    async def authorize(request: Request) -> Response:
        params, problem = authorize_params(request)
        if problem:
            return HTMLResponse(f"<h1>Ошибка</h1><p>{html.escape(problem)}</p>", status_code=400, headers=PAGE_HEADERS)
        client, redirect_uri, challenge, state = params
        ip = request.client.host if request.client else "?"
        cookie = request.cookies.get(config.session_cookie_name, "")
        if request.method == "GET":
            csrf = secrets.token_urlsafe(24)
            who = await session.who(cookie)
            if who:
                body = SIGNED_IN.format(who=html.escape(who["name"] or who["email"]), csrf=csrf)
            else:
                login = f"{config.public_base}/?" + urlencode({"next_path": str(request.url.path) + "?" + str(request.url.query)})
                body = SIGN_IN.format(error="", login=html.escape(login))
            response = page(client.name, body, csrf)
            response.set_cookie("mcp_csrf", csrf, httponly=True, secure=config.public_base.startswith("https"), samesite="strict", max_age=600, path=config.prefix + "/oauth")
            return response
        form = await request.form()
        csrf_cookie = request.cookies.get("mcp_csrf", "")
        if not csrf_cookie or not secrets.compare_digest(csrf_cookie, str(form.get("csrf", ""))):
            return HTMLResponse("<h1>Ошибка</h1><p>Сессия формы устарела, откройте ссылку заново.</p>", status_code=400, headers=PAGE_HEADERS)
        if too_many(ip):
            return HTMLResponse("<h1>Слишком много попыток</h1><p>Подождите 10 минут.</p>", status_code=429, headers=PAGE_HEADERS)

        token = str(form.get("token", "")).strip()
        if form.get("mode") == "session" and not token:
            # "Continue as <you>": the bridge makes a Plane API token for the signed-in person, then forgets the cookie.
            token = await session.create_token(cookie, f"MCP: {client.name}", config.token_days) or ""
            if not token or not await validate(token):
                failures.setdefault(ip, []).append(clock())
                error = '<p class="err">Не удалось получить доступ через ваш вход в Plane. Войдите в Plane заново или вставьте токен ниже.</p>'
                return page(client.name, SIGN_IN.format(error=error, login=html.escape(config.public_base + "/")), csrf_cookie, 401)
        elif not token or not await validate(token):
            failures.setdefault(ip, []).append(clock())
            error = '<p class="err">Plane не принял этот токен или у него нет доступа к рабочему пространству.</p>'
            return page(client.name, SIGN_IN.format(error=error, login=html.escape(config.public_base + "/")), csrf_cookie, 401)
        code = store.make_code(client.client_id, redirect_uri, challenge, token)
        query = {"code": code, **({"state": state} if state else {})}
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(redirect_uri + separator + urlencode(query), status_code=303, headers=NO_STORE)

    async def token(request: Request) -> JSONResponse:
        form = await request.form()
        grant = str(form.get("grant_type", ""))
        client_id = str(form.get("client_id", ""))
        if not store.client(client_id):
            return oauth_error(401, "invalid_client", "unknown client")
        if grant == "authorization_code":
            taken = store.take_code(str(form.get("code", "")))
            if not taken:
                return oauth_error(400, "invalid_grant", "code is unknown, used or expired")
            code_client, redirect_uri, challenge, pat = taken
            if code_client != client_id or redirect_uri != str(form.get("redirect_uri", "")) or not pkce_ok(str(form.get("code_verifier", "")), challenge):
                return oauth_error(400, "invalid_grant", "client, redirect_uri or code_verifier does not match")
            access, refresh = store.make_tokens(client_id, pat)
        elif grant == "refresh_token":
            rotated = store.rotate_refresh(str(form.get("refresh_token", "")), client_id)
            if not rotated:
                return oauth_error(400, "invalid_grant", "refresh token is unknown, used or expired")
            access, refresh = rotated
        else:
            return oauth_error(400, "unsupported_grant_type", "authorization_code or refresh_token")
        store.purge()
        return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh}, headers=NO_STORE)

    class McpBridge:
        """ASGI: swaps the opaque OAuth access token for the user's Plane token, then calls the official MCP app.
        One log line per MCP call (method, path, JSON-RPC method, status, duration, client): no tokens, no payloads."""

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                await header_app(scope, receive, send)
                return
            started = time.time()
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            seen = {"status": 0, "rpc": "", "ctype": ""}

            def note():
                log.info(json.dumps({"ev": "mcp", "method": scope["method"], "path": scope["path"], "rpc": seen["rpc"], "status": seen["status"],
                                     "ctype": seen["ctype"], "ms": int((time.time() - started) * 1000), "ua": headers.get("user-agent", "")[:60]}))

            async def logged_send(message):
                if message["type"] == "http.response.start":
                    seen["status"] = message["status"]
                    seen["ctype"] = next((v.decode() for k, v in message.get("headers", []) if k.lower() == b"content-type"), "")
                await send(message)

            async def logged_receive():
                message = await receive()
                if message["type"] == "http.request" and not seen["rpc"]:
                    try:
                        seen["rpc"] = str(json.loads(message.get("body") or b"{}").get("method", ""))
                    except (ValueError, AttributeError):
                        seen["rpc"] = "?"
                return message

            auth = headers.get("authorization", "")
            pat = store.pat_for_access(auth[7:].strip()) if auth.lower().startswith("bearer ") else None
            if not pat:
                response = JSONResponse({"error": "invalid_token"}, status_code=401,
                                        headers={"WWW-Authenticate": f'Bearer resource_metadata="{config.resource_metadata_url}"', **NO_STORE})
                await response(scope, receive, logged_send)
                note()
                return
            rewritten = [(k, v) for k, v in scope["headers"] if k.lower() not in (b"authorization", b"x-workspace-slug", b"x-api-key")]
            rewritten += [(b"authorization", f"Bearer {pat}".encode()), (b"x-workspace-slug", config.workspace_slug.encode())]
            try:
                await header_app({**scope, "headers": rewritten}, logged_receive, logged_send)
            finally:
                note()

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    @asynccontextmanager
    async def lifespan(_: Starlette):
        inner = getattr(header_app, "lifespan", None)
        if inner is None:
            yield
        else:
            async with inner(header_app):
                yield

    p = config.prefix
    routes = [
        Route(f"/.well-known/oauth-protected-resource{p}", protected_resource),
        Route("/.well-known/oauth-protected-resource", protected_resource),
        Route(f"/.well-known/oauth-authorization-server{p}", auth_server),
        Route("/.well-known/oauth-authorization-server", auth_server),
        Route(f"{p}/oauth/register", register, methods=["POST"]),
        Route(f"{p}/oauth/authorize", authorize, methods=["GET", "POST"]),
        Route(f"{p}/oauth/token", token, methods=["POST"]),
        Route("/health", health),
        Mount("/", app=McpBridge()),
    ]
    return Starlette(routes=routes, lifespan=lifespan)
