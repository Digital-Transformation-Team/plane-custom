# plane-mcp-gateway

OAuth 2.1 bridge for Plane's MCP server (`plane-mcp-server`, MIT) on a self-hosted Plane Community Edition.

```
ChatGPT / claude.ai ──OAuth──▶ gateway ──Bearer <user's Plane API token>──▶ official MCP app ──▶ Plane API
```

* **Sign-in = signing in to Plane.** The bridge shares the host with Plane, so the browser sends it the visitor's Plane session
  cookie. If it is valid the page says "you are signed in as X" and one click on *Allow* makes the bridge create a personal API
  token for that person (the same request Plane's "API tokens" page makes, labelled `MCP: <app>`, 90 days, revocable in Plane);
  the cookie is used for that one call and never stored. Without a Plane session the page links to Plane's sign-in. Pasting a
  token by hand remains available as a fallback. The token is checked against Plane, stored **encrypted** (Fernet) and swapped in on every MCP call:
  the AI acts in Plane with exactly that user's rights. Authorization codes and access/refresh tokens are stored only as
  SHA-256 hashes; refresh tokens rotate; codes live 5 minutes; PKCE (S256) is mandatory; redirect addresses must be
  registered and match an allow-list of known clients; wrong tokens lock an address for 10 minutes after 10 tries.
* Clients with a token header (Claude Code, Claude Desktop through `mcp-remote`, Cursor) do not need this: the official
  server already accepts `Authorization: Bearer <token>` + `X-Workspace-Slug`.

## Configuration (environment)
| Variable | Meaning |
|---|---|
| `PUBLIC_BASE_URL` | public address, e.g. `https://jira-idtai.narxoz.kz` |
| `PLANE_INTERNAL_BASE_URL` | address of Plane's API reachable from the container |
| `PLANE_WORKSPACE_SLUG` | the one workspace this gateway serves |
| `GATEWAY_ENCRYPTION_KEY` | Fernet key: `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"` |
| `GATEWAY_DB` | SQLite file (default `/data/gateway.db`, mount a volume) |
| `MCP_PATH_PREFIX` | default `/mcp` |
| `MCP_EXTRA_REDIRECT_URIS` | extra allowed redirect patterns, comma separated |

Routes: `/mcp` (MCP, streamable HTTP), `/mcp/oauth/{register,authorize,token}`, `/.well-known/oauth-protected-resource[/mcp]`,
`/.well-known/oauth-authorization-server[/mcp]`, `/health`. The last two `.well-known` families must be routed to this
service at the **root** of the public host (clients look for them there).

## Tests
```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt pytest
PLANE_INTERNAL_BASE_URL=http://127.0.0.1:9 python -m pytest -q tests
```
