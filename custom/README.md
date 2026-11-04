# custom/

Our own code that lives next to the upstream Plane sources. Everything here is in its own directory, so merging upstream
(`git fetch upstream && git merge upstream/preview`) never conflicts with it.

| Directory | What |
|---|---|
| `plane-mcp-gateway/` | OAuth bridge in front of Plane's official MCP server, so ChatGPT and claude.ai connectors (which require OAuth) can work with a Plane Community Edition that has no OAuth provider. Each user signs in with their own Plane API token and acts with their own rights. |
