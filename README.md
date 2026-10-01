# Cyberouter Lab

A small Vercel-hosted workspace for Enclave Cyberouter. It gives you:

- a browser playground for the models available to your Cyberouter API key
- defensive security-review and finding-triage modes
- token usage returned by the upstream API when available
- a live model catalogue from `GET https://router.enclave.ai/v1/models`
- a remote Streamable HTTP MCP server at `/api/mcp`

## Security model

The repository contains **no Cyberouter API key**.

The web UI stores the key in `sessionStorage` by default. If you explicitly enable “Remember on this device”, it uses `localStorage`. Each request sends the key to a same-origin Vercel function in the `x-cyberouter-key` header; the function forwards it to the fixed upstream `https://router.enclave.ai/v1` and does not persist it.

The MCP endpoint uses the caller's `Authorization: Bearer <CYBEROUTER_API_KEY>` token directly as the Cyberouter credential. The server therefore does not need a second stored copy of the key.

Do not add real API keys to source files, GitHub Actions logs, screenshots, or issues.

## Local development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`, paste a temporary Cyberouter key, and connect.

## Deploy to Vercel

Import this GitHub repository into Vercel and deploy it. No environment variables are required for the default setup.

After deployment, open the production URL and enter your Cyberouter API key in the browser.

## Remote MCP

The MCP endpoint is:

```text
https://YOUR_DEPLOYMENT/api/mcp
```

For Codex, keep the secret in an environment variable and configure the remote server:

```toml
[mcp_servers.cyberouter]
url = "https://YOUR_DEPLOYMENT/api/mcp"
bearer_token_env_var = "CYBEROUTER_API_KEY"
```

Available tools:

- `cyberouter_list_models`
- `cyberouter_security_review`
- `cyberouter_triage_finding`
- `cyberouter_ask`

The model name is intentionally explicit. Cyberouter's public site says it can route automatically, but this project does not guess an undocumented auto-router model identifier. Use `cyberouter_list_models` to read the live IDs your key can access.
