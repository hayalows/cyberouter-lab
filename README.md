# Cyberouter Lab

A Vercel-hosted security workspace for Enclave Cyberouter.

## Current capabilities

- load the live Cyberouter model catalogue from your own key
- focused Ask / Review code / Triage finding playground
- read-only GitHub repository mapping
- Quick Scan across up to 18 security-ranked source/config files
- Deep Audit across up to 48 security-ranked files in multiple model passes
- pull-request security review from a GitHub PR diff
- simple local secret-pattern checks with values redacted before reporting
- remote Streamable HTTP MCP endpoint at `/api/mcp`

## Security and credential handling

No API keys or GitHub tokens are committed to this repository.

Cyberouter key:
- sessionStorage by default
- optional localStorage only when "Remember on this device" is enabled
- forwarded by same-origin Vercel functions only to the fixed upstream `https://router.enclave.ai/v1`

GitHub token:
- optional, needed only for private repositories
- sessionStorage only
- use a fine-grained token scoped to the specific repositories you want to scan
- recommended permissions: Contents: Read and Pull requests: Read

Repository access is read-only. The site does not commit, push, merge, deploy, or modify target repositories.

## Repository scanning

The repository mapper first reads the GitHub tree and ranks source/config files using security-sensitive path signals such as authentication, authorization, API routes, database access, RLS, uploads, webhooks, secrets, infrastructure, and CI.

A scan then fetches the selected files and sends them to the chosen Cyberouter model in bounded batches. A final model pass deduplicates and consolidates the report.

This is a source review, not a live penetration test. Findings that depend on runtime behavior should be treated as hypotheses until tested in an authorized sandbox or staging environment.

## Remote MCP

Production endpoint:

```text
https://cyberouter-lab.vercel.app/api/mcp
```

For Codex, store the Cyberouter key in an environment variable and configure:

```toml
[mcp_servers.cyberouter]
url = "https://cyberouter-lab.vercel.app/api/mcp"
bearer_token_env_var = "CYBEROUTER_API_KEY"
```

Then verify with:

```bash
codex mcp list
```

MCP tools:
- `cyberouter_list_models`
- `cyberouter_security_review`
- `cyberouter_triage_finding`
- `cyberouter_ask`

MCP adds Cyberouter as a tool provider to Codex. It does not add third-party Cyberouter models to Codex's native OpenAI model picker.
