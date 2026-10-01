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
- bounded public-website security assessment with SSRF protections
- verified active web checks gated by a file challenge on the target domain
- optional website-to-repository correlation using security-relevant source files
- a manually triggered OWASP ZAP Baseline workflow that requires the same domain-control challenge
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

Source review findings that depend on runtime behavior should be treated as hypotheses until tested in an authorized sandbox or staging environment.

## Website assessment

The Website area accepts a public HTTP/HTTPS target and offers two modes.

**Passive assessment** uses bounded GET requests to map up to six same-host pages. It inspects browser security headers, cookie flags, forms without submitting them, mixed content, security.txt, robots.txt, and other response metadata.

**Verified active** requires the user to publish a random token at:

```text
/.well-known/cyberouter-lab.txt
```

The server verifies that challenge before adding low-impact CORS and HTTP-method checks. The hosted scanner blocks localhost, private/reserved IP space, internal hostnames, non-standard ports, and redirects outside the verified hostname. It does not submit forms, guess credentials, send exploit payloads, attempt persistence, or perform destructive requests.

The website evidence can optionally be correlated with a repository already loaded in the UI. Cyberouter receives the bounded web evidence plus a small security-ranked source-code sample and is instructed to distinguish observations from hypotheses.

## Deeper DAST runner

The repository also includes `.github/workflows/authorized-zap-baseline.yml`.

It is deliberately manual. Before OWASP ZAP Baseline runs, the workflow requires:

- an HTTPS target on the standard port
- a public, globally routable hostname
- the exact authorization phrase
- a Cyberouter Lab verification token published at the target's well-known path

The ZAP baseline report is retained as a GitHub Actions artifact. This workflow is intended for websites you own or have explicit authorization to assess.

This still is not an unrestricted exploitation environment. Authenticated role testing, business-logic abuse simulation, or exploit validation should be performed in a disposable staging environment with explicit test accounts and scope boundaries.

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
- `cyberouter_passive_web_audit`

MCP adds Cyberouter as a tool provider to Codex. It does not add third-party Cyberouter models to Codex's native OpenAI model picker.


## Interface design

The workspace UI follows the Product Design OS in `hayalows/Skills`: task hierarchy comes before decoration, system status stays visible, advanced security modes use progressive disclosure, feedback is placed next to the action that triggered it, and responsive/accessibility states are treated as part of the component.

Interaction references from useLayouts were adapted rather than dropped in unchanged:
- Discrete Tabs → the animated workspace switcher
- Status Button → scan/connect loading feedback that changes in place
- Bento Card → the compact workspace-status overview
- Dynamic Toolbar → sticky contextual navigation and report controls

Motion is used for feedback and orientation, with a reduced-motion fallback.
