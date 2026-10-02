# Cyberouter Lab

A Vercel-hosted security workspace for Enclave Cyberouter.

## Current capabilities

- load the live Cyberouter model catalogue from your own key
- focused Ask / Review code / Triage finding playground
- read-only GitHub repository mapping
- Quick Scan across up to 18 security-ranked source/config files
- Deep Audit across up to 48 security-ranked files in multiple model passes
- custom scan scope with path filtering and exact file selection
- pull-request security review from a GitHub PR diff
- best-effort local redaction for common credential formats before model review
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

Source and evidence handling:
- repository files, pull-request diffs, and supplied code/evidence are sent to the selected Cyberouter model for review
- common credential patterns are redacted in the browser first; the chat API and MCP route repeat the best-effort check server-side
- pattern-based redaction cannot identify every secret format, so review the scope and avoid scanning data you are not allowed to share

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


## useLayouts components

Five useLayouts components were incorporated into the production interface: Discrete Tabs, Dynamic Toolbar, Smooth Dropdown, Bento Card, and Save Button. The upstream source snapshots are preserved under `third_party/uselayouts/upstream/` with the original MIT license. Production adapters live under `components/uselayouts/` and keep the original interaction patterns while mapping them to Cyberouter Lab's existing state and dark security-workbench visual system.

## Security casebook

The **Casebook** turns an assessment into an evidence and remediation workflow:

- Capture repository, PR, playground and website reports. **Extract to casebook** makes an explicit additional Cyberouter request for structured finding data (up to 40 findings / 65,000 report characters). Invalid JSON is rejected and the original report remains available. Review extraction for missed findings, incorrect paths and unsupported evidence.
- **Capture web observations** saves deterministic website checks without another model request. **Save report as case** preserves other reports for manual triage.
- Run nine local source-pattern checks on a selected repository scope or pasted code, without a model connection. These are heuristics, not data-flow analysis or dependency vulnerability scanning. Pasted source is discarded after checking; redacted observations enter the case.
- Separate severity and confidence; search and filter findings; assign an owner and UTC due date; track open, investigating, resolved, accepted-risk and false-positive decisions. Resolution requires a reviewer and retest evidence. Risk acceptance and false-positive classification require a reviewer and rationale.
- Compare assessments by rule, path and normalized title (line shifts are ignored). Comparability requires the same target, check kind and observed paths. Changed model wording can change identity. Missing observations are not automatically resolved. Coverage and runtime differences still require human review.
- Review unresolved findings against a severity threshold. A named scope reviewer and coverage/exclusion note are required before a decision can have no policy blockers. This is a local review aid, not an automated deployment gate or certification.
- Generate a STRIDE worksheet for up to eight declared trust boundaries. All questions begin unreviewed; ratings are estimates, not CVSS. Record mitigations and verification, then promote a hypothesis into a finding when it needs tracking.
- Export Markdown handoffs, SARIF 2.1.0, and versioned JSON backups. Import accepts Cyberouter JSON exports up to 4 MB, validates disposition requirements and creates copies instead of replacing existing cases. It does not upload reports to GitHub.

Case data stays in browser memory by default. Refresh removes it. Opt-in **Save cases on this device** uses unencrypted localStorage, capped at 30 cases / 4 MB. Turning it off removes the saved device copy and retains current work in memory. JSON export is the backup and transfer mechanism. Keys and tokens are not fields in the casebook; common secret patterns in case text are redacted, but review all material before saving or sharing. Browser storage is not a secure vault. Local activity is editable data, not an immutable audit trail. There is no server account, shared team workspace or cross-device synchronization.

Repository maps resolve a branch or tag to a commit; subsequent source reads use that commit to avoid mixing revisions. Refresh the repository map before a new assessment if you want newer source. Scope notes include unreadable files, excerpt truncation and GitHub tree truncation.

### Dependency exposure and SBOM

The Casebook's **Dependency exposure** tool reads npm package-lock / shrinkwrap v1–v3 or exact package.json versions in the browser. It deduplicates name/version pairs, supports a development-package filter and lets you choose up to 80 resolved versions per lookup. Ranges and unresolved/git/file entries are omitted rather than guessed. A CycloneDX 1.6 JSON inventory export includes all eligible parsed versions for that filter; it describes the supplied file, not a verified deployed environment.

**Check selected versions** sends only selected npm names, exact versions and display paths through `/api/dependencies/audit` to the fixed OSV.dev advisory API. It does not send the full lockfile or source to OSV. The server bounds concurrency to five requests and the overall lookup to 40 seconds; each package's list is capped at 25 non-withdrawn advisories. Errors and truncation are explicit. The public GET path accepts one npm `name` and exact `version` for read-only inspection.

Matched advisories can be captured in a case (up to 250 findings with a visible cap notice); full lookup JSON can be exported separately. Advisory severity is used only when supplied in OSV's database metadata; missing severity gets a provisional Medium triage value. Fixed versions may belong to different release branches: inspect the advisory before choosing an upgrade. A version match is not proof of runtime exploitability, and a failed or empty lookup must not be treated as verified absence of risk. This tool currently supports npm, not other package ecosystems.
