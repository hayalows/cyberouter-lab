# AGENTS.md

## Repository

This repository is **Cyberouter Lab**.

Production URL:

```text
https://cyberouter-lab.vercel.app
```

The production Vercel project is already connected to this GitHub repository. A successful push to `main` triggers the production deployment automatically.

## Default operating rule

When asked to change this project:

1. inspect the current repository state before editing
2. preserve existing security boundaries and API-key handling
3. make the smallest coherent implementation that solves the request
4. run the production build before publishing
5. do not expose secrets in source, logs, screenshots, commits, or output
6. do not silently weaken the website-scanner authorization or SSRF protections
7. commit the completed work with a clear message

## When the user says "push live", "ship it", or equivalent

Treat that as explicit permission to publish the completed changes to production.

Use this sequence:

```bash
git status
git diff --stat
npm install
npm run build
git status
git add -A
git commit -m "<clear summary>"
git fetch origin
git log --oneline --decorate --max-count=8 HEAD origin/main
git push origin HEAD:main
```

Before pushing, make sure `origin/main` does not contain newer work that would be overwritten. Integrate newer remote commits normally. Never force-push production.

If the current branch already contains a clean committed change set, do not create an extra empty commit. Push the existing commit.

## Production verification

After pushing to `main`, wait for the deployment and verify the public production URL, not only a preview URL.

At minimum:

```bash
curl -I https://cyberouter-lab.vercel.app
```

Confirm:

- the response is successful
- the new UI or behavior is actually present on production
- the site still loads on the root route
- any changed API route returns the expected safe response
- the build did not introduce exposed secrets

If GitHub Actions are available, confirm the repository build for the pushed commit passes as well.

If production does not update after the push, investigate the GitHub-to-Vercel deployment connection before claiming the change is live.

## Vercel

Do not create a second Vercel project unless explicitly asked.

The intended production project is the one serving:

```text
https://cyberouter-lab.vercel.app
```

Prefer the existing GitHub integration over a manual `vercel --prod` deployment. Use a direct Vercel production deployment only if the Git integration is unavailable and the user explicitly authorizes that route.

## Security boundaries that must survive refactors

Cyberouter API keys must not be committed.

The hosted website scanner must continue to block or tightly constrain:

- localhost and loopback targets
- private/reserved IP ranges
- internal hostnames
- arbitrary non-standard ports
- unsafe cross-host redirects
- destructive requests
- password guessing or credential attacks
- exploit payloads against arbitrary third-party targets

The stronger website-testing path must remain authorization-gated.

Repository access should remain read-only unless the user explicitly asks for a separate write workflow.

## UI / UX

For substantial interface work, use the repository's established design direction and the user's Product Design OS principles:

- clear task hierarchy
- one obvious next action per state
- visible system status
- progressive disclosure for advanced controls
- useful empty/loading/error states
- mobile-first responsive behavior
- keyboard focus and accessible labels
- reduced-motion support
- restrained motion that communicates state rather than decoration

Do not turn the interface into a generic neon "cyberpunk" dashboard.

## What to report back

After shipping, state:

- what changed
- the commit SHA
- whether the production build passed
- whether `https://cyberouter-lab.vercel.app` was verified
- any remaining limitation or follow-up that was not completed

Never say something is live until production has actually been checked.
