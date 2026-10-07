# CI/CD Pipeline Security

## What
Securing build and deploy systems (GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI) and the path from commit to production. A pipeline holds deploy credentials and can push code to production, which makes it one of the most privileged systems in an organization.

## Why it matters
Compromising CI means compromising everything it deploys. Real incidents include:
- SolarWinds (build tampering)
- Codecov (modified bash uploader leaking CI secrets)
- `tj-actions/changed-files` (2025, compromised Action dumping secrets to logs)
- Ultralytics (PyPI release poisoned via a `pull_request_target` cache/injection chain)

## Attacks (OWASP Top 10 CI/CD Security Risks)
1. **Insufficient flow control**: pushing to main or deploying without review.
2. **Inadequate identity and access management**: stale accounts, overly broad tokens.
3. **Dependency chain abuse**: dependency confusion, typosquats, compromised third-party Actions/plugins.
4. **Poisoned pipeline execution (PPE)**: attacker-controlled code runs with secrets. Examples are `pull_request_target` checking out a fork's head, or untrusted PR changes to the Makefile or CI config.
5. **Insufficient PBAC**: one job's credentials usable everywhere.
6. **Insufficient credential hygiene**: long-lived cloud keys in CI secrets, secrets printed to logs.
7. **Insecure system configuration**: self-hosted runners shared across public repos, unpatched Jenkins.
8. **Ungoverned third-party services**: OAuth apps with org-wide write.
9. **Improper artifact integrity validation**: unsigned artifacts, no provenance.
10. **Insufficient logging and visibility**.

**Script injection**: using `${{ github.event.issue.title }}` (or PR title, branch name) inside `run:` lets anyone who can open an issue or PR execute shell commands.

## Defenses (GitHub Actions examples; concepts apply to all CI)
1. **Least-privilege token**: set `permissions: contents: read` at the workflow top level and grant more per job only when needed.
2. **Pin third-party Actions to a full commit SHA** (`uses: actions/checkout@<40-char-sha> # v4.x`). Let Dependabot update the pins.
3. **No untrusted input in `run:`**: pass it via `env:` and quote it:
   ```yaml
   env:
     TITLE: ${{ github.event.pull_request.title }}
   run: echo "$TITLE"
   ```
4. **Avoid `pull_request_target` and `workflow_run`** with a checkout of PR code. If you must use them, never expose secrets to untrusted code, and split into an unprivileged build job and a privileged job that consumes only artifacts.
5. **OIDC federation to cloud** (`id-token: write` plus a cloud trust policy scoped to repo/branch/environment) instead of static keys.
6. **Protected environments** with required reviewers for production deploys. Use branch protection or rulesets: required reviews, required status checks, signed commits, no force push, CODEOWNERS for `.github/`.
7. **Runners**: use ephemeral, isolated runners. Never attach self-hosted runners to public repos. Restrict egress (e.g., `step-security/harden-runner`).
8. **Secrets**: scope them to environments, mask them in logs, rotate them, and enable secret-scanning push protection.
9. **Artifact integrity**:
   - SLSA build provenance (`actions/attest-build-provenance`).
   - Sign images and artifacts with Sigstore `cosign` (keyless).
   - Verify signatures at deploy or admission (Kyverno, Sigstore policy-controller).
   - Generate an SBOM per build.
10. **Supply-chain hygiene**: commit lockfiles and use `npm ci`, `pip install --require-hashes`, private registry scoping to prevent dependency confusion, and minimum release-age policies for new package versions.
11. **Audit**: export CI audit logs to the SIEM and alert on workflow file changes, new self-hosted runners and secret access.

## How to verify
- `zizmor .github/workflows/` (static analysis for Actions) or `actionlint`.
- OpenSSF Scorecard: `scorecard --repo=github.com/org/repo` (Pinned-Dependencies, Token-Permissions, Dangerous-Workflow, Branch-Protection).
- Grep: `grep -rn 'pull_request_target\|\${{ github.event' .github/workflows`.
- Confirm no long-lived cloud keys remain in CI secrets once OIDC is in place.
- `cosign verify` / `gh attestation verify` on released artifacts.

## References
- OWASP Top 10 CI/CD Security Risks
- GitHub "Security hardening for GitHub Actions" docs · GitHub Security Lab "Preventing pwn requests"
- SLSA: https://slsa.dev · Sigstore: https://sigstore.dev · OpenSSF Scorecard
- See also `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `templates/`
