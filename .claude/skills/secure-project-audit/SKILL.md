---
name: secure-project-audit
description: Audit and harden a software project against the cybersecurity KB. Use when the user asks to secure, review, harden, or security-check a project, repo, app, API, container, or CI pipeline.
---

# Secure Project Audit

Locate the KB (this repo, or `$CYBERSEC_KB`, or `~/cybersec-kb`). Read the relevant `kb/` files as you go.

## Procedure
1. **Recon**: identify languages, frameworks, entry points, auth, data stores, deployment (Docker/K8s/cloud), CI.
2. **Automated pass**: run `scripts/audit.sh <project-path>` (secrets patterns, risky files, missing baseline files, dependency/tool scans if installed).
3. **Manual review** by priority (see `kb/03-application/owasp-top10.md`):
   - Secrets in code/history/config → `kb/05-identity-crypto/secrets-management.md`
   - Injection, XSS, SSRF, path traversal, deserialization, command exec
   - AuthN/AuthZ on every endpoint, session/JWT handling → `identity-access.md`, `api-security.md`
   - Crypto misuse (weak hashes, hardcoded keys, `Math.random`) → `cryptography.md`
   - Dependencies & lockfiles → `kb/06-secure-sdlc/`
   - Dockerfile/K8s/IaC → `kb/04-cloud-infra/`
   - CI/CD workflows (permissions, pinned actions, secrets) → `kb/06-secure-sdlc/`
   - Logging, error handling, security headers, CORS
4. **Report**: table of findings – Severity (Critical/High/Med/Low/Info), Location (`file:line`), Issue, Fix. Be concrete; no speculative noise.
5. **Fix**: apply safe fixes directly; add missing baseline files from `templates/`; for risky or breaking changes, ask first.
6. **Verify**: re-run tests/linters/`audit.sh`; state what remains.

## Rules
- Never echo secret values; report location and type only; advise rotation.
- Only test code/systems the user owns. No exploitation against third parties.
- Don't weaken controls to pass tests.
