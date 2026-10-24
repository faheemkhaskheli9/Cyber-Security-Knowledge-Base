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
   - GraphQL endpoints (resolver authZ, depth/cost limits, introspection, CSRF) → `kb/03-application/graphql-security.md`
   - OAuth/OIDC clients and servers (redirect URIs, PKCE, token validation and storage) → `kb/05-identity-crypto/oauth-oidc-security.md`
   - SAML service providers (signature, audience, replay checks; library version) → `kb/05-identity-crypto/saml-security.md`
   - File uploads and archive/document processing (type allowlist, storage, parser sandboxing, serving headers) → `kb/03-application/file-upload-security.md`
   - Business flows that spend, redeem or limit something (atomic check-and-update, idempotency keys, server-side state machines, server-computed prices) → `kb/03-application/business-logic-and-race-conditions.md`
   - WebSocket endpoints (Origin check, handshake auth, per-message authZ, size/rate limits) → `kb/03-application/websocket-security.md`
   - Browser extension code (manifest permissions, message sender checks, MV3 CSP) → `kb/03-application/browser-extension-security.md`
   - Crypto misuse (weak hashes, hardcoded keys, `Math.random`) → `cryptography.md`
   - Dependencies & lockfiles → `kb/06-secure-sdlc/`
   - Data stores (DB exposure, app DB roles, TLS, RLS, backups) → `kb/04-cloud-infra/database-security.md`
   - Dockerfile/K8s/IaC → `kb/04-cloud-infra/`
   - CI/CD workflows (permissions, pinned actions, secrets) → `kb/06-secure-sdlc/`
   - Logging, error handling, security headers, CORS → `kb/06-secure-sdlc/security-logging-and-monitoring.md`
   - Shipped products and libraries (SECURITY.md, security.txt, advisory/CVE and VEX process, supported versions) → `kb/06-secure-sdlc/product-security-incident-response.md`
   - Cloud accounts (org-level audit logs, log archive, responder roles, IR playbooks) → `kb/08-defensive/cloud-incident-response.md`
   - Endpoint and server fleet (EDR coverage, tamper protection, ASR/application control) → `kb/08-defensive/endpoint-security-and-edr.md`
4. **Report**: table of findings – Severity (Critical/High/Med/Low/Info), Location (`file:line`), Issue, Fix. Be concrete; no speculative noise.
5. **Fix**: apply safe fixes directly; add missing baseline files from `templates/`; for risky or breaking changes, ask first.
6. **Verify**: re-run tests/linters/`audit.sh`; state what remains.

## Rules
- Never echo secret values; report location and type only; advise rotation.
- Only test code/systems the user owns. No exploitation against third parties.
- Don't weaken controls to pass tests.
