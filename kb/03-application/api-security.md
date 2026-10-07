# API Security (OWASP API Top 10, 2023)

## What
Security of machine-to-machine and app-backend interfaces: REST, GraphQL, gRPC and webhooks. APIs expose business logic and object IDs directly, so authorization flaws dominate. The **OWASP API Security Top 10 (2023)** is the reference list; web risks from `kb/03-application/owasp-top10.md` (injection, crypto) still apply.

## Why it matters
- APIs carry most traffic for SPAs, mobile apps and partners; the client is untrusted and fully scriptable.
- Large breaches have come from simple API flaws: unauthenticated endpoints and sequential IDs (Optus 2022), excessive data exposure (Peloton 2021), BOLA in partner APIs.
- Undocumented "shadow" and old versions stay reachable long after the UI stops using them.

## Attacks
*For authorized testing only; each item lists its fix.*

| # | Risk | Example attack | Fix |
|---|------|----------------|-----|
| API1 | Broken Object Level Authorization (BOLA) – check ownership on every object ID | `GET /v1/orders/1002` with user A's token returns user B's order | Scope queries by the caller (`WHERE id=? AND tenant_id=?`); random UUIDs help but are not authZ |
| API2 | Broken Authentication – short-lived tokens, rotate, rate-limit login | Credential stuffing on `/login`, JWT with `alg:none`, no expiry, API key in URL | Standard IdP/OAuth, MFA, rate limit auth endpoints, validate every token claim |
| API3 | Broken Object Property Level Authorization – don't mass-assign; allowlist fields in/out | `PATCH /users/me {"role":"admin"}`; response leaks `password_hash`, `ssn` | Input DTO with allowed fields only; response serializer per role |
| API4 | Unrestricted Resource Consumption – rate limits, pagination caps, payload size limits, timeouts | `?limit=1000000`, 1 GB upload, SMS/email cost abuse, regex DoS | Caps on page size, body size, timeouts, quotas per key, spend limits on paid integrations |
| API5 | Broken Function Level Authorization – separate admin routes, enforce roles | Regular user calls `DELETE /admin/users/7` or swaps `GET` for `PUT` | Central authZ middleware, deny by default, role checks per route and method |
| API6 | Unrestricted Access to Sensitive Business Flows – bot/abuse protection | Scalper bots buying stock, mass account creation, referral abuse | Device fingerprinting, CAPTCHA/attestation on sensitive flows, per-account velocity limits |
| API7 | SSRF | Webhook URL or "import from URL" set to `http://169.254.169.254/` | Allowlist destinations, block internal ranges, egress proxy, IMDSv2 |
| API8 | Security Misconfiguration – CORS allowlist (never `*` with credentials), TLS, no verbose errors | Stack traces, permissive CORS, missing TLS, unpatched gateway | Hardened config as code, generic errors, security headers |
| API9 | Improper Inventory Management – retire old versions, document all endpoints | `/v1/` still live without new authZ fixes; forgotten `staging-api` host | OpenAPI inventory, gateway as the only ingress, sunset policy, external attack-surface scan |
| API10 | Unsafe Consumption of APIs – validate third-party responses | Trusting a partner API response that injects SQL or redirects to an attacker host | Treat upstream data as untrusted: schema validate, TLS, timeouts, no blind redirects |

### Other common attacks
- **JWT**: `alg:none`, RS256-to-HS256 key confusion (public key used as HMAC secret), weak HMAC secrets cracked offline, `kid`/`jku` header injection, missing `aud` check (token for service A accepted by B).
- **OAuth**: open `redirect_uri` matching steals codes, missing `state` (login CSRF), Implicit flow token leakage, code interception without PKCE, overly broad scopes.
- **GraphQL**: introspection reveals schema, deeply nested queries or aliases (`a1: user{...} a2: user{...}`) for DoS and brute force in one request, batching to bypass rate limits, field-level authZ missing.
- **Mass enumeration** of sequential IDs; **HTTP verb tampering**; **parameter pollution**; **webhook spoofing** without signatures.

## Defenses

### AuthN and authZ
1. Authenticate every endpoint (default deny); public endpoints are an explicit allowlist.
2. Object- and property-level checks in a shared policy layer (OPA/Cedar or framework policies), not per-handler ad hoc code.
3. Separate input and output schemas; never bind request bodies directly to ORM models.

### JWT/OAuth notes
Verify signature + `alg` allowlist (reject `none`), check `exp/aud/iss`, prefer short access tokens + rotating refresh, OAuth2 Authorization Code + PKCE, never Implicit flow, validate `redirect_uri` exactly, use `state`/`nonce`.
- Pin the algorithm in code, never take it from the token header:
  ```python
  claims = jwt.decode(token, key=public_key, algorithms=["RS256"],
                      audience="https://api.example.com", issuer="https://idp.example.com")
  ```
- Fetch keys from the IdP JWKS with caching; ignore attacker-supplied `jku`/`x5u`; restrict `kid` to known values.
- Access tokens 5–15 min; refresh tokens rotated on use with reuse detection; sender-constrained tokens (DPoP or mTLS) for high-value APIs.
- Revocation: short TTL plus a denylist for logout/compromise, or opaque tokens with introspection.
- Don't put PII in JWT payloads (base64, not encrypted). Never accept tokens in query strings (they end up in logs).
- Browser SPAs: BFF pattern with HttpOnly cookies rather than tokens in `localStorage`.
- Client credentials grant for service-to-service; prefer workload identity / mTLS over static API keys. API keys identify a client, they don't authenticate a user.

### GraphQL
Disable introspection in prod, depth/complexity limits, per-field authZ, batching limits.
- Example limits: max depth 10, query cost budget per request and per minute, max aliases ~15, max batch size ~10.
- Persisted queries/operation allowlists for first-party clients; reject arbitrary queries in prod.
- Disable field suggestions ("Did you mean ...") in prod; mask errors.
- AuthZ in resolvers or a directive layer, also for nested objects; DataLoader to avoid N+1 DoS.

### Rate limiting and resource controls
- Limit per API key, per user and per IP (token bucket); stricter on login, OTP, password reset, search and export.
- Return `429` with `Retry-After`; publish `RateLimit-*` headers.
- Body size limit (e.g., 1 MB JSON), max array length, pagination max (e.g., 100), server and upstream timeouts, query cost limits.

### Input schema validation (OpenAPI)
- Design-first OpenAPI 3.x spec as the contract; validate requests *and* responses against it at the gateway or with middleware.
- In the schema: `additionalProperties: false`, `maxLength`, `pattern`, `enum`, `minimum`/`maximum`, `maxItems`, `format: uuid`.
- Lint specs with Spectral (OWASP ruleset) in CI; fail builds on endpoints without `security` defined.

### API gateway
- Single ingress (AWS API Gateway, Azure API Management, Apigee, Kong, Envoy): TLS termination, token validation, rate limits, schema validation, request size limits, WAF, centralized logging.
- Gateway checks are coarse; object-level authZ still belongs in the service.
- mTLS between gateway and services or a service mesh; services not reachable except via the gateway.

### Other
- CORS: explicit origin allowlist; no `*` with credentials.
- Webhooks: HMAC-SHA256 signature over body with timestamp, constant-time compare, reject >5 min old, idempotency keys.
- Inventory: every endpoint in the spec; version and sunset (`Deprecation`/`Sunset` headers); remove old versions.
- Logging: request ID, principal, object IDs, authZ decisions; no tokens or secrets in logs.

## How to verify
- **BOLA/BFLA**: two users and one admin; replay every request with swapped tokens and IDs (Burp Autorize, AuthMatrix, or scripted Postman/pytest suites).
- **Mass assignment**: send extra fields (`role`, `is_admin`, `owner_id`) and confirm they are ignored or rejected.
- **JWT**: test `alg:none`, expired, wrong `aud`, and tampered tokens are all rejected (`jwt_tool` in an authorized test).
- **Rate limits**: `for i in $(seq 1 200); do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.example.com/login -d '{}'; done | sort | uniq -c` should show `429`s.
- **GraphQL**: confirm introspection is off (`{"query":"{__schema{types{name}}}"}` errors), depth/alias limits enforced; tools: InQL, graphql-cop.
- **Spec and DAST**: `spectral lint openapi.yaml`, OWASP ZAP API scan (`zap-api-scan.py -t openapi.yaml -f openapi`), Schemathesis property-based fuzzing (`schemathesis run openapi.yaml --url https://staging.example.com`).
- **Inventory**: compare gateway routes and traffic logs against the spec; scan DNS/certificate transparency for forgotten API hosts.
- Static: Semgrep/CodeQL for missing authZ decorators and unsafe deserialization.

## References
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/
- OWASP REST Security, JWT for Java, GraphQL, Mass Assignment Cheat Sheets: https://cheatsheetseries.owasp.org/
- RFC 8725 JSON Web Token Best Current Practices: https://datatracker.ietf.org/doc/html/rfc8725
- RFC 9700 OAuth 2.0 Security Best Current Practice: https://datatracker.ietf.org/doc/html/rfc9700
- RFC 7636 PKCE: https://datatracker.ietf.org/doc/html/rfc7636
- OpenAPI Specification: https://spec.openapis.org/oas/latest.html
- See also `kb/05-identity-crypto/identity-access.md`, `kb/03-application/owasp-top10.md`, `kb/07-offensive/pentest-methodology.md`
