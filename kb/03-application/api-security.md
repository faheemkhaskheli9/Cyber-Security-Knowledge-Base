# API Security (OWASP API Top 10, 2023)

1. Broken Object Level Authorization (BOLA) – check ownership on every object ID.
2. Broken Authentication – short-lived tokens, rotate, rate-limit login.
3. Broken Object Property Level Authorization – don't mass-assign; allowlist fields in/out.
4. Unrestricted Resource Consumption – rate limits, pagination caps, payload size limits, timeouts.
5. Broken Function Level Authorization – separate admin routes, enforce roles.
6. Unrestricted Access to Sensitive Business Flows – bot/abuse protection.
7. SSRF.
8. Security Misconfiguration – CORS allowlist (never `*` with credentials), TLS, no verbose errors.
9. Improper Inventory Management – retire old versions, document all endpoints.
10. Unsafe Consumption of APIs – validate third-party responses.

## JWT/OAuth notes
Verify signature + `alg` allowlist (reject `none`), check `exp/aud/iss`, prefer short access tokens + rotating refresh, OAuth2 Authorization Code + PKCE, never Implicit flow, validate `redirect_uri` exactly, use `state`/`nonce`.

## GraphQL
Disable introspection in prod, depth/complexity limits, per-field authZ, batching limits.
