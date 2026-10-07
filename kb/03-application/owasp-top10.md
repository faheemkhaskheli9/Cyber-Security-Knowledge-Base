# OWASP Top 10 (2021) – Web Application Risks

| # | Risk | Defense essentials |
|---|------|--------------------|
| A01 | Broken Access Control | Deny by default, server-side authZ on every request, object-level checks (IDOR), no trust in client |
| A02 | Cryptographic Failures | TLS, strong algos, no plaintext secrets/PII, proper key mgmt, Argon2id/bcrypt for passwords |
| A03 | Injection (SQL, NoSQL, OS, LDAP, XSS) | Parameterized queries, ORM, input validation, contextual output encoding, CSP |
| A04 | Insecure Design | Threat model, secure patterns, abuse cases, rate limits |
| A05 | Security Misconfiguration | Hardened defaults, no debug in prod, security headers, minimal features |
| A06 | Vulnerable & Outdated Components | SCA, SBOM, automated updates, remove unused deps |
| A07 | Identification & Authentication Failures | MFA, lockout/rate limit, secure session mgmt, no default creds, breached-password checks |
| A08 | Software & Data Integrity Failures | Signed artifacts, verified CI/CD, safe deserialization, SRI |
| A09 | Logging & Monitoring Failures | Log auth/authZ/input failures, tamper-resistant, alerts, no secrets in logs |
| A10 | SSRF | Allowlist outbound destinations, block metadata IPs (169.254.169.254), network segmentation |

## Key vulnerability classes in detail
- **SQLi**: never concatenate; use prepared statements. **XSS**: encode on output, use frameworks' auto-escaping, avoid `innerHTML`/`dangerouslySetInnerHTML`, set CSP. **CSRF**: SameSite cookies + anti-CSRF tokens. **XXE**: disable external entities. **Path traversal**: canonicalize + allowlist. **Open redirect**: allowlist targets. **Deserialization**: never deserialize untrusted data with native formats (pickle, Java serialization). **File upload**: validate type/size, store outside webroot, rename, scan. **Command injection**: avoid shell, use arg arrays. **Race conditions/TOCTOU**: atomic ops, locking. **Clickjacking**: `frame-ancestors`/`X-Frame-Options`.

## Security headers
`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, cookies `Secure; HttpOnly; SameSite`.

## Verify
OWASP ZAP/Burp baseline scan, Semgrep/CodeQL, `securityheaders.com`, ASVS checklist.
