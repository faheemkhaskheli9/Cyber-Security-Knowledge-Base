# Browser and Client-Side Security

## What
Security of code running in the user's browser and of the browser security model: the same-origin policy, cookies, CORS, CSP and related response headers.

## Why it matters
XSS and client-side flaws run attacker code with the victim's session. That means account takeover, data theft and actions taken on the user's behalf. Third-party scripts (analytics, ads, CDNs) are a supply-chain risk on every page view (e.g., Magecart card skimmers, the polyfill.io compromise).

## Attacks
- **XSS**:
  - Reflected, stored, and **DOM-based** (sinks such as `innerHTML`, `document.write`, `eval`, `location` assignment)
  - Mutation XSS that bypasses naive sanitizers
- **CSRF**: cross-site requests riding ambient cookies.
- **Clickjacking**: UI redress inside an invisible iframe.
- **CORS misconfiguration**: reflecting arbitrary `Origin` with `Access-Control-Allow-Credentials: true`.
- **Open redirects** used in phishing and OAuth token theft.
- **postMessage** handlers that don't check `event.origin`.
- **Prototype pollution** leading to XSS or logic bypass.
- **Third-party script compromise** / formjacking.
- **Tokens in `localStorage`** are readable by any XSS.
- **Cross-site leaks** (XS-Leaks) and Spectre-style side channels.

## Defenses
1. **Output encoding by context** (HTML, attribute, JS, URL, CSS). Use framework auto-escaping (React, Angular, Vue). Avoid `dangerouslySetInnerHTML`, `v-html` and `bypassSecurityTrust*`. If HTML is required, sanitize with DOMPurify.
2. **Content Security Policy** (strict, nonce- or hash-based):
   ```
   Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests
   ```
   Add **Trusted Types** (`require-trusted-types-for 'script'`) to eliminate DOM XSS sinks. Roll out with `Content-Security-Policy-Report-Only` first.
3. **Cookies**: `Secure; HttpOnly; SameSite=Lax` (or `Strict`), and the `__Host-` prefix for session cookies. Keep session tokens out of `localStorage`.
4. **CSRF**: rely on SameSite cookies, add synchronizer or double-submit tokens for state-changing requests, and check the `Origin`/`Sec-Fetch-Site` headers.
5. **CORS**: use an explicit origin allowlist. Never reflect arbitrary origins, never send `*` with credentials, and don't trust a `null` origin.
6. **Other headers**:
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy` (disable unused features)
   - `Cross-Origin-Opener-Policy: same-origin`
   - `Cross-Origin-Resource-Policy`
7. **Third-party scripts**: self-host where possible. Use **Subresource Integrity** (`integrity="sha384-..."`) for CDN assets, inventory all scripts, and monitor for changes (PCI DSS 4.0 req. 6.4.3 / 11.6.1).
8. **postMessage**: always validate `event.origin` and the message schema, and set an explicit `targetOrigin`.
9. **Redirects**: validate against an allowlist of relative paths or known hosts.

## How to verify
- Check headers with https://securityheaders.com or `curl -sI https://site`, and test CSP with https://csp-evaluator.withgoogle.com.
- DAST with OWASP ZAP or Burp Suite (authorized). Use DOM Invader for DOM XSS and postMessage.
- Lint for dangerous sinks: Semgrep rules, `eslint-plugin-security`, `eslint-plugin-no-unsanitized`.
- Manual check of a CORS request: `curl -H "Origin: https://evil.example" -I https://api.site/` should not echo the origin.

## References
- OWASP XSS / DOM XSS / CSRF / Clickjacking Prevention Cheat Sheets
- OWASP HTTP Headers Cheat Sheet · MDN Web Security docs
- web.dev Strict CSP · W3C Trusted Types · https://xsleaks.dev
