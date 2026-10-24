# OAuth 2.0 and OpenID Connect Security

## What
**OAuth 2.0** (RFC 6749) lets a client application get a limited **access token** to call an API for a user (resource owner) without handling the user's password. **OpenID Connect (OIDC)** adds an identity layer: an **ID token** (a signed JWT) tells the client who logged in. Roles: authorization server (AS, the IdP), client (web app, SPA, mobile app, service), resource server (API). The current security baseline is **RFC 9700, Best Current Practice for OAuth 2.0 Security** (January 2025); the OAuth 2.1 draft folds most of it into the core spec. Short IdP and API checklists live in `kb/05-identity-crypto/identity-access.md` and `kb/03-application/api-security.md`; this file covers the protocol in depth.

## Why it matters
- OAuth/OIDC is how most SSO, "Sign in with ...", SaaS integrations and API access work, so a flaw in one client or AS configuration can hand an attacker accounts or long-lived API access.
- Tokens bypass MFA: a stolen refresh token or a phished consent grant keeps working after a password reset until it is revoked (`kb/04-cloud-infra/saas-security.md`).
- Real abuse is common and documented: Microsoft reported Storm-2372 running device code phishing against Microsoft 365 accounts since at least August 2024 (published February 2025); stolen OAuth tokens issued to Heroku and Travis CI were used to download private GitHub repositories in 2022.
- Many implementations still use flows the BCP now forbids or discourages (implicit grant, resource owner password credentials).

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Redirect URI manipulation | AS accepts wildcard, prefix or substring matches, so the code or token is sent to an attacker-controlled URL or an open redirector on the client domain | Exact string matching of pre-registered `redirect_uri` (RFC 9700 §4.1); no open redirectors on client domains |
| Authorization code interception / injection | Code stolen from logs, Referer, a malicious app with the same custom URI scheme, or injected into the victim's session | PKCE (RFC 7636) with `S256` for every client, including confidential ones; one-time codes with short lifetime |
| CSRF / login CSRF | Attacker makes the victim's browser complete a flow with the attacker's code | PKCE, or a one-time `state` bound to the user agent; OIDC `nonce` |
| Mix-up attack | Client talks to several AS; a malicious AS tricks it into sending another AS's code to the attacker | Authorization response `iss` parameter (RFC 9207) checked against the expected issuer; distinct redirect URIs per AS |
| Implicit grant token leakage | Access token returned in the URL fragment leaks through history, Referer or injected scripts, and cannot be sender-constrained | Do not use `response_type=token`; use authorization code + PKCE |
| Resource owner password credentials (ROPC) | Client collects the password, which breaks MFA and phishing resistance and trains users to type passwords into apps | RFC 9700: ROPC MUST NOT be used; migrate to code flow or device flow |
| Consent phishing | Attacker registers a legitimate-looking app and asks users for `offline_access`, mail or file scopes | Restrict user consent, admin consent workflow, publisher verification, review grants |
| Device code phishing | Attacker starts a device authorization flow (RFC 8628) and sends the victim the user code with a lure; the victim signs in on the real IdP and the attacker gets tokens | Block the device code flow except for named apps and devices that need it; alert on device code sign-ins; user training |
| Token theft and replay | Bearer tokens copied by infostealers, from logs, browser storage, or a compromised integration vendor | Sender-constrained tokens (DPoP RFC 9449, mTLS RFC 8705), short access token lifetime, refresh token rotation with reuse detection, revocation |
| Token audience confusion | API accepts a token issued for another API or client; ID token used as an access token | Validate `aud`, `iss`, `exp`, scope on every request; resource indicators (RFC 8707); never accept ID tokens at APIs |
| JWT validation flaws | `alg: none`, RS256/HS256 key confusion, unchecked `kid`/`jku` | Pin accepted algorithms, keys only from the AS's `jwks_uri`; follow RFC 8725 (`kb/03-application/api-security.md`) |
| Account linking by unverified email | Client merges accounts when a third-party IdP asserts an email it never verified | Key accounts on `iss` + `sub`, not on email; link only verified emails after re-authentication |

## Defenses

### 1. Choose the right flow per client type
| Client | Flow |
|---|---|
| Server-side web app (confidential) | Authorization code + PKCE, client authenticated with `private_key_jwt` or mTLS rather than a shared secret where the AS supports it |
| Single-page app | Backend-for-frontend (BFF) that holds tokens server-side and gives the browser an `HttpOnly` session cookie; if tokens must live in the browser, code + PKCE, in-memory storage, short lifetimes, DPoP |
| Native / mobile app (public) | Code + PKCE through the system browser, not an embedded web view (RFC 8252); claimed HTTPS redirect URIs (app links / universal links) over custom schemes |
| Service to service | Client credentials with key-based client authentication or workload identity federation; no user tokens |
| Input-constrained device (TV, CLI) | Device authorization grant (RFC 8628), enabled only for the apps that need it |

### 2. Authorization server configuration
- Register exact redirect URIs per client; refuse wildcards. For native apps, allow a variable port only on loopback (`http://127.0.0.1`).
- Require PKCE with `S256` for all clients; reject `plain`.
- Disable the implicit grant and ROPC; disable device code flow by default (in Microsoft Entra ID, a conditional access authentication-flows policy can block it).
- Return `iss` in authorization responses (RFC 9207) and publish metadata (RFC 8414 / OIDC discovery) so clients do not hard-code endpoints.
- Consider Pushed Authorization Requests (PAR, RFC 9126) so request parameters are sent over a back channel and cannot be tampered with in the browser; FAPI 2.0 Security Profile requires PAR, PKCE and sender-constrained tokens for high-value APIs such as open banking.
- Token lifetimes: short access tokens (minutes, not days); refresh tokens either sender-constrained or rotated on every use with reuse detection, plus an absolute lifetime.
- Expose revocation (RFC 7009) and, for opaque tokens, introspection (RFC 7662); revoke all grants on account compromise and offboarding.
- Restrict user consent to low-impact scopes and verified publishers; route the rest through admin consent.

### 3. Client implementation
- Use a maintained, certified library (OpenID Foundation certified implementations list) instead of hand-written flows.
- Validate the ID token fully: signature with an algorithm allowlist, `iss` equals the expected issuer, `aud` contains your `client_id`, `exp`/`iat`, `nonce` matches the one you sent, `azp` when there are multiple audiences.
- Bind `state`, `nonce` and the PKCE `code_verifier` to the user's session; use each once.
- Request the minimum scopes; ask for more incrementally when a feature needs them.
- Never put tokens in URLs, logs, analytics or error reports; set `Referrer-Policy: no-referrer` (or `strict-origin`) on pages that handle the authorization response.
- Store client secrets and signing keys in a secrets manager (`kb/05-identity-crypto/secrets-management.md`) and rotate them.

### 4. Resource server (API)
- Validate every token on every request: signature or introspection, `iss`, `aud` (this API only), expiry, scopes, and the DPoP proof or mTLS binding when tokens are sender-constrained.
- Authorization is still the API's job: scopes say what the client may ask for, not which objects the user owns (BOLA, `kb/03-application/api-security.md`).

### 5. Monitoring
- Log grant and consent events, token issuance by flow type, refresh token reuse detections, and revocations, and send them to the SIEM (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on: new high-privilege consent grants, device code sign-ins outside the expected apps, refresh token reuse, sign-ins for one user from many token-holding IPs, new client secrets on existing apps.

## How to verify
- Fetch the AS metadata (`/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`): `grant_types_supported` should not list `implicit` or `password`; `code_challenge_methods_supported` should include `S256`; check `authorization_response_iss_parameter_supported`.
- Redirect URI tests on a test client: change the path, add a subdomain, append a query string or use an open redirector; every variant must be rejected.
- Start a flow without `code_challenge`; the AS must refuse it if PKCE is required. Replay a used code; it must fail and should revoke tokens issued from it.
- ID token tests: wrong `aud`, expired token, altered signature, `alg: none`, missing or reused `nonce`; the client must reject all.
- Refresh token rotation: use a refresh token twice; the second use must fail and the token family must be revoked.
- Revocation test: revoke a user's sessions at the IdP and confirm the API rejects their tokens within the expected window (immediately for introspected tokens, at expiry for self-contained JWTs).
- Review consent grants and enabled device code usage in the IdP (for Entra ID, sign-in logs filtered on authentication protocol "Device code").
- Run the OpenID Foundation conformance suite against your AS or relying party where you operate one.

## References
- RFC 9700, Best Current Practice for OAuth 2.0 Security (January 2025): https://www.rfc-editor.org/rfc/rfc9700
- RFC 6749, The OAuth 2.0 Authorization Framework: https://www.rfc-editor.org/rfc/rfc6749
- RFC 7636, Proof Key for Code Exchange (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- RFC 9207, OAuth 2.0 Authorization Server Issuer Identification: https://www.rfc-editor.org/rfc/rfc9207
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://www.rfc-editor.org/rfc/rfc9449
- RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: https://www.rfc-editor.org/rfc/rfc8705
- RFC 9126, Pushed Authorization Requests: https://www.rfc-editor.org/rfc/rfc9126
- RFC 8252, OAuth 2.0 for Native Apps: https://www.rfc-editor.org/rfc/rfc8252
- RFC 8628, OAuth 2.0 Device Authorization Grant: https://www.rfc-editor.org/rfc/rfc8628
- RFC 8725, JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- IETF draft, OAuth 2.0 for Browser-Based Applications: https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OpenID Foundation FAPI 2.0 Security Profile: https://openid.net/specs/fapi-security-profile-2_0-final.html
- OWASP OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- Microsoft Threat Intelligence, Storm-2372 conducts device code phishing campaign (February 2025): https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- MITRE ATT&CK T1528 (Steal Application Access Token), T1550.001 (Application Access Token)
- See also `kb/05-identity-crypto/identity-access.md`, `kb/03-application/api-security.md`, `kb/04-cloud-infra/saas-security.md`, `kb/05-identity-crypto/saml-security.md`
