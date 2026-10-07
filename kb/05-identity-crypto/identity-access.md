# Identity & Access Management

## What
IAM covers who a user or workload is (**authentication**, AuthN: something you know/have/are), what they may do (**authorization**, AuthZ), and how identities are created, changed and removed over time (lifecycle and governance). It spans workforce identity (IdP, SSO, AD/Entra ID), customer identity and machine identities.

## Why it matters
- Valid accounts and stolen credentials are among the most common initial access vectors in breach reports (MITRE ATT&CK T1078).
- Identity is the perimeter for SaaS and cloud: one phished admin session can expose the whole tenant.
- Broken access control is OWASP Top 10 A01 (2021).

## Attacks
For authorized testing only; each is paired with its defense.
- **Credential stuffing** (breached password reuse) → MFA, breached-password checks, bot detection, rate limiting.
- **Password spraying** (one common password across many accounts) → banned-password lists, smart lockout, alert on many failed users from one source.
- **Phishing / AitM phishing kits** (e.g., Evilginx proxies the real login and steals the session cookie, bypassing OTP and push) → phishing-resistant MFA (FIDO2/passkeys are origin-bound), token binding, conditional access requiring compliant devices.
- **MFA fatigue / push bombing** → number matching, rate-limit prompts, alert on repeated denials, user reporting.
- **SIM swap** against SMS OTP → move off SMS.
- **Session hijack / token theft** (infostealer cookies, refresh tokens, OAuth consent phishing) → short token lifetimes, continuous access evaluation, device-bound tokens, admin consent for OAuth apps, revoke sessions on incident.
- **Privilege escalation** via overbroad roles, IDOR, missing server-side checks → deny by default, object-level authorization tests.
- **Active Directory**:
  - Kerberoasting (offline cracking of service tickets) → gMSAs, long random service passwords, AES only; detect 4769 with RC4 encryption.
  - Pass-the-Hash / Pass-the-Ticket → LAPS, Credential Guard, tiered admin, Protected Users, restrict NTLM.
  - DCSync (replication rights abuse) → limit `Replicating Directory Changes All` to DCs; alert on 4662 from non-DC hosts.
  - Details and more in `kb/04-cloud-infra/os-hardening.md`.

## Defenses

### MFA strength ladder (weakest → strongest)
1. SMS / voice OTP (SIM swap, interception; avoid for admins)
2. Email OTP / magic link
3. TOTP authenticator app (phishable via AitM)
4. Push with **number matching** and context (phishable via AitM, resists fatigue)
5. **FIDO2/WebAuthn passkeys / security keys**, smart cards (PIV/CBA): phishing-resistant, required for admins and high-risk users.
Prefer phishing-resistant MFA (FIDO2/WebAuthn passkeys) over SMS/TOTP. Secure recovery flows as strongly as login (no SMS fallback for passkey users).

### SSO / Federation
- SAML, OIDC, OAuth2: validate signatures/audience/redirects.
- OIDC: Authorization Code + PKCE, exact-match `redirect_uri`, validate `iss`, `aud`, `exp`, `nonce`, pin accepted `alg`; no implicit flow.
- SAML: validate signature on the assertion, reject unsigned/XSW-wrapped responses, check `Audience`, `Recipient`, `NotOnOrAfter`, use a maintained library.
- Centralize on one IdP; SCIM for provisioning; disable local app accounts except break-glass.

### Authorization models
- **RBAC** (roles), **ABAC** (attributes: department, device, time), **ReBAC** (relationships, e.g., Google Zanzibar-style: OpenFGA, SpiceDB).
- Enforce server-side, deny by default, check on every request at the object level; centralize policy (OPA/Cedar) where possible.
- **Least privilege**: scoped roles, no standing admin, separate admin accounts from daily accounts.

### PAM and just-in-time access
- Just-in-time access (Entra PIM, AWS IAM Identity Center with temporary elevation, Teleport), approval + time limit + justification.
- Vaulting of shared/privileged credentials, session recording, break-glass accounts (2 accounts, FIDO2, excluded from CA only where needed, monitored, tested regularly).

### Lifecycle (joiner / mover / leaver)
- Joiner: provision from HR source of truth via SCIM with role-based birthright access.
- Mover: remove old access when roles change (avoid privilege creep).
- Leaver: disable within hours, revoke sessions and tokens, rotate shared secrets they knew, transfer ownership.
- Quarterly access reviews (monthly for privileged), disable stale accounts (e.g., 90 days inactive), inventory service accounts with owners.

### Passwords (NIST SP 800-63B)
- Length > complexity: minimum 8 (15 recommended when password is the only factor), allow at least 64 characters and all printable/Unicode characters, allow paste and password managers.
- Check against breached lists (HIBP k-anonymity) and context words; no composition rules, no periodic forced rotation (change on evidence of compromise); no security questions.
- Rate-limit failed attempts.
- Storage: hash with Argon2id (or bcrypt/scrypt), unique salts, never reversible encryption. See `kb/05-identity-crypto/cryptography.md`.

### Sessions
- Random ≥128-bit IDs from a CSPRNG; cookies `Secure; HttpOnly; SameSite=Lax` (or `Strict`).
- Rotate on login/priv change, idle + absolute timeouts, invalidate on logout server-side.
- Short-lived access tokens (5–60 min) with rotating refresh tokens and reuse detection; re-authenticate for sensitive actions.

### Conditional access
- Require compliant/managed devices for admin and sensitive apps; block legacy authentication protocols.
- Risk-based policies (impossible travel, anonymizing IPs, leaked credentials) → step-up or block.
- Phishing-resistant authentication strength for privileged roles; continuous access evaluation.

## How to verify
- IdP reports: % users with phishing-resistant MFA, accounts without MFA, legacy auth sign-ins (should be zero).
- Review privileged role assignments: standing vs. JIT, accounts with admin and no FIDO2.
- Test OIDC/SAML: tampered signature, wrong audience, modified `redirect_uri` must all be rejected.
- Test authZ: access another user's object by ID (IDOR) with a second account; expect 403/404.
- Session cookie flags in browser devtools; session ID changes after login; logout invalidates server-side.
- AD: PingCastle, BloodHound (authorized use), `Get-ADUser -Filter {ServicePrincipalName -like "*"}` to inventory Kerberoastable accounts.
- Leaver test: a disabled account's existing tokens stop working within the expected window.

## References
- NIST SP 800-63B (Digital Identity Guidelines, Authentication): https://pages.nist.gov/800-63-4/
- NIST SP 800-207 (Zero Trust Architecture)
- OWASP Authentication, Session Management, Authorization and Multifactor Authentication Cheat Sheets: https://cheatsheetseries.owasp.org/
- OWASP ASVS (V2 Authentication, V3 Session, V4 Access Control)
- CISA "Implementing Phishing-Resistant MFA" fact sheet
- FIDO Alliance passkeys: https://fidoalliance.org/passkeys/
- MITRE ATT&CK T1078 (Valid Accounts), T1558 (Steal or Forge Kerberos Tickets): https://attack.mitre.org
- See also `kb/04-cloud-infra/os-hardening.md`, `kb/05-identity-crypto/secrets-management.md`, `kb/03-application/api-security.md`, `kb/04-cloud-infra/cloud-security.md`
