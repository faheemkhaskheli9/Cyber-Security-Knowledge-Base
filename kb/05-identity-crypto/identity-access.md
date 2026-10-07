# Identity & Access Management

- **AuthN**: something you know/have/are. Prefer phishing-resistant MFA (FIDO2/WebAuthn passkeys) over SMS/TOTP.
- **AuthZ models**: RBAC, ABAC, ReBAC; enforce server-side, deny by default.
- **Passwords**: length > complexity, check against breached lists (HIBP k-anonymity), hash with Argon2id (or bcrypt/scrypt), unique salts, never reversible encryption.
- **Sessions**: random ≥128-bit IDs, rotate on login/priv change, idle + absolute timeouts, invalidate on logout.
- **SSO/Federation**: SAML, OIDC, OAuth2 – validate signatures/audience/redirects.
- **PAM**: just-in-time access, vaulting, session recording, break-glass accounts.
- **Lifecycle**: joiner/mover/leaver, quarterly access reviews, disable stale accounts.
- **Attacks**: credential stuffing, password spraying, phishing/AiTM (Evilginx), MFA fatigue, session hijack, token theft, privilege escalation.
