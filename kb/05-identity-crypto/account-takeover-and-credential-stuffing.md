# Account Takeover and Credential Stuffing

## What
**Account takeover (ATO)** is an attacker gaining control of a legitimate user's account in your application or tenant. The most common routes are automated:
- **Credential stuffing**: replaying username/password pairs leaked from other sites, relying on password reuse (MITRE ATT&CK T1110.004; OWASP Automated Threat OAT-008).
- **Password spraying**: a few common passwords tried against many accounts, staying under per-account lockout (T1110.003).
- **Credential cracking / brute force**: many guesses against one account (T1110.001; OAT-007).

Others are flow abuse: weak password reset and account recovery, MFA bypass (fatigue, SIM swap, AitM relay), stolen session cookies from infostealer malware (T1539), and account linking flaws in social login.

This file covers the customer-facing and workforce login surface as a whole. Authentication methods are in `kb/05-identity-crypto/identity-access.md` and `kb/05-identity-crypto/passkeys-and-webauthn.md`.

## Why it matters
- **Leaked credentials are plentiful**: breach compilations and infostealer logs supply working pairs and live session cookies at scale. In 2024 attackers used infostealer-harvested credentials against Snowflake customer accounts without MFA and stole data from many organizations (Mandiant, UNC5537; `kb/04-cloud-infra/saas-security.md`).
- **It looks like normal logins**: a correct password from a residential proxy is a successful authentication, so per-IP blocking and WAF signatures miss it.
- **Direct monetization**: stored payment methods, loyalty points, gift cards, crypto wallets and personal data; in a workforce tenant, one account opens email, files and SaaS (`kb/02-network/email-security.md`, BEC).
- **Regulatory and contractual impact**: an ATO wave is often a personal-data breach, and PCI DSS v4.0 requires MFA for access into the cardholder data environment (`kb/09-governance/grc-compliance-privacy.md`).

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Credential stuffing | Bot replays leaked pairs across your login and API endpoints, rotating residential proxies and browser fingerprints | MFA or passkeys; breached-password screening at signup, change and login; bot management; per-account and global velocity limits |
| Password spraying | A few passwords (`Season2025!`) tried once against thousands of accounts | Banned-password list plus breached list; alert on many usernames failing from one source or one password pattern; smart lockout |
| Brute force on one account | Many guesses against a known high-value user | Exponential back-off per account (NIST SP 800-63B caps consecutive failures at 100), MFA, notify the user |
| Alternate unprotected endpoints | Mobile API, legacy login, SOAP/XML-RPC, IMAP/POP/SMTP AUTH or a GraphQL mutation skip the rate limits and MFA of the web form | One authentication service for every channel; disable legacy auth; same limits everywhere (`kb/03-application/api-security.md`, `kb/03-application/graphql-security.md`) |
| User enumeration | Different message, status code or response time for "unknown user" vs "wrong password", also on reset and signup | Identical response and timing for all failures; "if the account exists, we sent an email" |
| Password reset flaws | Predictable or long-lived tokens, token in URL leaked through `Referer`, reset link built from a forged `Host` header, token not bound to the user, no invalidation after use | CSPRNG tokens (at least 128 bits), stored hashed, single use, short expiry, absolute URL from config, `Referrer-Policy: no-referrer` on reset pages (OWASP Forgot Password Cheat Sheet) |
| MFA bypass | Push bombing (T1621), SIM swap against SMS, OTP relay through an AitM phishing kit, MFA reset through the help desk | Phishing-resistant MFA; number matching; no SMS for high-value accounts; help-desk identity verification and call-back procedures |
| Session and token theft | Infostealer exfiltrates cookies or refresh tokens; replay skips password and MFA | Short sessions, bind to device where available, re-auth for sensitive actions, revoke all sessions on password or MFA change; detect cookie reuse from a new device/ASN |
| Sensitive change without re-auth | Attacker with a session changes email, phone or MFA, locking the owner out | Re-authenticate and notify the old address/phone before the change takes effect; delay or hold high-risk changes |
| Account pre-hijacking and linking | Attacker registers the victim's email first (unverified), or social login links by unverified email claim; victim later signs up and the attacker keeps access (Sudhodanan and Paverd, USENIX Security 2022) | Verify email before the account can be used; link identities only on verified email and with user confirmation; drop sessions created before verification |
| Fake account creation | Bots register accounts for abuse (OAT-019), later used for fraud or as stuffing targets | Rate-limit signup, verify email/phone, risk scoring, disposable-domain checks |

## Defenses

### 1. Take passwords out of the attack path
- Offer passkeys and phishing-resistant MFA, prioritizing admins, high-value customers and accounts with stored payment methods (`kb/05-identity-crypto/passkeys-and-webauthn.md`).
- Workforce: SSO for every app, local accounts disabled, legacy authentication blocked (`kb/04-cloud-infra/saas-security.md`).

### 2. Screen passwords against breach corpora
Check new and changed passwords (and, at login, flag matches for a forced reset) against known breached passwords, following NIST SP 800-63B. The Have I Been Pwned Pwned Passwords range API uses k-anonymity: only the first 5 hex characters of the SHA-1 hash leave your server. Minimal stdlib example (Python 3):

```python
import hashlib, urllib.request

def breach_count(password: str, timeout=3) -> int:
    """Times this password appears in Pwned Passwords; 0 = not found."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": "example-app-password-check"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for line in resp.read().decode().splitlines():
            h, _, count = line.partition(":")
            if h == suffix:
                return int(count)
    return 0
# Fail open or closed by policy if the API is unreachable; you can also host the downloadable dataset.
```

### 3. Rate-limit by account, source and globally
Per-IP limits alone fail against proxy rotation, and per-account lockout alone lets attackers lock out real users. Combine: per account (back-off, not permanent lockout), per source (IP, /24 or ASN, device fingerprint), and a global failure-rate alarm. Minimal stdlib sketch of a sliding-window limiter keyed on both:

```python
import time
from collections import defaultdict, deque

class LoginLimiter:
    def __init__(self, per_account=5, per_source=20, window=900):
        self.limits = {"acct": per_account, "src": per_source}
        self.window = window
        self.fails = defaultdict(deque)          # (kind, key) -> failure timestamps

    def _recent(self, kind, key, now):
        q = self.fails[(kind, key)]
        while q and q[0] <= now - self.window:
            q.popleft()
        return q

    def allowed(self, account, source, now=None):
        now = time.time() if now is None else now
        return (len(self._recent("acct", account.lower(), now)) < self.limits["acct"]
                and len(self._recent("src", source, now)) < self.limits["src"])

    def record_failure(self, account, source, now=None):
        now = time.time() if now is None else now
        self.fails[("acct", account.lower())].append(now)
        self.fails[("src", source)].append(now)

lim = LoginLimiter()
for i in range(5):
    lim.record_failure("alice@example.com", "203.0.113.7", now=1000 + i)
assert not lim.allowed("alice@example.com", "198.51.100.9", now=1010)   # account throttled
assert lim.allowed("bob@example.com", "198.51.100.9", now=1010)         # other users unaffected
assert lim.allowed("alice@example.com", "198.51.100.9", now=1000 + 901) # window expired
```

In production keep counters in a shared store (Redis) with expiry, return the same generic error and timing whether throttled or wrong, and offer a step-up (CAPTCHA or email challenge) instead of a hard block when throttled. CAPTCHAs add cost for attackers but solving services exist; treat them as friction, not a control.

### 4. Detect bots and risky logins
- Bot management at the edge (device and browser signals, behavioral scoring) on login, signup, reset and gift-card or balance endpoints.
- Risk-based authentication: new device, impossible travel, anonymizing infrastructure, known-bad ASN, leaked-credential match → step-up or block.
- Honeytoken accounts and canary credentials that no real user logs into (`kb/08-defensive/deception-and-honeytokens.md`).

### 5. Secure recovery and account changes
- Password reset: CSPRNG token, hashed at rest, single use, short expiry, invalidated when another is issued or the password changes; build the link from configuration, not the `Host` header.
- Require re-authentication for email, phone, password and MFA changes; notify the old contact point; hold or delay the change for high-value accounts.
- On password reset or confirmed ATO: revoke all sessions and refresh tokens, remove attacker-added MFA methods, OAuth grants, API keys, mail-forwarding rules and payout details.

### 6. Monitor and respond
- Log every authentication event with outcome, account, source IP, ASN, user agent, device ID and MFA method (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on: global login failure ratio spike; one source failing for many accounts; one account failing from many sources; successful login after many failures; many resets requested; MFA method or email changed shortly after a new-device login.
- Playbook: block or challenge the source, force resets for affected accounts, notify users, and review for downstream fraud (`kb/08-defensive/soc-detection-ir.md`).

## How to verify
- **Endpoint inventory**: list every place that accepts a password or issues a session (web, mobile API, legacy, partner, IMAP/SMTP AUTH) and confirm each has the same limits, MFA and logging.
- **Enumeration test**: compare response body, status, headers and timing for an existing and non-existing account on login, signup and reset; they must match.
- **Rate-limit test** (authorized, against your own staging): scripted failures for one account from many IPs, and for many accounts from one IP, must both trigger throttling and an alert.
- **Reset test**: token is single use, expires, is not in logs or `Referer`, and a forged `Host` header does not change the emailed link.
- **Session test**: after password change or MFA reset, previously issued cookies and refresh tokens stop working.
- **Workforce, Entra ID example**: password-spray hunting in sign-in logs (KQL; `50126` = invalid username or password):
  ```kusto
  SigninLogs
  | where TimeGenerated > ago(1d) and ResultType == "50126"
  | summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress
  | where Users > 20
  | order by Users desc
  ```
- **Metrics**: share of accounts with phishing-resistant MFA, share of logins screened against breached passwords, ATO incidents per month and time to contain.

## References
- OWASP Credential Stuffing Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- OWASP Automated Threats to Web Applications (OAT-007, OAT-008, OAT-019): https://owasp.org/www-project-automated-threats-to-web-applications/
- MITRE ATT&CK T1110 Brute Force (.001 Guessing, .003 Spraying, .004 Stuffing): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1539 Steal Web Session Cookie: https://attack.mitre.org/techniques/T1539/ · T1621 MFA Request Generation: https://attack.mitre.org/techniques/T1621/
- NIST SP 800-63B rev. 4, Authentication and Authenticator Management: https://pages.nist.gov/800-63-4/sp800-63b.html
- Have I Been Pwned, Pwned Passwords API (k-anonymity range search): https://haveibeenpwned.com/API/v3#PwnedPasswords
- Sudhodanan and Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web", USENIX Security 2022: https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan
- Mandiant, UNC5537 targets Snowflake customer instances (2024): https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- Microsoft, Password spray investigation playbook: https://learn.microsoft.com/security/compass/incident-response-playbook-password-spray
- See also `kb/05-identity-crypto/identity-access.md`, `kb/05-identity-crypto/passkeys-and-webauthn.md`, `kb/03-application/owasp-top10.md`, `kb/03-application/api-security.md`, `kb/03-application/business-logic-and-race-conditions.md`, `kb/04-cloud-infra/saas-security.md`, `kb/08-defensive/soc-detection-ir.md`
