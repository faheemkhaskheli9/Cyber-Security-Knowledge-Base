# Passkeys and WebAuthn

## What
**WebAuthn** (W3C Web Authentication) is the browser API for public-key login; **CTAP2** (FIDO Client to Authenticator Protocol) is how the browser talks to an authenticator (platform authenticator such as Windows Hello, Touch ID or Android, or a roaming security key over USB, NFC or BLE). Together they are **FIDO2**. A **passkey** is a FIDO2 discoverable credential: a key pair scoped to one relying party (RP), where the private key stays in the authenticator and the server stores only the public key.

Login in one picture:
1. Server sends a random **challenge** and its **RP ID** (a registrable domain such as `example.com`).
2. The browser checks the page origin is allowed for that RP ID, builds `clientDataJSON` (`type`, `challenge`, `origin`), and asks the authenticator.
3. The authenticator checks **user presence** (touch) and, if asked, **user verification** (PIN or biometric, done locally), then signs `authenticatorData || SHA-256(clientDataJSON)`.
4. The server verifies the signature with the stored public key and checks challenge, origin, RP ID hash and flags.

Two kinds:

| | Synced passkey (multi-device) | Device-bound passkey |
|---|---|---|
| Where the key lives | Passkey provider (Apple, Google, Microsoft, password managers) syncs it, end-to-end encrypted, across the user's devices | One hardware authenticator (security key, TPM, secure element); not exportable |
| Flags | Backup Eligible (`BE`) = 1; Backup State (`BS`) = 1 once backed up | `BE` = 0 |
| Recovery | Survives device loss via the provider account | Lost key means re-enrolment; register at least two |
| Assurance (NIST SP 800-63B rev. 4) | AAL2 (syncable authenticators allowed, with conditions on the sync fabric) | Can meet AAL3 when hardware-based, non-exportable and verifier-impersonation resistant |
| Fit | Consumers and most workforce users | Admins, break-glass, regulated or high-risk roles |

## Why it matters
- **Phishing resistance**: the browser binds the signature to the real origin and the authenticator scopes keys to the RP ID, so a look-alike domain or an AitM proxy (Evilginx-style) cannot get a valid assertion. OTP, push and SMS can all be relayed (`kb/05-identity-crypto/identity-access.md`).
- **No shared secret on the server**: a database breach leaks public keys, not reusable passwords, which removes credential stuffing for passkey-only accounts (`kb/05-identity-crypto/account-takeover-and-credential-stuffing.md`).
- **Regulatory pull**: CISA and NIST name FIDO2/WebAuthn as phishing-resistant MFA; US federal zero trust strategy (OMB M-22-09) requires phishing-resistant MFA for agency staff.
- **The weak points move**: once login is strong, attackers target the fallback methods, account recovery, the synced provider account, and the session cookie issued *after* login.

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Downgrade to a phishable method | AitM page says "passkey unavailable, use password/OTP"; user falls back and is phished | Make passkey-enrolled users passkey-only, or require phishing-resistant strength for sensitive apps (conditional access authentication strengths); remove SMS and password fallbacks over time |
| Weak account recovery | Attacker uses email link, SMS or help-desk reset to add their own passkey | Recovery as strong as login: second passkey, recovery codes, in-person or verified ID proofing; notify on every new credential; cool-down before a new credential can do sensitive actions |
| Session theft after login | Infostealer or AitM steals the cookie or refresh token issued after a valid passkey login | Short sessions, token binding where available (Device Bound Session Credentials in Chrome, DPoP for OAuth), re-authenticate for sensitive actions, revoke sessions on credential change (`kb/05-identity-crypto/oauth-oidc-security.md`) |
| Sync provider account takeover | Attacker takes over the user's Apple/Google/password-manager account and gets their synced passkeys | Strong MFA on the provider account; device-bound keys for admins; for workforce, restrict allowed authenticators by AAGUID |
| Server verification bugs | RP skips checks: challenge not single-use, origin or RP ID hash not compared, `UV` flag ignored, signature not verified for a given algorithm | Use a maintained library (py_webauthn, SimpleWebAuthn, webauthn4j, java-webauthn-server); store challenge server-side, single use, short expiry; test each check |
| Credential swapping and account linking | Credential ID registered to one account accepted for another, or `userHandle` not matched to the account | Look up the credential by ID, require it to belong to the user being logged in, and match `userHandle` |
| Rogue or weak authenticators (workforce) | Unapproved or software authenticators enrolled for privileged users | Request attestation for enterprise enrolment, validate against the FIDO Metadata Service (MDS3), allowlist AAGUIDs |
| Malicious extension or compromised endpoint | Code running in the page or on the device drives a login while the user is present | Endpoint protection and extension allowlists (`kb/03-application/browser-extension-security.md`); `UV` required for high-risk actions; transaction confirmation in the server UI |
| User and credential enumeration | `allowCredentials` lists returned for a typed username reveal which accounts exist | Prefer discoverable credentials with conditional UI (no username first); return fake or empty lists consistently |

## Defenses

### 1. Roll out
- **Consumer apps**: offer passkey creation after a successful login, use **conditional mediation** (`mediation: "conditional"`, passkeys in the username autofill), keep a password only while needed, and let users manage (name, list, delete) their passkeys.
- **Workforce**: enable FIDO2/passkey authentication in the IdP (Entra ID, Okta, Google Workspace), require phishing-resistant strength for admins first, then all users; use device-bound keys for tier-0 and break-glass accounts (`kb/05-identity-crypto/active-directory-security.md`, `kb/04-cloud-infra/cloud-provider-baselines.md`).
- Register **at least two** authenticators per privileged user, or a passkey plus offline recovery codes.

### 2. Registration options (server side)
- `rp.id` set to the registrable domain you want the key valid on, no wider. If several domains share credentials, use **Related Origin Requests** (`/.well-known/webauthn`) instead of loosening checks.
- `authenticatorSelection.residentKey = "required"` (discoverable) and `userVerification = "required"` for login without a password.
- `user.id`: a random, opaque handle (not email); `excludeCredentials` with the user's existing IDs so the same authenticator is not enrolled twice.
- `pubKeyCredParams`: ES256 (`-7`) and RS256 (`-257`) for broad support; add EdDSA (`-8`) if your library verifies it.
- `attestation: "none"` for consumers (privacy, fewer failures); `"direct"` or enterprise attestation only where you will actually check AAGUIDs against MDS3.

### 3. Verify every assertion
Use a maintained library for CBOR/COSE parsing and signature verification. Whatever library you use, these checks must happen. Minimal stdlib sketch (Python 3) of the non-crypto checks, to show what the library must do:

```python
import base64, hashlib, hmac, json, struct

RP_ID = "example.com"
ORIGINS = {"https://example.com", "https://www.example.com"}
UP, UV, BE, BS = 0x01, 0x04, 0x08, 0x10

def unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def check_assertion(client_data_json: bytes, auth_data: bytes, expected_challenge: bytes,
                    stored_sign_count: int, require_uv=True):
    cd = json.loads(client_data_json)
    if cd.get("type") != "webauthn.get":
        raise ValueError("wrong ceremony type")
    if not hmac.compare_digest(unb64u(cd.get("challenge", "")), expected_challenge):
        raise ValueError("challenge mismatch or replay")          # single-use, server-stored
    if cd.get("origin") not in ORIGINS or cd.get("crossOrigin"):
        raise ValueError("unexpected origin")
    if len(auth_data) < 37:
        raise ValueError("authenticatorData too short")
    rp_hash, flags, count = auth_data[:32], auth_data[32], struct.unpack(">I", auth_data[33:37])[0]
    if not hmac.compare_digest(rp_hash, hashlib.sha256(RP_ID.encode()).digest()):
        raise ValueError("RP ID hash mismatch")
    if not flags & UP or (require_uv and not flags & UV):
        raise ValueError("user presence/verification missing")
    if (count or stored_sign_count) and count <= stored_sign_count:
        raise ValueError("signature counter did not increase: possible cloned authenticator")
    # Next (library): verify signature over auth_data + sha256(client_data_json) with the stored COSE key.
    return {"sign_count": count, "backup_eligible": bool(flags & BE), "backed_up": bool(flags & BS)}

# Self-test with synthetic values
chal = b"\x01" * 32
cdj = json.dumps({"type": "webauthn.get", "origin": "https://example.com",
                  "challenge": base64.urlsafe_b64encode(chal).rstrip(b"=").decode()}).encode()
ad = hashlib.sha256(b"example.com").digest() + bytes([UP | UV | BE | BS]) + struct.pack(">I", 0)
print(check_assertion(cdj, ad, chal, stored_sign_count=0))
```

Synced passkeys usually report a signature counter of 0; treat a counter that goes backwards on a non-zero authenticator as a cloning signal, not a routine error.

### 4. Harden the rest of the account
- Notify the user (and for workforce, the SOC) when a passkey is added or removed, and when recovery is used.
- Require re-authentication with a passkey before adding a credential, changing email or phone, or disabling MFA.
- Bind or shorten sessions after login (see Attacks), since passkeys protect the login, not the cookie.
- Log credential ID, AAGUID, `BE`/`BS` flags and `UV` with each authentication event (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).

## How to verify
- **Browser testing**: Chrome DevTools WebAuthn panel (virtual authenticators) or the WebDriver WebAuthn extension in Selenium/Playwright to test registration and login in CI, including a virtual authenticator without `UV` and one with a wrong origin.
- **Negative tests on the server**: replayed challenge, challenge from another session, assertion from `https://evil.example`, RP ID hash for another domain, `UP` or `UV` cleared, credential ID belonging to another user, decreasing non-zero counter. Every one must fail.
- **Coverage report**: in the IdP, the share of users and of admins with a phishing-resistant method, and how many can still sign in with password-only or SMS. Admins should be 100% phishing-resistant with no fallback.
- **Recovery drill**: walk the account-recovery and help-desk flow as an attacker would (authorized test); it must not be possible to add a passkey without strong proofing.
- **Policy check**: confirm AAGUID restrictions and attestation enforcement for privileged groups in the IdP's FIDO2/passkey policy.

## References
- W3C Web Authentication (WebAuthn) specification: https://www.w3.org/TR/webauthn/
- FIDO Alliance, Client to Authenticator Protocol (CTAP): https://fidoalliance.org/specifications/download/
- FIDO Alliance, Passkeys: https://fidoalliance.org/passkeys/
- passkeys.dev (developer guidance from FIDO Alliance and W3C community): https://passkeys.dev/
- NIST SP 800-63B rev. 4, Authentication and Authenticator Management: https://pages.nist.gov/800-63-4/sp800-63b.html
- CISA, Implementing Phishing-Resistant MFA: https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf
- OMB M-22-09, Moving the U.S. Government Toward Zero Trust Cybersecurity Principles: https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
- FIDO Metadata Service (MDS3): https://fidoalliance.org/metadata/
- OWASP Multifactor Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- Chrome for Developers, Device Bound Session Credentials: https://developer.chrome.com/docs/web-platform/device-bound-session-credentials
- py_webauthn: https://github.com/duo-labs/py_webauthn · SimpleWebAuthn: https://simplewebauthn.dev/
- See also `kb/05-identity-crypto/identity-access.md`, `kb/05-identity-crypto/account-takeover-and-credential-stuffing.md`, `kb/05-identity-crypto/oauth-oidc-security.md`, `kb/02-network/email-security.md`, `kb/01-foundations/zero-trust-architecture.md`, `kb/05-identity-crypto/cryptography.md`
