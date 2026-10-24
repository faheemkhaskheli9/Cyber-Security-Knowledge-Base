# SAML Security

## What
**SAML 2.0** (Security Assertion Markup Language, OASIS standard) is the XML-based federation protocol behind most enterprise single sign-on. An **Identity Provider (IdP)** (Entra ID, Okta, AD FS, Shibboleth) authenticates the user and issues a signed XML **assertion**; the **Service Provider (SP)** (the application) receives it at its **Assertion Consumer Service (ACS)** URL, usually through the browser via HTTP-POST, validates it and creates a session. Trust rests on the IdP's signing key and on the SP validating every part of the response correctly. Short SSO checklist: `kb/05-identity-crypto/identity-access.md`; OAuth 2.0 / OIDC equivalents: `kb/05-identity-crypto/oauth-oidc-security.md`.

## Why it matters
- **One bug, every account**: an SP that accepts a forged or altered assertion lets an attacker sign in as any user, including administrators, with no password or MFA.
- **XML signatures are hard to verify correctly**: the signed element, the element the application reads and the parser that reads it can differ. Signature-wrapping and parser-differential bugs keep appearing in widely used libraries (ruby-saml CVE-2024-45409, CVE-2025-25291 and CVE-2025-25292; comment-truncation bugs such as CVE-2017-11427 in python-saml).
- **The IdP is Tier 0**: whoever holds the IdP token-signing key can mint assertions for every federated application ("Golden SAML", used in the 2020 SolarWinds-related intrusions; CISA AA21-008A).
- **Long-lived integrations**: SP metadata, certificates and attribute mappings are configured once and rarely reviewed.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Signature exclusion | Remove the `<ds:Signature>`; SP accepts unsigned responses or assertions | Require a valid signature on the assertion (or on the response covering it) for every message; fail closed |
| XML Signature Wrapping (XSW) | Move the signed assertion elsewhere in the document and insert a forged one where the application looks; the signature still verifies but over a different element | Use the element the signature verification returned (by reference), not a fresh XPath lookup; reject documents with more than one assertion; schema-validate; use a maintained library |
| Parser differential | Signature check and attribute extraction use different XML parsers or traversal, which disagree on the same document | Single parser for verification and extraction; keep the library patched (ruby-saml 2024-2025 advisories) |
| Comment / canonicalization truncation | `user@evil.test<!---->.victim.test`: canonicalization ignores the comment so the signature holds, but the app reads only the first text node | Libraries that read the full text content; patched versions; reject NameIDs containing comments |
| Certificate faking | SP verifies the signature with the certificate embedded in the message's `KeyInfo` instead of the configured IdP certificate | Pin the IdP signing certificate(s) from metadata; ignore `KeyInfo` for trust decisions |
| Assertion replay | A captured assertion (logs, proxy, browser history) is posted again | Enforce `NotBefore` / `NotOnOrAfter` with small clock skew; cache assertion `ID`s until expiry and reject repeats; check `InResponseTo` for SP-initiated flows |
| Audience / recipient confusion | An assertion issued for SP A (attacker-controlled or low-value) is accepted by SP B | Check `Audience` equals this SP's entity ID, `Recipient` and `Destination` equal this ACS URL, `Issuer` equals the expected IdP |
| XXE and transform abuse | SAML parser resolves external entities or runs XSLT transforms listed in the signature | Disable DTDs and external entities; allow only the expected transforms (enveloped signature, exclusive C14N) |
| Weak algorithms | SHA-1 signatures or digests; RSA key too short | Require RSA-SHA256 or stronger; reject SHA-1; 2048-bit RSA minimum (`kb/05-identity-crypto/cryptography.md`) |
| Unsolicited / IdP-initiated login CSRF | SP accepts unsolicited responses, so an attacker logs the victim into the attacker's account or replays a leaked response | Prefer SP-initiated flows with `InResponseTo` checks; if IdP-initiated is required, short validity and strict replay cache |
| RelayState open redirect | `RelayState` returned after login redirects to any URL, used for phishing or token leakage | Accept only relative paths or an allowlist |
| Golden SAML | Attacker with IdP admin or host access steals the token-signing private key (for example AD FS) and forges assertions offline (MITRE ATT&CK T1606.002) | Protect the IdP as Tier 0 (`kb/05-identity-crypto/active-directory-security.md`); keys in an HSM where supported; alert on signing-key export and on federation trust changes |
| Federation trust tampering | Attacker with cloud admin rights adds a federated domain or a new signing certificate to an existing trust | Alert on federation configuration changes; restrict who can modify trusts; review trusts regularly |
| Account linking by mutable attribute | SP maps users by email or display name that users can change at the IdP, or that a second IdP also asserts | Map on an immutable, IdP-scoped identifier (persistent NameID or object ID) plus the `Issuer` |

## Defenses

### 1. Use a maintained library, configured strictly
- Never parse or verify SAML by hand. Use a maintained SP library or the platform's built-in SSO, subscribe to its advisories and patch quickly.
- Strict mode on: signed assertions required, unsigned and multiple assertions rejected, destination and audience checked, schema validation enabled.
- Configure the IdP signing certificate(s) from metadata (fetched over TLS and verified, or exchanged out of band); support two certificates during rollover; never trust `KeyInfo`.

### 2. Validate every response
On every response the SP checks, in order, and rejects on any failure:
1. Response is well-formed, schema-valid, contains exactly one assertion, no DTD.
2. Signature valid with a pinned IdP key and an allowed algorithm; the assertion used is the one the signature covers.
3. `Issuer` is the expected IdP; `Destination` / `Recipient` is this ACS URL; `Audience` is this SP's entity ID.
4. `InResponseTo` matches a pending request (SP-initiated); `NotBefore` / `NotOnOrAfter` and `SubjectConfirmationData` times hold with small clock skew.
5. Assertion `ID` not seen before (replay cache until expiry).
6. If assertions are encrypted, decrypt with the SP key, then apply the same checks; encryption does not replace signature validation.

### 3. Identity mapping and sessions
- Key accounts on the IdP's persistent, immutable identifier together with `Issuer`; treat email as an attribute, not the key.
- Accept authorization attributes (groups, roles) only from the configured IdP, and map them through an allowlist.
- After login, issue a normal app session with secure cookie flags and sensible lifetime; honour `SessionNotOnOrAfter`; deprovision via SCIM so disabled users lose access (`kb/04-cloud-infra/saas-security.md`).
- Disable local password login once SSO is enforced, except monitored break-glass accounts.

### 4. Protect the IdP
- IdP servers, signing keys and federation admin roles are Tier 0: privileged access workstations, phishing-resistant MFA, minimal admins.
- Prefer a cloud IdP or HSM-backed keys; on AD FS, restrict who can read the token-signing key and monitor access to its DKM container.
- Rotate signing certificates on schedule and immediately after suspected IdP compromise; after Golden SAML, also review and rebuild federation trusts.
- Enforce MFA and conditional access at the IdP; the SP inherits whatever the IdP allows.

### 5. Monitoring
- Log at the SP: issuer, NameID, assertion ID, validation result and failure reason; alert on signature failures, replays and unknown issuers.
- Correlate SP or cloud sign-ins with IdP issuance logs: a federated sign-in with no matching IdP authentication event suggests a forged assertion.
- Alert on federation changes: new federated domains, new or changed signing certificates, new SP trusts, IdP admin role grants (`kb/08-defensive/soc-detection-ir.md`).

## How to verify
- With an intercepting proxy and the SAML Raider extension (Burp) against a test SP, authorized only: remove the signature; alter the NameID after signing; apply each XSW variant; replace the signing certificate with a self-signed one in `KeyInfo`; insert an XML comment in the NameID. Every case must be rejected.
- Replay a previously accepted response; send one with an expired `NotOnOrAfter`; send one issued for another SP's audience; all must fail.
- Send a response containing a DTD with an external entity; it must be rejected without any outbound request.
- Set `RelayState` to an external URL; the SP must not redirect there.
- Confirm the library version has no open advisories and strict mode is on in configuration, not just the default.
- Review IdP: list token-signing certificates and federation trusts, who can change them, and whether changes alert.

## References
- OASIS SAML 2.0 specifications (Core, Bindings, Profiles, Security and Privacy Considerations): https://docs.oasis-open.org/security/saml/v2.0/
- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- W3C XML Signature Syntax and Processing 1.1: https://www.w3.org/TR/xmldsig-core1/
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be", USENIX Security 2012: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- NIST SP 800-63C, Federation and Assertions: https://pages.nist.gov/800-63-4/sp800-63c.html
- CVE-2024-45409 (ruby-saml signature bypass): https://nvd.nist.gov/vuln/detail/CVE-2024-45409
- CVE-2025-25291 (ruby-saml parser differential): https://nvd.nist.gov/vuln/detail/CVE-2025-25291
- CVE-2017-11427 (python-saml comment truncation): https://nvd.nist.gov/vuln/detail/CVE-2017-11427
- MITRE ATT&CK T1606.002, Forge Web Credentials: SAML Tokens: https://attack.mitre.org/techniques/T1606/002/
- CISA AA21-008A, Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a
- SAML Raider (Burp extension): https://github.com/CompassSecurity/SAMLRaider
- See also `kb/05-identity-crypto/identity-access.md`, `kb/05-identity-crypto/oauth-oidc-security.md`, `kb/05-identity-crypto/active-directory-security.md`, `kb/04-cloud-infra/saas-security.md`, `kb/05-identity-crypto/pki-and-tls.md`
