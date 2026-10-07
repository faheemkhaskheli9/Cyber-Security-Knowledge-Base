# OWASP Top 10 (2021) – Web Application Risks

## What
The OWASP Top 10 is a consensus awareness list of the most critical web application security risks, built from contributed vulnerability data and a community survey. This file uses the **2021 edition**, which most standards, scanners and training still map to. It covers risk *categories*, not a complete checklist; use **OWASP ASVS** for testable requirements.

> A 2025 edition was published by OWASP (release candidate announced November 2025). Notable changes: Security Misconfiguration moves up, a **Software Supply Chain Failures** category broadens "Vulnerable and Outdated Components", SSRF is merged into Broken Access Control, and a new **Mishandling of Exceptional Conditions** category appears. Check https://owasp.org/Top10/ for the final list before mapping findings to 2025 IDs.

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

## Why it matters
- These categories account for most exploitable web findings in pentests and bug bounties; A01 was found in 94% of tested applications in the 2021 dataset.
- PCI DSS, many procurement questionnaires and SAST/DAST tools reference the Top 10 IDs, so findings are usually reported against them.
- One flaw is often enough: a single SQLi or SSRF can mean full database dump or cloud credential theft (Capital One 2019: SSRF to instance metadata).

## Attacks
*Examples are for authorized testing only; each is paired with its fix below.*

### A01 Broken Access Control
- IDOR: `GET /api/invoices/1043` returns another user's invoice when the ID is changed.
- Forced browsing to `/admin`, missing checks on `PUT`/`DELETE`, privilege escalation via a `role` field, CORS misconfig, JWT tampering.
- **Path traversal**: `GET /download?file=../../etc/passwd` (also encoded: `%2e%2e%2f`, `..%5c`).

### A02 Cryptographic Failures
- HTTP or TLS 1.0/1.1, missing HSTS (downgrade/strip), MD5/SHA-1/unsalted password hashes cracked offline, ECB mode, hardcoded keys, predictable tokens from `Math.random()`.

### A03 Injection
- **SQLi**: `' OR '1'='1` in a concatenated query; blind/time-based variants; second-order SQLi via stored data.
- **NoSQLi**: `{"user":"admin","pass":{"$ne":null}}` to MongoDB.
- **OS command injection**: `; id` or `$(id)` appended to a filename passed to a shell.
- **XSS**: reflected, stored, DOM (see `kb/03-application/browser-client-side.md`).
- LDAP, XPath, template injection (SSTI: `{{7*7}}`), header/CRLF injection, log injection.

### A04 Insecure Design
- Missing rate limits on OTP or password reset, business-logic flaws (negative quantities, coupon reuse), race conditions on balance updates, "security questions" for recovery.

### A05 Security Misconfiguration
- Debug pages/stack traces in prod, default credentials, directory listing, exposed `.git/` or `.env`, verbose errors, unneeded HTTP methods.
- **XXE**: XML parser with external entities enabled reads local files or performs SSRF:
  `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`

### A06 Vulnerable & Outdated Components
- Exploitation of known CVEs (Log4Shell CVE-2021-44228, Spring4Shell, Struts CVE-2017-5638 in Equifax), abandoned packages, typosquats.

### A07 Identification & Authentication Failures
- Credential stuffing, brute force, session fixation, session IDs in URLs, no invalidation on logout, weak reset flows.

### A08 Software & Data Integrity Failures
- **Insecure deserialization**: Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter` on attacker data leading to RCE via gadget chains.
- Unsigned auto-updates, CDN scripts without SRI, poisoned CI/CD (see `kb/06-secure-sdlc/cicd-security.md`).

### A09 Logging & Monitoring Failures
- Attacks go unnoticed because logins, authZ failures and high-value transactions are not logged or alerted; logs that contain secrets become a breach source.

### A10 SSRF
- `POST /fetch {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` steals cloud role credentials.
- Bypasses: decimal/octal IPs (`2852039166`), IPv6 (`[::ffff:169.254.169.254]`), DNS rebinding, redirects to internal hosts, `file://` / `gopher://` schemes.

## Defenses

### Key vulnerability classes in detail
- **SQLi**: never concatenate; use prepared statements. **XSS**: encode on output, use frameworks' auto-escaping, avoid `innerHTML`/`dangerouslySetInnerHTML`, set CSP. **CSRF**: SameSite cookies + anti-CSRF tokens. **XXE**: disable external entities. **Path traversal**: canonicalize + allowlist. **Open redirect**: allowlist targets. **Deserialization**: never deserialize untrusted data with native formats (pickle, Java serialization). **File upload**: validate type/size, store outside webroot, rename, scan. **Command injection**: avoid shell, use arg arrays. **Race conditions/TOCTOU**: atomic ops, locking. **Clickjacking**: `frame-ancestors`/`X-Frame-Options`.

### A01: object-level authZ and path traversal
```python
# Vulnerable: trusts the ID
inv = db.get(Invoice, invoice_id)
# Fixed: scope every query to the caller
inv = db.query(Invoice).filter_by(id=invoice_id, owner_id=current_user.id).one_or_none()
if inv is None: abort(404)
```
```python
# Path traversal fix: canonicalize, then confirm it stays under the base dir
base = Path("/srv/files").resolve()
target = (base / user_name).resolve()
if not target.is_relative_to(base): abort(400)   # Python 3.9+
```
Better still: map an opaque ID to a server-side path and never accept filenames.

### A02: crypto and passwords
- TLS 1.2+ only (prefer 1.3), HSTS, AEAD ciphers (AES-GCM, ChaCha20-Poly1305), keys in KMS/HSM, CSPRNG (`secrets`, `crypto.randomBytes`).
- Password hashing with Argon2id (OWASP minimum: m=19 MiB, t=2, p=1), or bcrypt cost ≥10 / scrypt:
```python
from argon2 import PasswordHasher          # argon2-cffi
ph = PasswordHasher()                      # Argon2id by default
stored = ph.hash(password)
ph.verify(stored, attempt)                 # raises on mismatch
if ph.check_needs_rehash(stored): stored = ph.hash(attempt)
```
- See `kb/05-identity-crypto/cryptography.md`, `kb/05-identity-crypto/pki-and-tls.md`.

### A03: injection
```python
# Vulnerable
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
# Fixed: parameterized (driver handles quoting)
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
```
- Identifiers (column/table names, `ORDER BY`) cannot be parameterized: map from an allowlist.
```python
# Command injection: vulnerable
os.system(f"convert {filename} out.png")
# Fixed: no shell, argument array, "--" ends option parsing, validated input
subprocess.run(["convert", "--", filename, "out.png"], check=True, shell=False)
```
- Prefer a library over shelling out at all. NoSQL: reject objects where strings are expected (schema validation). Templates: never render user input as a template.

### A04: insecure design
- Threat model each feature (`kb/01-foundations/threat-modeling.md`), write abuse cases next to user stories, rate limit and add idempotency keys for money flows, use DB transactions/row locks against races.

### A05: misconfiguration and XXE
- Hardened, repeatable config (IaC), `DEBUG=False`, generic error pages, remove samples/default accounts, disable directory listing, deny unused methods.
- XXE: disable DTDs.
```python
import defusedxml.ElementTree as ET     # Python: use defusedxml
tree = ET.fromstring(xml_bytes)
```
```java
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setXIncludeAware(false); f.setExpandEntityReferences(false);
```
- Prefer JSON where XML is not required.

### Security headers
`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, cookies `Secure; HttpOnly; SameSite`. Values: `kb/03-application/browser-client-side.md`.

### A06: components
- Lockfiles, SCA in CI (Dependabot, `npm audit`, `pip-audit`, OSV-Scanner, Trivy), SBOM per build, remove unused deps, track EOL runtimes. See `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/09-governance/vulnerability-management.md`.

### A07: authentication
- MFA (phishing-resistant/passkeys for admins), rate limiting and progressive delays, breached-password check (k-anonymity API), no composition rules or forced rotation (NIST SP 800-63B), regenerate session ID on login, server-side logout, idle and absolute timeouts. See `kb/05-identity-crypto/identity-access.md`.

### A08: integrity and deserialization
```python
# Vulnerable: RCE if data is attacker-controlled
obj = pickle.loads(request.data)
# Fixed: data-only format + schema validation
obj = MyModel.model_validate_json(request.data)   # pydantic
```
- Java: avoid native serialization; if unavoidable, set an `ObjectInputFilter` allowlist (JEP 290). Jackson: no default typing. YAML: `yaml.safe_load`.
- Sign artifacts and updates (cosign), SRI on CDN scripts, HMAC-sign any serialized state sent to clients.

### A09: logging and monitoring
- Log authN success/failure, authZ denials, input validation failures, admin actions, with user, source IP, timestamp and request ID; structured JSON; ship to a SIEM with alerts; redact secrets/PII; protect log integrity. See `kb/08-defensive/soc-detection-ir.md`.

### A10: SSRF
```python
ALLOWED_HOSTS = {"api.partner.example", "images.example-cdn.com"}
u = urlparse(url)
if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS: abort(400)
# Reject private/link-local/loopback targets
ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved: abort(400)
resp = session.get(url, allow_redirects=False, timeout=5)
# The HTTP client re-resolves DNS: pin the checked IP (custom adapter) or route via an
# egress proxy that enforces the same rules, or DNS rebinding bypasses this check.
```
- Also: egress proxy/firewall that denies internal ranges, IMDSv2 with hop limit 1 (`kb/04-cloud-infra/cloud-security.md`), disable unused URL schemes, don't return raw responses to the user.

## How to verify
| Category | Check |
|---|---|
| A01 | Two test accounts; replay requests with swapped IDs/tokens (Burp Autorize/AuthMatrix); try `../` payloads on file params |
| A02 | `testssl.sh https://site`; grep for `md5(`, `sha1(`, `Math.random`; inspect password hash format in DB |
| A03 | Semgrep/CodeQL taint rules; `grep -rnE "execute\(f\"|\+ *request\.|shell=True|os\.system"`; sqlmap only against authorized targets |
| A04 | Review threat model and abuse cases; test rate limits on login/OTP/reset |
| A05 | `curl -sI https://site`; check `/.git/HEAD`, `/.env`, error pages; CIS benchmark for servers; XXE test with a benign entity |
| A06 | `osv-scanner -r .`, `trivy fs .`, `npm audit`, `pip-audit` |
| A07 | Brute-force and credential-stuffing resistance, session rotation on login, logout invalidation |
| A08 | Grep for `pickle.loads`, `ObjectInputStream`, `unserialize(`, `yaml.load(`; verify signatures (`cosign verify`) |
| A09 | Trigger failed logins/authZ denials and confirm they reach the SIEM and alert |
| A10 | Point URL params at a controlled callback host and at `169.254.169.254` (authorized); confirm blocked |

General: OWASP ZAP/Burp baseline scan, Semgrep/CodeQL, `securityheaders.com`, ASVS checklist. Run `scripts/audit.sh <path>` for repo-level checks.

## References
- OWASP Top 10:2021: https://owasp.org/Top10/
- OWASP Cheat Sheet Series (SQL Injection Prevention, OS Command Injection Defense, XXE Prevention, SSRF Prevention, Password Storage, Deserialization, File Upload): https://cheatsheetseries.owasp.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-63B (Digital Identity Guidelines, authentication)
- MITRE CWE Top 25: https://cwe.mitre.org/top25/
- See also `kb/03-application/api-security.md`, `kb/03-application/browser-client-side.md`, `kb/07-offensive/pentest-methodology.md`
