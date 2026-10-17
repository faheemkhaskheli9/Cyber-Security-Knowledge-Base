# OWASP Top 10 (2025) – Web Application Risks

## What
The OWASP Top 10 is a consensus awareness list of the most critical web application security risks, built from contributed testing data and a community survey. This file uses the **2025 edition** (the 8th installment). It covers risk *categories*, not a complete checklist; use **OWASP ASVS 5.0** for testable requirements.

| 2025 | Risk | 2021 equivalent | Defense essentials |
|---|------|---|--------------------|
| A01 | Broken Access Control (now includes SSRF) | A01 + A10 SSRF | Deny by default, server-side authZ on every request, object-level checks (IDOR), allowlist outbound destinations |
| A02 | Security Misconfiguration | A05 | Hardened defaults, no debug in prod, security headers, minimal features, XXE off |
| A03 | Software Supply Chain Failures | A06 Vulnerable & Outdated Components (broadened) | SBOM, SCA, pinned and reviewed dependencies, hardened CI/CD, staged rollouts |
| A04 | Cryptographic Failures | A02 | TLS, strong algorithms, no plaintext secrets/PII, key management, passwords hashed with Argon2id or bcrypt |
| A05 | Injection (SQL, NoSQL, OS, LDAP, XSS) | A03 | Parameterized queries, ORM, input validation, contextual output encoding, CSP |
| A06 | Insecure Design | A04 | Threat model, secure patterns, abuse cases, rate limits |
| A07 | Authentication Failures | A07 Identification & Authentication Failures | MFA, rate limiting, secure session management, no default creds, breached-password checks |
| A08 | Software or Data Integrity Failures | A08 | Signed artifacts and updates, safe deserialization, SRI |
| A09 | Security Logging & Alerting Failures | A09 Logging & Monitoring Failures | Log auth/authZ/input failures, tamper-resistant storage, alerts that reach a responder |
| A10 | Mishandling of Exceptional Conditions | new | Fail closed, catch errors where they occur, global handler, generic error messages, roll back partial transactions |

Many standards, scanners and older reports still use 2021 IDs; quote the edition with the ID (for example `A05:2025-Injection`) and map with the column above.

## Why it matters
- These categories account for most exploitable web findings in pentests and bug bounties. In the 2025 data, Broken Access Control is #1 again: on average 3.73% of tested applications had one or more of its 40 CWEs.
- Training, procurement questionnaires and SAST/DAST tools report findings against Top 10 categories, so findings are usually triaged with them.
- One flaw is often enough: a single SQLi or SSRF can mean a full database dump or cloud credential theft (Capital One 2019: SSRF to instance metadata).
- Supply chain failures (A03) were voted the top concern in the 2025 community survey and have the highest average exploit and impact scores, even though few CVEs map to them.

## Attacks
*Examples are for authorized testing only; each is paired with its fix below.*

### A01 Broken Access Control (incl. SSRF)
- IDOR: `GET /api/invoices/1043` returns another user's invoice when the ID is changed.
- Forced browsing to `/admin`, missing checks on `PUT`/`DELETE`, privilege escalation via a `role` field, CORS misconfig, JWT tampering.
- **Path traversal**: `GET /download?file=../../etc/passwd` (also encoded: `%2e%2e%2f`, `..%5c`).
- **SSRF**: `POST /fetch {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` steals cloud role credentials. Bypasses: decimal/octal IPs (`2852039166`), IPv6 (`[::ffff:169.254.169.254]`), DNS rebinding, redirects to internal hosts, `file://` / `gopher://` schemes.

### A02 Security Misconfiguration
- Debug pages/stack traces in prod, default credentials, directory listing, exposed `.git/` or `.env`, verbose errors, unneeded HTTP methods, permissive cloud storage.
- **XXE**: XML parser with external entities enabled reads local files or performs SSRF:
  `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`

### A03 Software Supply Chain Failures
- Exploitation of known CVEs in components (Log4Shell CVE-2021-44228, Spring4Shell, Struts CVE-2017-5638 in Equifax), abandoned packages.
- Malicious or hijacked packages and maintainers: typosquats, dependency confusion, the xz-utils backdoor (CVE-2024-3094), self-propagating npm worms.
- Compromised build or developer tooling: mutable CI Action tags re-pointed to malicious code, poisoned IDE extensions, a CI/CD pipeline weaker than the systems it deploys. See `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`.

### A04 Cryptographic Failures
- HTTP or TLS 1.0/1.1, missing HSTS (downgrade/strip), MD5/SHA-1/unsalted password hashes cracked offline, ECB mode, hardcoded keys, predictable tokens from `Math.random()`.

### A05 Injection
- **SQLi**: `' OR '1'='1` in a concatenated query; blind/time-based variants; second-order SQLi via stored data.
- **NoSQLi**: `{"user":"admin","pass":{"$ne":null}}` to MongoDB.
- **OS command injection**: `; id` or `$(id)` appended to a filename passed to a shell.
- **XSS**: reflected, stored, DOM (see `kb/03-application/browser-client-side.md`).
- LDAP, XPath, template injection (SSTI: `{{7*7}}`), header/CRLF injection, log injection.

### A06 Insecure Design
- Missing rate limits on OTP or password reset, business-logic flaws (negative quantities, coupon reuse), race conditions on balance updates, "security questions" for recovery.

### A07 Authentication Failures
- Credential stuffing, brute force, session fixation, session IDs in URLs, no invalidation on logout, weak reset flows.

### A08 Software or Data Integrity Failures
- **Insecure deserialization**: Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter` on attacker data leading to RCE via gadget chains.
- Unsigned auto-updates, CDN scripts without SRI, client-side state trusted without a signature, poisoned CI/CD artifacts (see `kb/06-secure-sdlc/cicd-security.md`).

### A09 Security Logging & Alerting Failures
- Attacks go unnoticed because logins, authZ failures and high-value transactions are not logged, or are logged but nobody is alerted; logs that contain secrets become a breach source.

### A10 Mishandling of Exceptional Conditions
- **Failing open**: an authZ or license check that throws (timeout, null, parse error) and the `catch` lets the request through.
- **Error messages as reconnaissance**: forced database errors return stack traces, SQL fragments or file paths that refine the next attack.
- **Partial transactions**: interrupting a multi-step operation (debit, credit, log) leaves state inconsistent, or a retry repeats the credit.
- **Resource exhaustion**: exception paths that never release file handles, locks or connections, until the service stops (DoS).
- Unchecked return values, swallowed exceptions (`except: pass`), missing or extra parameters that drive code into an untested branch.
- Detail: `kb/03-application/error-handling-and-fail-safe.md`.

## Defenses

### Key vulnerability classes in detail
- **SQLi**: never concatenate; use prepared statements. **XSS**: encode on output, use frameworks' auto-escaping, avoid `innerHTML`/`dangerouslySetInnerHTML`, set CSP. **CSRF**: SameSite cookies + anti-CSRF tokens. **XXE**: disable external entities. **Path traversal**: canonicalize + allowlist. **Open redirect**: allowlist targets. **Deserialization**: never deserialize untrusted data with native formats (pickle, Java serialization). **File upload**: validate type/size, store outside webroot, rename, scan. **Command injection**: avoid shell, use arg arrays. **Race conditions/TOCTOU**: atomic ops, locking. **Clickjacking**: `frame-ancestors`/`X-Frame-Options`.

### A01: object-level authZ, path traversal and SSRF
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
```python
# SSRF: allowlist destinations, then reject private/link-local/loopback targets
ALLOWED_HOSTS = {"api.partner.example", "images.example-cdn.com"}
u = urlparse(url)
if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS: abort(400)
ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved: abort(400)
resp = session.get(url, allow_redirects=False, timeout=5)
# The HTTP client re-resolves DNS: pin the checked IP (custom adapter) or route via an
# egress proxy that enforces the same rules, or DNS rebinding bypasses this check.
```
- SSRF also: egress proxy/firewall that denies internal ranges, IMDSv2 with hop limit 1 (`kb/04-cloud-infra/cloud-security.md`), disable unused URL schemes, don't return raw responses to the user.

### A02: misconfiguration and XXE
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

### A03: software supply chain
- Lockfiles, SCA in CI (Dependabot, `npm audit`, `pip-audit`, OSV-Scanner, Trivy), SBOM per build, remove unused deps, track EOL runtimes.
- Obtain components from official sources, prefer signed packages with provenance, pin CI Actions to commit SHAs, wait a few days before adopting new releases, and roll out updates in stages (canary) so one compromised vendor release does not reach every system at once.
- Separation of duties: nobody can take a change to production alone; MFA and least privilege on repositories, registries and CI. See `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/06-secure-sdlc/cicd-security.md`, `kb/09-governance/vulnerability-management.md`.

### A04: crypto and passwords
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

### A05: injection
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

### A06: insecure design
- Threat model each feature (`kb/01-foundations/threat-modeling.md`), write abuse cases next to user stories, rate limit and add idempotency keys for money flows, use DB transactions/row locks against races.

### A07: authentication
- MFA (phishing-resistant/passkeys for admins), rate limiting and progressive delays, breached-password check (k-anonymity API), no composition rules or forced rotation (NIST SP 800-63B-4), regenerate session ID on login, server-side logout, idle and absolute timeouts. See `kb/05-identity-crypto/identity-access.md`.

### A08: integrity and deserialization
```python
# Vulnerable: RCE if data is attacker-controlled
obj = pickle.loads(request.data)
# Fixed: data-only format + schema validation
obj = MyModel.model_validate_json(request.data)   # pydantic
```
- Java: avoid native serialization; if unavoidable, set an `ObjectInputFilter` allowlist (JEP 290). Jackson: no default typing. YAML: `yaml.safe_load`.
- Sign artifacts and updates (cosign), SRI on CDN scripts, HMAC-sign any serialized state sent to clients.

### A09: logging and alerting
- Log authN success/failure, authZ denials, input validation failures, admin actions, with user, source IP, timestamp and request ID; structured JSON; ship to a SIEM with alerts that reach an on-call responder; redact secrets/PII; protect log integrity. See `kb/06-secure-sdlc/security-logging-and-monitoring.md` and `kb/08-defensive/soc-detection-ir.md`.

### A10: exceptional conditions
```python
# Vulnerable: any error in the policy lookup grants access (fail open)
try:
    allowed = policy.check(user, action)
except Exception:
    allowed = True
# Fixed: deny on error, log it, and let a global handler return a generic 5xx
try:
    allowed = policy.check(user, action)
except PolicyError:
    log.exception("authz.check_failed", extra={"fields": {"user_id": user.id}})
    allowed = False
```
- Handle errors where they occur, plus one global handler; return generic messages with a correlation ID; release resources in `finally`/`with`; wrap multi-step changes in a transaction that rolls back completely; cap sizes, rates and timeouts so nothing is unbounded.

## How to verify
| Category | Check |
|---|---|
| A01 | Two test accounts; replay requests with swapped IDs/tokens (Burp Autorize/AuthMatrix); try `../` payloads on file params; point URL params at a controlled callback host and at `169.254.169.254` (authorized) and confirm they are blocked |
| A02 | `curl -sI https://site`; check `/.git/HEAD`, `/.env`, error pages; CIS benchmark for servers; XXE test with a benign entity |
| A03 | `osv-scanner scan source -r .`, `trivy fs .`, `npm audit`, `pip-audit`; SBOM exists per release; `zizmor .github/workflows/` and OpenSSF Scorecard for the pipeline |
| A04 | `testssl.sh https://site`; grep for `md5(`, `sha1(`, `Math.random`; inspect password hash format in DB |
| A05 | Semgrep/CodeQL taint rules; `grep -rnE "execute\(f\"|\+ *request\.|shell=True|os\.system"`; sqlmap only against authorized targets |
| A06 | Review threat model and abuse cases; test rate limits on login/OTP/reset |
| A07 | Brute-force and credential-stuffing resistance, session rotation on login, logout invalidation |
| A08 | Grep for `pickle.loads`, `ObjectInputStream`, `unserialize(`, `yaml.load(`; verify signatures (`cosign verify`) |
| A09 | Trigger failed logins/authZ denials and confirm they reach the SIEM and an alert reaches on-call |
| A10 | Fault injection: make dependencies time out or return errors and confirm requests are denied, not allowed; send missing, extra and malformed parameters and confirm generic errors with no stack trace; grep for `except: pass`, `catch (Exception e) {}` |

General: OWASP ZAP/Burp baseline scan, Semgrep/CodeQL, `securityheaders.com`, ASVS checklist. Run `scripts/audit.sh <path>` for repo-level checks.

## References
- OWASP Top 10:2025: https://owasp.org/Top10/2025/ (source: https://github.com/OWASP/Top10/tree/master/2025)
- OWASP Top 10 project page (older editions, incl. 2021 for older reports and tool mappings): https://owasp.org/www-project-top-ten/
- OWASP Cheat Sheet Series (SQL Injection Prevention, OS Command Injection Defense, XXE Prevention, SSRF Prevention, Password Storage, Deserialization, File Upload, Error Handling): https://cheatsheetseries.owasp.org/
- OWASP ASVS 5.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-63B-4 (Digital Identity Guidelines, authentication): https://pages.nist.gov/800-63-4/
- MITRE CWE Top 25: https://cwe.mitre.org/top25/
- See also `kb/03-application/api-security.md`, `kb/03-application/browser-client-side.md`, `kb/03-application/error-handling-and-fail-safe.md`, `kb/07-offensive/pentest-methodology.md`
