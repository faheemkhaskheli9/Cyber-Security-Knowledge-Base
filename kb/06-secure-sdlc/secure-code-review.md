# Secure Code Review

## What
Secure code review is manual, risk-driven reading of source code (often with SAST support) to find security flaws before they ship. It complements, not replaces, automated scanning: tools find known sink patterns, while humans find missing authZ checks, logic flaws and broken trust assumptions.

Where it sits in the lifecycle and which gates surround it: `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`. Vulnerability classes and their fixes in depth: `kb/03-application/owasp-top10.md`. This file covers **how to review** and **what to grep for per language**.

### Review process (risk-based)
1. **Scope by risk**: start with code that crosses a trust boundary or guards an asset. Use the threat model (`kb/01-foundations/threat-modeling.md`) to rank components.
2. **Map trust boundaries**: HTTP handlers, message consumers, CLI args, file/archive parsers, IPC, webhooks, deserializers, third-party API responses, environment and config.
3. **Review the focus areas** in this order:
   - **AuthN/AuthZ**: every route has an authN decorator/middleware; every object access is scoped to the caller (IDOR); deny by default; admin paths separated.
   - **Input handling**: validated at the boundary (type, length, range, allowlist); canonicalized before checks (paths, URLs, Unicode).
   - **Output/sink handling**: parameterized queries, no shell, contextual encoding, no dynamic code or template evaluation.
   - **Crypto**: vetted libraries, AEAD, CSPRNG for tokens, no hardcoded keys, TLS verification on (`kb/05-identity-crypto/cryptography.md`).
   - **Secrets**: none in code, tests, fixtures or logs (`kb/05-identity-crypto/secrets-management.md`).
   - **Error handling**: fail closed, no stack traces to clients, exceptions do not skip authZ or leave partial state.
   - **Logging**: security events logged with context; no passwords, tokens or PII; log-injection safe (CR/LF stripped or structured logs).
4. **Trace source → sink**: for each dangerous sink found, walk backwards to its source. Ask: is the data attacker-controlled? Is there a sanitizer/validator on *every* path? Is it the right one for this sink (HTML escaping does not protect SQL)?
5. **Trace sink ← source for new inputs**: for each new input, walk forward to every place it lands.
6. **Record findings** with file:line, source→sink path, impact, severity and a concrete fix.

### How to review a diff
- Read the PR description and threat-relevant context first: what trust boundary does it touch?
- List changed files by risk: `git diff --stat main...HEAD`, then open auth, routing, serialization, crypto, config, CI and dependency manifests first.
- Grep only the added lines for sinks: `git diff -U0 main...HEAD | grep '^+' | grep -nE '<pattern>'`.
- Look at what was **removed**: deleted checks, decorators, validation or tests are as risky as added sinks.
- Expand context beyond the hunk: a safe-looking call may receive tainted data from an unchanged caller.
- Check new dependencies, lockfile changes and workflow files (`kb/06-secure-sdlc/cicd-security.md`).
- Check tests: does the PR add a negative test (unauthorized user, malicious input) for the security-relevant change?

## Why it matters
- Many high-impact bugs are invisible to scanners: missing ownership checks, business-logic flaws, wrong trust assumptions. Broken Access Control topped the OWASP Top 10 2021 data set.
- Review at PR time is the cheapest point to fix: the author still has context, and the flaw is not yet deployed or copied elsewhere.
- NIST SSDF lists code review/analysis as practice PW.7; PCI DSS requires review of custom code before release.
- Reviews spread knowledge: a reviewer who explains *why* `yaml.load` is dangerous prevents the next ten instances.

## Attacks
Dangerous sinks and patterns to grep for. A hit is a lead, not a finding: confirm the data is attacker-controlled. Grep columns are extended regex for `grep -rnE` (`\|` in the table is a plain `|`).

### Python
| Class | Sink / pattern | Grep |
|---|---|---|
| Command injection | `subprocess.*(..., shell=True)`, `os.system`, `os.popen` | `shell=True\|os\.system\|os\.popen` |
| Insecure deserialization | `pickle.load(s)`, `shelve`, `dill`, `joblib.load` on untrusted data | `pickle\.loads?\|joblib\.load` |
| Deserialization (YAML) | `yaml.load` without `SafeLoader`, `yaml.unsafe_load` | `yaml\.(unsafe_)?load\(` |
| Code injection | `eval`, `exec`, `compile` on input | `\b(eval\|exec)\(` |
| SQL injection | f-string / `%` / `+` in `execute()`, raw ORM queries | `execute\(f["']\|execute\(.*%\|\.raw\(` |
| TLS bypass | `requests.*(verify=False)`, `ssl._create_unverified_context` | `verify=False\|_create_unverified_context` |
| SSTI | `render_template_string(user_input)`, `jinja2.Template(user_input)` | `render_template_string` |

### JavaScript / Node.js
| Class | Sink / pattern | Grep |
|---|---|---|
| Code injection | `eval`, `new Function`, `setTimeout("string")`, `vm.runInNewContext` | `\beval\(\|new Function\(\|vm\.run` |
| Command injection | `child_process.exec`/`execSync` with interpolated strings | `\bexec(Sync)?\(\|shell: *true` |
| XSS | `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, React `dangerouslySetInnerHTML`, Vue `v-html` | `innerHTML\|outerHTML\|dangerouslySetInnerHTML\|document\.write\|v-html` |
| Prototype pollution | recursive merge/`set` with user keys (`__proto__`, `constructor.prototype`), `obj[a][b] = v` | `__proto__\|merge\(\|\]\[[^]]+\] *=` |
| ReDoS | user input in `new RegExp(...)`; nested quantifiers like `(a+)+`, `(.*)*` | `new RegExp\(\|\([^)]*[+*]\)[+*]` |
| NoSQL injection | request objects passed straight into Mongo queries (`{ $ne: null }`) | `find(One)?\(req\.(body\|query)` |

### Java
| Class | Sink / pattern | Grep |
|---|---|---|
| Insecure deserialization | `ObjectInputStream.readObject`, `XMLDecoder`, Jackson default typing, XStream without allowlist | `readObject\(\|XMLDecoder\|enableDefaultTyping` |
| XXE | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory` without DTDs disabled | `(DocumentBuilder\|SAXParser\|XMLInput\|Transformer)Factory` |
| Command injection | `Runtime.getRuntime().exec(String)`, `ProcessBuilder("sh","-c", ...)` | `getRuntime\(\)\.exec\|"-c"` |
| JNDI injection | `InitialContext.lookup(userInput)`; user input logged via vulnerable Log4j 2 (Log4Shell) | `\.lookup\(\|log4j` |
| SQL injection | `Statement.execute*` with concatenation, `createQuery("..." + x)` | `createStatement\|createQuery\(".*\+` |

### Go
| Class | Sink / pattern | Grep |
|---|---|---|
| SQL injection | `fmt.Sprintf` building a query passed to `db.Query`/`Exec` | `Sprintf\(".*(SELECT\|INSERT\|UPDATE\|DELETE)` |
| TLS bypass | `tls.Config{InsecureSkipVerify: true}` | `InsecureSkipVerify` |
| XSS | `text/template` rendering HTML (no auto-escaping); `template.HTML(userInput)` | `"text/template"\|template\.HTML\(` |
| Command injection | `exec.Command("sh", "-c", ...)` | `exec\.Command\("(ba)?sh"` |

### PHP
| Class | Sink / pattern | Grep |
|---|---|---|
| Insecure deserialization | `unserialize($_GET[...])`; `phar://` paths reaching file functions | `unserialize\(\|phar://` |
| File inclusion (LFI/RFI) | `include`/`require` (`_once`) with user input | `(include\|require)(_once)? *\(? *\$` |
| Code / command injection | `eval`, `assert($str)`, `system`, `exec`, `shell_exec`, `passthru`, backticks | `\b(eval\|system\|shell_exec\|passthru)\(` |
| SQL injection | `mysqli_query` / `->query` with interpolated `$vars` | `query\(".*\$` |

### C / C++
| Class | Sink / pattern | Grep |
|---|---|---|
| Buffer overflow | `strcpy`, `strcat`, `sprintf`, `gets` (removed in C11), `scanf("%s")`, unchecked `memcpy` length | `\b(strcpy\|strcat\|sprintf\|gets)\(\|scanf\(.*%s` |
| Format string | `printf(user)`, `fprintf(f, user)`, `syslog(p, user)` with non-literal format | `\bprintf\( *[a-z_]+ *\)\|fprintf\([^,]+, *[a-z_]+ *\)` |
| Integer overflow | `malloc(n * size)` without overflow check | `malloc\([^)]*\*` |
| Command injection | `system`, `popen` with built strings | `\b(system\|popen)\(` |

### C# / .NET
| Class | Sink / pattern | Grep |
|---|---|---|
| Insecure deserialization | `BinaryFormatter` (obsolete; implementation removed in .NET 9), `NetDataContractSerializer`, `LosFormatter`, Json.NET `TypeNameHandling` other than `None` | `BinaryFormatter\|LosFormatter\|TypeNameHandling\.(All\|Auto\|Objects)` |
| SQL injection | `SqlCommand` with concatenation, `FromSqlRaw($"...")` | `FromSqlRaw\|new SqlCommand\(.*\+` |
| XSS | `Html.Raw(userInput)`, Blazor `MarkupString` | `Html\.Raw\(\|MarkupString` |

## Defenses
### Vulnerable → fixed
```python
subprocess.run(f"tar xf {name}", shell=True)            # vulnerable
subprocess.run(["tar", "xf", "--", name], check=True)    # fixed: argv, no shell
cfg = yaml.load(body)                                     # vulnerable (old PyYAML / Loader=yaml.Loader)
cfg = yaml.safe_load(body)                                # fixed
```
```javascript
el.innerHTML = comment;                                   // vulnerable: XSS
el.textContent = comment;                                 // fixed (or DOMPurify.sanitize for rich HTML)
exec(`convert ${file} out.png`);                          // vulnerable
execFile("convert", ["--", file, "out.png"]);             // fixed: no shell
```
```javascript
function merge(t, s) { for (const k in s) t[k] = s[k]; }  // vulnerable: __proto__ key
const BAD = new Set(["__proto__", "constructor", "prototype"]);
for (const k of Object.keys(s)) if (!BAD.has(k)) t[k] = s[k]; // fixed; or use Map / Object.create(null)
```
```go
db.Query(fmt.Sprintf("SELECT * FROM u WHERE id='%s'", id)) // vulnerable
db.Query("SELECT * FROM u WHERE id = $1", id)              // fixed (placeholder syntax per driver)
tls.Config{InsecureSkipVerify: true}                       // vulnerable
tls.Config{MinVersion: tls.VersionTLS12}                   // fixed: verify; add RootCAs for private CA
```
```c
char buf[64]; strcpy(buf, input); printf(input);         /* vulnerable: overflow + format string */
snprintf(buf, sizeof buf, "%s", input);                   /* fixed: bounded, truncates */
printf("%s", input);                                      /* fixed: literal format */
```
```java
Context ctx = new InitialContext(); ctx.lookup(userInput);  // vulnerable: JNDI injection
// fixed: never look up user-supplied names; map an allowlisted key to a fixed JNDI name
```
Deserialization and XXE fixes (pickle → schema-validated JSON, `ObjectInputFilter`, `defusedxml`, `disallow-doctype-decl`) are in `kb/03-application/owasp-top10.md` (A05, A08). For .NET, replace `BinaryFormatter` with `System.Text.Json` and explicit types.

### Reviewer checklist
- [ ] Every new endpoint/handler has authN and an object-level authZ check; deny by default
- [ ] All new inputs validated at the trust boundary (allowlist, type, length); paths/URLs canonicalized first
- [ ] No string-built SQL, shell commands, templates, regexes or LDAP/XPath queries from input
- [ ] No native deserialization (`pickle`, `ObjectInputStream`, `unserialize`, `BinaryFormatter`) of untrusted data
- [ ] XML parsers have DTDs/external entities disabled
- [ ] Output encoded for its context; no `innerHTML`/`dangerouslySetInnerHTML`/`Html.Raw`/`text/template` for user data
- [ ] TLS verification on; no `verify=False`/`InsecureSkipVerify`; tokens from a CSPRNG
- [ ] No secrets in code, tests, fixtures, logs or error messages
- [ ] Errors fail closed; no stack traces or internals returned to clients
- [ ] Security events logged without secrets/PII; logs not injectable
- [ ] Removed lines did not drop a check, decorator, validator or test
- [ ] New dependencies justified and pinned; CI/workflow changes reviewed by CODEOWNERS
- [ ] C/C++: bounded string functions, literal format strings, overflow-checked size arithmetic
- [ ] Negative tests added for the security-relevant behaviour

### Automating the review
- **Semgrep** (pattern + taint mode, fast, diff-aware in CI): start with registry rulesets `p/owasp-top-ten`, `p/security-audit`, `p/secrets` and language packs (`p/python`, `p/javascript`, `p/java`, `p/golang`, `p/php`, `p/csharp`). Write custom rules for in-house sinks, e.g.:
  ```yaml
  rules:
    - id: no-requests-verify-false
      languages: [python]
      severity: ERROR
      message: TLS verification disabled
      pattern: requests.$METHOD(..., verify=False, ...)
  ```
- **CodeQL** (interprocedural dataflow): enable the `security-extended` query suite via `templates/codeql.yml`. Relevant query IDs include `py/sql-injection`, `py/command-line-injection`, `js/code-injection`, `js/redos`, `java/unsafe-deserialization`, `java/xxe`, `go/disabled-certificate-check`, `cpp/tainted-format-string`.
- **Language linters**: Bandit (Python), gosec (Go), eslint-plugin-security (Node), SpotBugs + Find Security Bugs (Java), compiler warnings like `-Wall -Wformat-security` (C/C++), .NET analyzers (C#).
- Gate PRs on new High+ findings only; triage false positives with inline suppressions that carry a reason.

## How to verify
- Semgrep on the repo, or on a PR diff only:
  ```bash
  semgrep scan --config p/owasp-top-ten --config p/security-audit --error .
  semgrep scan --config auto .                           # registry rules matched to detected languages
  semgrep ci                                             # in CI: diff-aware against the base branch
  ```
- CodeQL locally:
  ```bash
  codeql database create db --language=python --source-root .
  codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls \
    --format=sarif-latest --output=codeql.sarif
  ```
- Grep one-liners (exclude vendored code; review each hit):
  ```bash
  grep -rnE 'shell=True|pickle\.loads?|yaml\.load\(|\beval\(|verify=False|execute\(f"' --include='*.py' .
  grep -rnE 'eval\(|new Function\(|child_process|innerHTML|dangerouslySetInnerHTML|__proto__|new RegExp\(' --include='*.js' --include='*.ts' --include='*.tsx' .
  grep -rnE 'ObjectInputStream|readObject\(|DocumentBuilderFactory|Runtime\.getRuntime\(\)\.exec|\.lookup\(' --include='*.java' .
  grep -rnE 'InsecureSkipVerify|"text/template"|Sprintf\(".*(SELECT|INSERT|UPDATE|DELETE)' --include='*.go' .
  grep -rnE 'unserialize\(|(include|require)(_once)?\s*\(?\s*\$|eval\(|shell_exec\(' --include='*.php' .
  grep -rnE '\b(strcpy|strcat|sprintf|gets)\(' --include='*.c' --include='*.cpp' --include='*.h' .
  grep -rnE 'BinaryFormatter|TypeNameHandling\.(All|Auto|Objects)|Html\.Raw\(' --include='*.cs' .
  ```
- Repo-level baseline: `scripts/audit.sh <path>`.
- Seed check: plant a known-bad snippet in a test branch and confirm Semgrep/CodeQL fail the PR.
- **Metrics** (track per quarter):
  - % of merged PRs touching high-risk paths that had a security-aware review
  - Findings per KLOC reviewed, by class and severity
  - Escape rate: vulns found in test/prod that were reviewable in the PR
  - Mean time to remediate review/SAST findings; open High+ count
  - SAST false-positive rate and suppression count (rising suppressions = rule tuning needed)

## References
- OWASP Code Review Guide (v2)
- OWASP Cheat Sheet Series (Deserialization, XXE Prevention, OS Command Injection Defense, Prototype Pollution Prevention): https://cheatsheetseries.owasp.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- SEI CERT Coding Standards (C, C++, Java)
- MITRE CWE Top 25: https://cwe.mitre.org/top25/
- Semgrep docs and registry: https://semgrep.dev/docs/ · CodeQL docs: https://codeql.github.com/docs/
- NIST SP 800-218 SSDF (PW.7): https://csrc.nist.gov/pubs/sp/800/218/final
- See also `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/03-application/owasp-top10.md`, `kb/03-application/browser-client-side.md`, `kb/06-secure-sdlc/cicd-security.md`
