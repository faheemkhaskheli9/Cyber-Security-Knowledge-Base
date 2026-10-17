# Error Handling and Fail-Safe Design

## What
How an application prevents, detects and responds to abnormal conditions: exceptions, timeouts, missing or malformed input, unavailable dependencies, exhausted resources and partial failures. Secure handling means the system **fails closed** (denies, rolls back, stops) rather than open, tells users only what they need, and records enough for responders. OWASP added this as **A10:2025 Mishandling of Exceptional Conditions** (24 CWEs, including CWE-209 sensitive error messages, CWE-252 unchecked return value, CWE-390/391 errors detected without action, CWE-460 improper cleanup on exception and CWE-636 failing open). The logging side is in `kb/06-secure-sdlc/security-logging-and-monitoring.md`.

## Why it matters
- A security check is only as strong as its error path. An authorization, signature or license check that returns "allow" when it throws is a bypass that any attacker who can cause the error can trigger.
- Detailed errors (stack traces, SQL text, file paths, library versions) turn a probe into reconnaissance for injection or exploit selection.
- Payments, transfers and inventory changes span several steps. A failure halfway through without a full rollback leaves money or stock in the wrong place, and retries can apply a credit twice.
- Error paths are the least tested code. Leaked connections, locks and file handles on exceptions turn a burst of bad requests into a denial of service.

## Attacks
*For authorized testing only; each item is paired with its defense below.*

| Attack | How it works | Defense |
|---|---|---|
| Fail-open authorization | Force the policy service, IdP, LDAP or token introspection to time out or error; the code's `catch` grants access or skips the check | Default-deny on any error; treat "unknown" as "no" |
| Signature or certificate check bypass | Malformed input makes the verifier throw; the caller ignores the exception or the return value and continues | Check every return value; verification functions return a verified object, not a boolean |
| Error-message reconnaissance | Send `'`, huge numbers, wrong types or missing fields to trigger stack traces with SQL, paths or versions (CWE-209) | Generic error responses with a correlation ID; details only in server logs |
| Partial-transaction abuse | Interrupt a multi-step flow (drop the connection after the debit, race two requests) so state is inconsistent or a step repeats | One database transaction, or a saga with compensations; idempotency keys |
| Resource exhaustion via errors | Each failing upload or request leaks a file handle, lock, thread or connection until the pool is empty | `with`/`try-finally`/`using` for every resource; timeouts and pool limits |
| Unexpected parameters | Missing, duplicated or extra parameters (CWE-234/235) drive code into an untested branch, a null dereference or a default that is too permissive | Strict schema validation that rejects unknown and missing fields |
| Swallowed exceptions | `except: pass` or an empty `catch` hides an attack in progress and leaves state undefined | Catch specific exceptions only, and always log or re-raise |

## Defenses
1. **Fail closed by design.** Write security decisions so the default value is deny, and only an explicit, successful check sets allow. A dependency outage should degrade to "no access", never to "no check". Decide per feature which non-security functions may fail open (for example a recommendation widget) and record that decision.
2. **Handle errors where they occur, and once more globally.** Catch specific exceptions next to the operation that raises them and do something meaningful (retry with a limit, roll back, deny). Add one global handler per process or framework that logs the error and returns a generic response, so nothing escapes as a raw stack trace.
3. **Generic messages out, details in logs.** Return a stable error code, a plain message and a correlation ID. Keep stack traces, SQL and internal identifiers in the server log, tied to the same ID. Turn off framework debug modes in production (`DEBUG=False`, no Werkzeug/Django debug pages, `customErrors` on in ASP.NET).
4. **Roll back completely.** Put multi-step state changes in one database transaction. Across services, use a saga with compensating actions and an idempotency key per operation so retries do not apply twice. Do not try to "repair" a half-finished transaction in place.
5. **Release resources on every path.** Use context managers (`with`), `try/finally`, `using` or `defer`. Set timeouts on every network call, bound pools and queues, and cap request sizes, upload sizes, recursion depth and loop iterations. Nothing should be unlimited.
6. **Validate input strictly at the boundary.** Reject missing, extra and wrongly typed fields (`additionalProperties: false`, pydantic `extra="forbid"`) before business logic runs. Handle null and empty values explicitly.
7. **Check return values and status codes.** Treat unexpected status codes or return values from libraries and APIs as failures, not as success (CWE-252, CWE-394).
8. **Alert on error patterns.** Repeated identical errors from one client, spikes in 5xx or validation failures, and circuit breakers opening are attack signals. Aggregate repeats into counts instead of flooding the log, and alert on rates (`kb/08-defensive/soc-detection-ir.md`).
9. **Use one approach everywhere.** A shared error-handling library or middleware is easier to review than per-handler code. Add error-handling requirements (ASVS 5.0 V16 Security Logging and Error Handling) to the definition of done and to code review (`kb/06-secure-sdlc/secure-code-review.md`).

### Example (Python, standard library only)
```python
import logging, sqlite3, uuid

log = logging.getLogger("app")

class PolicyError(Exception):
    pass

def is_allowed(check, user, action) -> bool:
    """Fail closed: a failed check denies; unexpected errors reach the global handler (also no access)."""
    try:
        return check(user, action) is True          # only an explicit True allows
    except PolicyError:
        log.warning("authz check failed; denying", exc_info=True)
        return False

def transfer(db, src, dst, amount):
    """All-or-nothing: the context manager commits on success and rolls back on any exception."""
    if amount <= 0:
        raise ValueError("amount must be positive")
    with db:
        cur = db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
                         (amount, src, amount))
        if cur.rowcount != 1:                         # check the result, do not assume success
            raise ValueError("insufficient funds or unknown account")
        cur = db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, dst))
        if cur.rowcount != 1:
            raise ValueError("unknown destination")   # rolls back the debit above

def handle(request_fn):
    """Global handler: generic message to the client, details in the log under one ID."""
    try:
        return 200, request_fn()
    except Exception:
        ref = uuid.uuid4().hex[:12]
        log.exception("unhandled error ref=%s", ref)
        return 500, {"error": "internal error", "ref": ref}

def broken_policy(user, action):
    raise PolicyError("policy service timeout")

assert is_allowed(broken_policy, "alice", "delete") is False

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, balance INTEGER NOT NULL)")
db.executemany("INSERT INTO accounts VALUES (?, ?)", [("a", 100), ("b", 0)])
db.commit()
status, body = handle(lambda: transfer(db, "a", "missing", 50))
assert status == 500 and "Traceback" not in str(body)
assert db.execute("SELECT balance FROM accounts WHERE id = 'a'").fetchone()[0] == 100  # debit rolled back
```

## How to verify
- **Fault injection**: in staging, make each security dependency (policy engine, IdP, token introspection, database) time out, refuse connections and return garbage. Every protected request must be denied, with a log entry. Tools: Toxiproxy, service-mesh fault injection, or test doubles in integration tests.
- **Error disclosure**: send a single quote, oversized values, wrong types, and missing and duplicated parameters to every endpoint (authorized targets, OWASP WSTG "Testing for Improper Error Handling"). Responses must be generic with no stack trace, SQL, path or version.
- **Rollback tests**: unit-test that a failure at each step of a multi-step operation leaves state exactly as before, and that replaying a request with the same idempotency key changes nothing.
- **Resource leaks**: run a load test with a high rate of failing requests and watch open file descriptors, connection pool use and memory; they must stay flat.
- **Static checks**: Semgrep/CodeQL rules for empty catch blocks, `except: pass`, broad `except Exception` around security checks, and ignored return values; grep for `DEBUG = True` and framework debug flags in production config.
- **Alerting**: trigger a burst of validation errors from one client in staging and confirm the alert reaches on-call.

## References
- OWASP Top 10:2025 A10 Mishandling of Exceptional Conditions: https://owasp.org/Top10/2025/
- OWASP Error Handling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- OWASP ASVS 5.0, V16 Security Logging and Error Handling: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- OWASP WSTG, Testing for Improper Error Handling: https://owasp.org/www-project-web-security-testing-guide/
- MITRE CWE-636 Not Failing Securely ('Failing Open'): https://cwe.mitre.org/data/definitions/636.html · CWE-209: https://cwe.mitre.org/data/definitions/209.html
- See also `kb/03-application/owasp-top10.md`, `kb/06-secure-sdlc/security-logging-and-monitoring.md`, `kb/01-foundations/threat-modeling.md`
