# Application Security Logging and Monitoring

## What
Security logging is the set of events an application records so that attacks can be detected, investigated and proven: authentication, authorization decisions, input validation failures, privilege changes and access to sensitive data. Monitoring turns those logs into alerts. This is OWASP Top 10 A09:2025 (Security Logging and Alerting Failures, "Monitoring" in 2021) from the developer's side; the SOC side is in `kb/08-defensive/soc-detection-ir.md`.

## Why it matters
- Without the right events, an incident cannot be scoped: you cannot say which accounts or records an attacker touched, so you notify everyone or no one.
- Breaches are often found by a third party first; application events such as many failed logins or many 403s are early signals that infrastructure logs do not show.
- Logs are also an attack surface: they leak secrets and personal data when they record too much, and they mislead investigators when attackers can forge entries.

## Attacks
- **Log injection / forging**: user input containing newlines (`%0d%0a`) or fake JSON fields writes fake entries, hiding activity or framing another user.
- **Log4Shell-style lookups**: a logging library that interprets input (`${jndi:ldap://...}`) turns a log call into RCE (CVE-2021-44228).
- **Secrets and PII in logs**: tokens, passwords, session IDs, card numbers in request dumps or debug logs become a breach of the log store.
- **Evasion and tampering**: attackers with host access delete or edit local logs, or trigger log floods so that storage rotates away evidence.
- **Blind spots**: authZ failures, admin actions and data exports not logged, so abuse by a valid user leaves no trace.

## Defenses

### Log the right events
| Event | Fields |
|---|---|
| Login success/failure, MFA challenge, lockout, password reset | user id, source IP, user agent, result, reason |
| Authorization failure (403), access to another tenant's or user's object | user, resource id, action |
| Privilege and role changes, API key creation, admin actions | actor, target, old/new value |
| Input validation failures that look hostile, rate-limit triggers | endpoint, rule, client |
| Bulk reads, exports, downloads of sensitive data | actor, record count, filter |
| Security config changes (MFA disabled, SSO settings) | actor, setting |

Use structured logs (JSON) with a consistent schema, UTC timestamps, a request/trace ID and the authenticated principal on every entry.

### Log safely
- Never log secrets, full tokens, passwords, session IDs or full card numbers; redact at the logger (allowlist fields), not by convention.
- Encode or strip CR/LF and control characters from user input; structured logging libraries escape values for you.
- Keep logging libraries patched and disable message lookups/interpolation of user data.
- Treat personal data in logs under your privacy rules: minimise, pseudonymise, set retention (`kb/09-governance/grc-compliance-privacy.md`).

### Protect and use the logs
- Ship logs off the host in near real time to a central store the application cannot modify or delete (append-only or WORM bucket, separate account).
- Alert on: failed-login spikes per account and per IP, logins from new countries after success elsewhere, many 403/404s from one principal, admin role grants, MFA disablement, unusual export volume.
- Monitor the pipeline itself: alert when a source stops sending.

```python
import logging, json, time

class JsonFormatter(logging.Formatter):
    converter = time.gmtime  # UTC timestamps
    SAFE = {"event", "user_id", "ip", "result", "resource", "trace_id"}
    def format(self, record):
        data = {k: v for k, v in getattr(record, "fields", {}).items() if k in self.SAFE}
        data.update(ts=self.formatTime(record), level=record.levelname, msg=record.getMessage())
        return json.dumps(data)  # json.dumps escapes CR/LF, so input cannot forge new lines

log = logging.getLogger("security")
h = logging.StreamHandler(); h.setFormatter(JsonFormatter()); log.addHandler(h)
log.warning("login failed", extra={"fields": {"event": "auth.login", "user_id": "u123",
            "ip": "203.0.113.7", "result": "fail", "password": "<dropped>"}})
```

## How to verify
- Walk through a test script (failed logins, a forbidden object access, a role grant, a data export) and confirm each produces one structured entry with actor, target and trace ID in the central store.
- Send `test%0d%0aFAKE ENTRY` and `${jndi:ldap://example.invalid/a}` in a logged field; the store must show one escaped entry and no outbound lookup.
- Grep a day of logs for `password`, `Authorization: Bearer`, `token=`, card-number patterns; findings are bugs.
- Try to delete or edit a shipped log entry with the application's credentials: it must fail.
- Trigger each alert rule in staging and confirm it reaches the on-call channel; stop a log source and confirm the silence alert fires.

## References
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Logging Vocabulary Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
- OWASP Top 10:2025 A09 Security Logging and Alerting Failures: https://owasp.org/Top10/2025/
- OWASP ASVS 5.0 (V16 Security Logging and Error Handling; V7 in 4.0.3): https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-92, Guide to Computer Security Log Management: https://csrc.nist.gov/pubs/sp/800/92/final
- See also `kb/03-application/owasp-top10.md`, `kb/03-application/error-handling-and-fail-safe.md`, `kb/08-defensive/soc-detection-ir.md`
