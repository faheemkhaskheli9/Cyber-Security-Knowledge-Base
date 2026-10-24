# Business Logic Flaws and Race Conditions

## What
Flaws in what the application allows rather than in how it parses input: a request that is well formed, authenticated and free of injection, but that the business rules should have refused. Examples are skipping a checkout step, a negative quantity, reusing a one-time coupon, or redeeming a gift card twice by sending two requests at the same moment. **Race conditions** are the concurrency subset: a check and the action it guards are not atomic, so parallel requests all pass the check before any of them records its effect (TOCTOU, CWE-367). Scanners rarely find either class because the requests look normal; they need a model of the intended behavior. Related weaknesses: CWE-840 (Business Logic Errors), CWE-841 (Improper Enforcement of Behavioral Workflow), CWE-362 (Race Condition), CWE-799 (Improper Control of Interaction Frequency). OWASP API Security Top 10 2023 lists the abuse side as API6 (Unrestricted Access to Sensitive Business Flows).

## Why it matters
- **Direct financial loss**: double spending of balances, gift cards, refunds, loyalty points, referral credits or coupons; price manipulation at checkout.
- **Security control bypass**: a race on an MFA or OTP check, on a rate limit or on a "one invitation per user" rule turns a limit into a suggestion.
- **Authorization bypass by workflow**: jumping straight to the final step of a multi-step flow (password reset, KYC, approval, payment confirmation) skips the checks earlier steps enforced.
- **Invisible to tooling**: SAST, DAST and WAFs look for malformed input; a logic flaw uses valid requests, so it surfaces in pentests, bug bounty reports (`kb/07-offensive/red-team-and-bug-bounty.md`) or fraud losses.
- **Automation at scale**: scalping, inventory hoarding, account creation and card testing abuse flows that are individually legitimate (OWASP Automated Threats, OAT).

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Limit overrun race | Many parallel requests redeem the same coupon, gift card or balance; each reads "unused" before any writes "used" | Atomic conditional update or row lock; unique constraint on the redemption; idempotency key |
| Multi-endpoint / state race | Request A changes state (add item, change email) while request B acts on the old state (confirm payment, send verification link) | Bind the action to a versioned snapshot (order version, cart hash); recheck inside the same transaction |
| Race on a security check | Parallel OTP, MFA or password-reset submissions all evaluated before the attempt counter increments | Increment the counter atomically before checking the value; lock per account; single-use tokens consumed in the same statement |
| Single-packet / last-byte sync | Attacker withholds the final bytes of many requests and releases them together (HTTP/2 single-packet attack), shrinking network jitter so races open reliably | Do not rely on timing being hard to hit; fix the atomicity |
| Workflow step skipping | Calling `/checkout/confirm` without `/checkout/pay`, or the final reset step without the token check | Server-side state machine; each step checks the stored state, not a client flag or hidden field |
| Parameter tampering | Client-supplied `price`, `discount`, `role`, `isAdmin` or `total` trusted by the server | Compute prices and totals server-side from the catalog; ignore or reject client-supplied authoritative fields (mass assignment allowlist) |
| Numeric edge cases | Negative quantity or amount, zero, very large values that overflow, float rounding on currency, currency mismatch | Validate ranges and types; integer minor units or decimal types for money; one currency per transaction |
| Replay and duplicate submission | Resending a captured "refund" or "transfer" request, or double-clicking, processes it twice | Idempotency keys stored with a unique constraint; nonces; state check (already refunded) |
| Coupon and promotion stacking | Applying the same or mutually exclusive codes repeatedly, or removing items after a threshold discount applied | Recalculate all promotions at order confirmation against explicit stacking rules |
| Referral and sign-up abuse | Self-referral with throwaway accounts, email aliases (`user+1@`), or disposable domains | Normalize identities; delay credit until a real transaction; velocity limits; fraud scoring |
| Inconsistent validation | One path (mobile API, old version, bulk import, GraphQL mutation) skips a rule the web UI enforces | Enforce rules in a shared domain layer, not per controller or in the client |
| Feature interaction | Two correct features combine badly: cancel after partial refund, transfer between own accounts in different currencies, gift card bought with a gift card | Threat-model flows end to end (`kb/01-foundations/threat-modeling.md`); abuse-case tests for each new feature combination |

## Defenses

### 1. Make check and act atomic
- Put the condition in the write: one statement that both checks and changes state, then look at the affected row count.
- Or take a lock for the read-modify-write: `SELECT ... FOR UPDATE` on the row in PostgreSQL/MySQL InnoDB, inside a transaction.
- Or use `SERIALIZABLE` isolation and retry on serialization failures. `READ COMMITTED` (the PostgreSQL default) does not prevent lost updates in read-then-write code.
- Enforce invariants in the database where possible: unique constraints (one redemption per coupon per user), `CHECK (balance >= 0)`, foreign keys. The database then rejects the second racer even if application code is wrong.
- Distributed locks (Redis, etcd) are a last resort; they need fencing tokens and expiry handling, and a database constraint is usually simpler and safer.

Atomic single-use redemption (runnable with the Python standard library):

```python
import sqlite3

db = sqlite3.connect(":memory:", isolation_level=None)
db.execute("CREATE TABLE coupon (code TEXT PRIMARY KEY, uses INTEGER NOT NULL, max_uses INTEGER NOT NULL)")
db.execute("CREATE TABLE redemption (code TEXT, user_id TEXT, UNIQUE (code, user_id))")
db.execute("INSERT INTO coupon VALUES ('WELCOME10', 0, 1)")

def redeem(code: str, user_id: str) -> bool:
    db.execute("BEGIN IMMEDIATE")  # takes the write lock before reading
    try:
        # Check and increment in one statement; never read, compare in Python, then write.
        cur = db.execute(
            "UPDATE coupon SET uses = uses + 1 WHERE code = ? AND uses < max_uses", (code,))
        if cur.rowcount != 1:
            db.execute("ROLLBACK")
            return False
        db.execute("INSERT INTO redemption VALUES (?, ?)", (code, user_id))  # unique constraint backstop
        db.execute("COMMIT")
        return True
    except sqlite3.IntegrityError:
        db.execute("ROLLBACK")
        return False

assert redeem("WELCOME10", "alice") is True
assert redeem("WELCOME10", "bob") is False  # max_uses reached
```

The same pattern in PostgreSQL: `UPDATE wallet SET balance = balance - $1 WHERE id = $2 AND balance >= $1` and treat zero affected rows as "insufficient funds".

### 2. Idempotency for side effects
- Require an `Idempotency-Key` header (IETF httpapi draft) or a client-generated request ID on payments, transfers, refunds and order creation.
- Store the key with a unique constraint in the same transaction as the side effect, together with the request hash and the response; a repeat with the same key returns the stored response, a repeat with a different body is rejected.
- Make webhooks and queue consumers idempotent the same way: process each event ID once.

### 3. Server-side state machines
- Model multi-step flows (checkout, reset, onboarding, approval) as explicit states with allowed transitions stored server-side; every step checks the current state and moves it atomically (`UPDATE ... SET state = 'paid' WHERE id = ? AND state = 'pending_payment'`).
- Tokens for a step (reset, email change, invitation) are single use, bound to the user and the purpose, short lived, and consumed in the same statement that checks them.
- Recompute authoritative values (price, discount, totals, entitlements) at the final step; never carry them in hidden fields or client state.

### 4. Validate business invariants
- Range and type checks on every numeric input; reject negatives and zero where meaningless; money in integer minor units or a decimal type.
- Mass assignment protection: bind only allowlisted fields from requests (`kb/03-application/api-security.md`).
- Keep rules in one domain layer that every channel (web, mobile, partner API, GraphQL, batch import, admin tool) calls.

### 5. Limit and monitor abuse of legitimate flows
- Per-user, per-account and per-instrument velocity limits on sensitive flows (redemptions, sign-ups, OTP attempts, card checks), enforced atomically (counter increment before check).
- Bot management and device signals for flows listed in OWASP OAT (scalping, carding, account creation); CAPTCHA only as one signal.
- Log business events with user, amount, state transition and idempotency key (`kb/06-secure-sdlc/security-logging-and-monitoring.md`); alert on duplicate redemptions, negative balances, refunds above purchase value and transitions that skip states.
- Reconcile ledgers daily: sum of redemptions vs. issued value, refunds vs. captures.

### 6. Design and review
- Write abuse cases next to user stories: "what if this request is sent twice, 50 times at once, out of order, with a negative value, by another user?"
- In code review (`kb/06-secure-sdlc/secure-code-review.md`), flag read-then-write on shared state without a lock, constraint or conditional update; flag client-supplied prices and roles.

## How to verify
- For every endpoint that spends, redeems, consumes or limits something, send 20 to 50 identical requests in parallel (Burp Repeater "send group in parallel", or Turbo Intruder's single-packet mode) in a test environment; exactly the allowed number may succeed and the ledger must balance.
- Test cross-endpoint races: change the cart or email in parallel with confirm/verify, and check the confirmed object matches what was paid or verified.
- Call each step of multi-step flows directly and out of order; each must be refused unless the stored state allows it.
- Tamper with price, quantity (negative, zero, huge), currency, discount and role fields; the server must recompute or reject.
- Replay a captured payment or refund request with and without the same idempotency key; it must be processed once.
- Unit/integration tests: run the redemption function from many threads or processes against the real database engine and assert the invariant (`uses <= max_uses`, `balance >= 0`); tests against an in-memory mock miss races.
- Review database schema for unique and check constraints backing each business rule.
- Follow the OWASP WSTG Business Logic Testing section (WSTG-BUSL) for further cases.

## References
- OWASP WSTG, Business Logic Testing: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- OWASP API Security Top 10 2023, API6 Unrestricted Access to Sensitive Business Flows: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- OWASP Automated Threats to Web Applications (OAT): https://owasp.org/www-project-automated-threats-to-web-applications/
- PortSwigger Web Security Academy, Business logic vulnerabilities: https://portswigger.net/web-security/logic-flaws
- PortSwigger Web Security Academy, Race conditions: https://portswigger.net/web-security/race-conditions
- James Kettle, "Smashing the state machine: the true potential of web race conditions" (PortSwigger Research, 2023): https://portswigger.net/research/smashing-the-state-machine
- Turbo Intruder: https://github.com/PortSwigger/turbo-intruder
- CWE-840, Business Logic Errors: https://cwe.mitre.org/data/definitions/840.html
- CWE-841, Improper Enforcement of Behavioral Workflow: https://cwe.mitre.org/data/definitions/841.html
- CWE-362, Race Condition: https://cwe.mitre.org/data/definitions/362.html
- CWE-367, Time-of-check Time-of-use (TOCTOU) Race Condition: https://cwe.mitre.org/data/definitions/367.html
- PostgreSQL documentation, Transaction Isolation: https://www.postgresql.org/docs/current/transaction-iso.html
- PostgreSQL documentation, Explicit Locking: https://www.postgresql.org/docs/current/explicit-locking.html
- IETF draft, The Idempotency-Key HTTP Header Field: https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/
- See also `kb/03-application/owasp-top10.md`, `kb/03-application/api-security.md`, `kb/03-application/graphql-security.md`, `kb/04-cloud-infra/database-security.md`, `kb/07-offensive/pentest-methodology.md`, `kb/05-identity-crypto/account-takeover-and-credential-stuffing.md`
