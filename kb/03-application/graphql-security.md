# GraphQL Security

## What
**GraphQL** is a query language and runtime for APIs: one endpoint (usually `POST /graphql`) accepts a client-written document of queries, mutations or subscriptions, and resolvers fetch each requested field. The schema is typed and self-describing (introspection). Because the client controls the shape and size of every request, GraphQL changes where authorization, rate limiting and cost control must live. The short checklist is in `kb/03-application/api-security.md`; this file covers the attacks and controls in depth. General API risks (OWASP API Security Top 10, BOLA, mass assignment) still apply.

## Why it matters
- **One endpoint, many operations**: WAF rules, path-based authorization and per-route rate limits designed for REST see a single URL and cannot tell a cheap query from an expensive one.
- **Authorization moves into resolvers**: every type and field reachable through the graph is a potential path to data. A check on `Query.user` does nothing if `Order.customer` returns the same `User` object without one.
- **Client-defined cost**: nesting, aliases, fragments and batching let one HTTP request do thousands of resolver calls, so a single request can exhaust a database or downstream service.
- **Schema exposure**: introspection or verbose error suggestions give an attacker a full map of types, fields, mutations and arguments, including internal or deprecated ones.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Schema discovery | `{__schema{types{name fields{name}}}}` returns the whole schema; with introspection off, "Did you mean ...?" suggestions in error messages still leak field names (tools such as Clairvoyance rebuild the schema from them) | Disable introspection and field suggestions in production; treat the schema as public anyway and never rely on obscurity |
| Broken object / field authorization | Resolver for a nested field (`order { customer { email } }`) or a node lookup (`node(id: "...")`) skips the ownership check that the top-level query does | Authorize in the business layer every resolver calls, per object and per field; test every path to each sensitive type |
| Deep / circular queries | Cycles in the type graph (`user { friends { friends { ... } } }`) multiply resolver work exponentially | Max depth limit; query cost analysis with a per-request and per-client budget; pagination limits (`first <= N`) on lists |
| Alias and batching abuse | Many aliased copies of one field (`a1: login(...) a2: login(...)`) or an array of operations in one HTTP request bypass per-request rate limits; used for password or OTP brute force | Count aliases and batched operations toward rate limits; cap aliases and batch size; disable array batching if not needed; rate-limit sensitive mutations per user and per target |
| Field duplication / directive overloading | Repeating a field or directive thousands of times in one document consumes parser and validation CPU | Maximum document size and token count; limits on repeated fields and directives before execution |
| Injection through arguments | Resolver concatenates arguments into SQL, NoSQL, LDAP, OS commands or URLs (SSRF) | Typed input validation (custom scalars, enums), parameterized queries, the same sink defenses as `kb/03-application/owasp-top10.md` |
| CSRF | Server accepts queries via `GET` or "simple" `POST` bodies (`application/x-www-form-urlencoded`, `text/plain`), so a cross-site form triggers a mutation with the victim's cookies | Mutations only over `POST` with `Content-Type: application/json`; reject other content types; `SameSite` cookies; framework CSRF prevention (Apollo Server's requires a preflight-triggering header) |
| Cross-site WebSocket hijacking | Subscription endpoint over WebSocket authenticates with cookies and does not check `Origin` | Validate `Origin`; authenticate in `connection_init` with a token, re-check authorization per subscription event |
| Information disclosure in errors | Stack traces, SQL errors or internal service names returned in `errors[].extensions` | Mask unexpected errors in production; log details server-side only |
| Federation / gateway bypass | Subgraphs behind a gateway are reachable directly and trust any caller, or trust a user-ID header that the client can set | Network-restrict subgraphs to the gateway; authenticate the gateway to subgraphs (mTLS or signed tokens); enforce authorization in each subgraph too |

## Defenses

### 1. Authorization model
- Put authorization in the domain / service layer that all resolvers call (the GraphQL Foundation's own guidance), not in the HTTP middleware alone; deny by default.
- Check object ownership on every resolver that returns a sensitive object, including nested fields, connection edges and global `node(id:)` lookups.
- Field-level rules for sensitive fields (email, PII, internal flags), via schema directives (`@auth`, `@requiresScopes`) or explicit resolver checks; test that directives are actually enforced.
- Mutations validate inputs against an allowlist of writable fields; never map an input type straight onto a database model (mass assignment).

### 2. Cost and abuse limits
- Enforce, before execution: maximum document size, maximum depth, maximum aliases, maximum batched operations, and a computed query cost (fields weighted by list size and resolver expense). Choose limits from your real client queries rather than defaults.
- Paginate every list field with a server-enforced maximum page size.
- Timeouts on each resolver and on the whole request; DataLoader-style batching so a nested list does not cause N+1 database queries.
- Rate limit by authenticated principal and by computed cost, not just by HTTP request count.

### 3. Restrict what can be sent
- For first-party clients, use **trusted documents / operation allowlists**: the build registers every query, and production accepts only an operation ID or hash from that list. This removes arbitrary queries, most cost attacks and much schema discovery.
- Automatic persisted queries (APQ) are a caching feature, not a security control: they register any query a client sends.
- Public APIs that must accept arbitrary queries rely on cost analysis, authentication and per-client quotas instead.

### 4. Production configuration
- Introspection off for public endpoints (or only for authenticated internal tooling); field suggestions off; GraphiQL / Playground UIs off.
- Accept `POST` with `application/json` (or `application/graphql-response+json` per the GraphQL over HTTP spec); allow `GET` only for queries, never mutations.
- CORS: explicit origin allowlist; no reflected origins with credentials (`kb/03-application/browser-client-side.md`).
- Error masking with server-side correlation IDs.
- Subscriptions: authenticate at connection time, expire long-lived connections with the token, limit subscriptions per connection.

### 5. Logging and monitoring
- Log operation name, operation hash, computed cost, depth, alias count, principal and result per request (not the variables when they carry secrets or PII; `kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on introspection attempts, rejected-by-limit queries, sudden rise in cost per principal, and many failed authentications inside one batched or aliased request.

## How to verify
- Introspection: `curl -s -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}' https://api.example.test/graphql` must return an error in production.
- Suggestions: send a misspelled field (`{usr{id}}`); the error must not contain "Did you mean".
- Limits: send a query nested deeper than the limit, one with more aliases than allowed, an array of batched operations, and a list field with `first: 100000`; each must be rejected before execution.
- CSRF: send a mutation as `GET` and as `Content-Type: text/plain` and `application/x-www-form-urlencoded`; all must fail.
- Authorization: with two test users, request user B's objects through every path (top-level query, nested field, `node(id:)`, connection edges, mutation return types); every path must refuse.
- Trusted documents: send a valid query that is not in the allowlist; it must be rejected.
- Run graphql-cop and InQL (Burp extension) against a test environment; review results against this file. OWASP WSTG "Testing GraphQL" lists further test cases.

## References
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP Web Security Testing Guide, Testing GraphQL: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- GraphQL Specification: https://spec.graphql.org/
- graphql.org, Authorization (delegate to the business logic layer): https://graphql.org/learn/authorization/
- GraphQL over HTTP specification (draft): https://graphql.github.io/graphql-over-http/draft/
- PortSwigger Web Security Academy, GraphQL API vulnerabilities: https://portswigger.net/web-security/graphql
- PortSwigger, Cross-site WebSocket hijacking: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- Apollo Server, CORS and CSRF prevention: https://www.apollographql.com/docs/apollo-server/security/cors
- Tools: graphql-cop https://github.com/dolevf/graphql-cop, InQL https://github.com/doyensec/inql, Clairvoyance https://github.com/nikitastupin/clairvoyance
- See also `kb/03-application/api-security.md`, `kb/03-application/owasp-top10.md`, `kb/05-identity-crypto/oauth-oidc-security.md`, `kb/07-offensive/pentest-methodology.md`
