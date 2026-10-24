# WebSocket Security

## What
WebSockets (RFC 6455) upgrade an HTTP/1.1 request (`Upgrade: websocket`, `Sec-WebSocket-Key`) into a long-lived, full-duplex message channel; RFC 8441 carries them over HTTP/2. They power chat, live dashboards, trading, collaborative editing, notifications and GraphQL subscriptions, often through libraries such as Socket.IO or SignalR that fall back to HTTP long polling. Security-relevant properties: browsers do not apply the same-origin policy or CORS to WebSocket connections, browsers send cookies with the handshake, the protocol has no built-in authentication or authorization, and once open a connection can outlive the session that created it. This file covers the handshake, message handling and infrastructure.

## Why it matters
- **Cross-site WebSocket hijacking (CSWSH)**: a page on any site can open a WebSocket to your server; if the handshake is authenticated only by cookies and the server does not check `Origin`, the attacker's page gets a fully authenticated two-way channel, reading responses as well as sending actions (CSRF with read access). CWE-1385 (Missing Origin Validation in WebSockets).
- **Authorization gaps**: teams authenticate the handshake and then trust every message, so any connected user can subscribe to another tenant's channel or call admin actions.
- **Classic injection over a new transport**: message fields reach SQL, shell, templates and the DOM just like HTTP parameters; WAFs and DAST tools often inspect them less, or not at all.
- **Availability**: long-lived connections, large frames and message floods exhaust memory, file descriptors and worker capacity with little traffic.
- **Stale sessions**: a connection opened before logout, password reset or role removal keeps working unless the server closes it.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Cross-site WebSocket hijacking | Attacker page runs `new WebSocket("wss://app.example/ws")`; the browser attaches the victim's cookies; the server accepts any `Origin` | Exact-match `Origin` allowlist in the handshake; authenticate with a short-lived ticket or token, not cookies alone; `SameSite=Lax`/`Strict` session cookies as defense in depth |
| Missing per-message authorization | After connecting, the client sends `{"action":"subscribe","room":"tenant-42"}` or `{"action":"deleteUser"}` and the server does not check rights | Authorize every message and subscription against the connection's identity, as for each HTTP request (`kb/03-application/api-security.md`) |
| Unauthenticated endpoint | The WebSocket path is not covered by the auth middleware that protects the REST routes | Deny by default at the handshake; include WebSocket routes in auth tests and the API inventory |
| Token in the URL | `wss://host/ws?token=...` lands in proxy, CDN and server access logs and browser history | Send a one-time ticket (seconds of validity) in the URL, or the token in the first message or `Sec-WebSocket-Protocol`; never a long-lived token |
| Injection via messages | Message fields used in SQL queries, OS commands, templates, or written to other users' DOM with `innerHTML` (stored or broadcast XSS) | Schema-validate every message (type, length, enum); parameterized queries; encode output on the client (`kb/03-application/browser-client-side.md`) |
| Session outliving logout | Connection stays open after logout, token expiry, password change or permission change | Track connections per session; close them on logout and revocation; re-check token expiry on a timer; cap connection lifetime |
| Plaintext `ws://` | Messages and the cookie-bearing handshake travel unencrypted; proxies may also mangle them | `wss://` only; HSTS; reject `ws://` in production |
| Resource exhaustion | Many idle connections, huge frames, fragmented messages, compression bombs (`permessage-deflate`), high message rates | Max message and frame size, per-IP and per-user connection limits, message rate limits, idle and handshake timeouts, bounded per-connection queues |
| Compression side channel | Attacker-controlled data and secrets compressed in the same `permessage-deflate` context leak through message size (CRIME-like) | Disable compression for channels that mix secrets with attacker input, or do not mix them |
| Upgrade smuggling through proxies | A reverse proxy treats a failed or fake `Upgrade` as a tunnel, giving the client a raw connection to internal backend endpoints | Proxy validates the backend's `101 Switching Protocols` before tunneling; keep the proxy patched; backends do not expose internal routes on the same listener (`kb/03-application/http-request-smuggling-and-cache-attacks.md`) |
| SSRF via server-side clients | Server opens a WebSocket to a URL supplied by the user (webhooks, integrations) and reaches internal services | Destination allowlist and egress controls as for HTTP SSRF (`kb/03-application/owasp-top10.md`) |
| Fallback transport gaps | Socket.IO / SignalR long-polling fallback uses ordinary HTTP endpoints with different CORS and CSRF handling than the WebSocket path | Apply the same origin, auth and CSRF rules to fallback transports; disable fallbacks you do not need |

## Defenses

### 1. Handshake
- `wss://` only, behind the same TLS configuration as the rest of the site (`kb/05-identity-crypto/pki-and-tls.md`).
- Validate `Origin` against an exact allowlist (scheme, host, port); reject a missing or `null` origin for browser endpoints. RFC 6455 section 10.2 leaves this check to the server. Non-browser clients can forge `Origin`, so this stops cross-site browser abuse only, not direct attackers.
- Authenticate explicitly. A common pattern: an authenticated HTTP `POST /ws-ticket` (CSRF-protected) returns a random single-use ticket valid for seconds, bound to the user and the origin; the client connects with it and the server consumes it atomically. Alternatively send an access token in the first message and close the connection if it does not arrive within a few seconds.
- Do not log full handshake URLs that contain tickets or tokens.

Origin and single-use ticket check (standard library, framework-agnostic):

```python
import secrets, time

ALLOWED_ORIGINS = {"https://app.example.com"}
TICKET_TTL = 30  # seconds
_tickets: dict[str, tuple[str, float]] = {}  # use a shared store (e.g. Redis GETDEL) in production

def issue_ticket(user_id: str) -> str:
    """Called from an authenticated, CSRF-protected HTTP endpoint."""
    ticket = secrets.token_urlsafe(32)
    _tickets[ticket] = (user_id, time.monotonic() + TICKET_TTL)
    return ticket

def authenticate_handshake(headers: dict[str, str], ticket: str) -> str | None:
    """Return the user ID for a valid handshake, else None (reject with 403)."""
    if headers.get("origin") not in ALLOWED_ORIGINS:
        return None
    entry = _tickets.pop(ticket, None)  # single use: removed whether valid or expired
    if entry is None or time.monotonic() > entry[1]:
        return None
    return entry[0]

t = issue_ticket("alice")
assert authenticate_handshake({"origin": "https://evil.example"}, t) is None
t = issue_ticket("alice")
assert authenticate_handshake({"origin": "https://app.example.com"}, t) == "alice"
assert authenticate_handshake({"origin": "https://app.example.com"}, t) is None  # replay refused
```

### 2. Messages
- Define a schema per message type (JSON Schema, Pydantic, protobuf); reject unknown types and fields, oversize strings and wrong types before any processing.
- Authorize every action and every channel subscription against the connection's user, tenant and current permissions; do not trust IDs or room names in the message.
- Treat message data as untrusted at every sink: parameterized queries, no shell, safe templating; on the client, render with `textContent` or framework escaping, never `innerHTML`.
- Server-to-client broadcasts: filter per recipient; do not send another user's data and rely on the client to hide it.

### 3. Connection lifecycle
- Bind each connection to a session ID; on logout, password change, token revocation or role change, close affected connections (or re-check on each message).
- Re-validate token expiry periodically; cap the maximum connection lifetime and require reconnecting with a fresh ticket.
- Idle timeout and ping/pong keepalive; close half-open connections.

### 4. Limits and infrastructure
- Maximum message size, frame size and fragment count; limit decompressed size if `permessage-deflate` is on.
- Per-IP and per-user concurrent connection caps; message rate limits per connection; bounded outbound queues so a slow reader cannot exhaust server memory.
- Configure the reverse proxy or load balancer explicitly for WebSockets (upgrade handling, read timeouts, max connections) and keep it patched.
- Put WebSocket endpoints in the API inventory and the attack surface inventory (`kb/09-governance/attack-surface-management.md`).

### 5. Logging and detection
- Log handshakes (user, origin, IP, result), authorization denials, schema rejections, rate-limit hits and forced closes (`kb/06-secure-sdlc/security-logging-and-monitoring.md`); never log ticket or token values or full message bodies containing personal data.
- Alert on handshakes with unexpected origins, many rejected tickets from one source, and connection counts per user above normal.

## How to verify
- CSWSH test (authorized, test environment): from a page on another origin, open a WebSocket to the endpoint while logged in; the handshake must fail. Repeat with `curl` or a WebSocket client sending `Origin: https://evil.example` and the victim's cookie; expect `403`, not `101`.
- Connect without credentials, with an expired ticket and with a reused ticket; each must be refused.
- With Burp Suite (WebSockets history and Repeater) or OWASP ZAP, change room, tenant and object IDs in messages and call privileged actions as a low-privilege user; each must be denied.
- Send injection payloads (SQL, template, HTML/script) in message fields; check server behavior and how other clients render broadcasts.
- Log out or revoke the user's session in another tab; the open connection must close or start refusing messages.
- Send an oversize message, a flood of messages and many parallel connections; the server must close or throttle without degrading other users.
- Check that `ws://` is refused in production and that access logs contain no tokens.
- Follow OWASP WSTG test WSTG-CLNT-10 (Testing WebSockets).

## References
- RFC 6455, The WebSocket Protocol (section 10, Security Considerations): https://www.rfc-editor.org/rfc/rfc6455
- RFC 8441, Bootstrapping WebSockets with HTTP/2: https://www.rfc-editor.org/rfc/rfc8441
- RFC 7692, Compression Extensions for WebSocket (permessage-deflate): https://www.rfc-editor.org/rfc/rfc7692
- OWASP WSTG, Testing WebSockets (WSTG-CLNT-10): https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- PortSwigger Web Security Academy, WebSockets security vulnerabilities: https://portswigger.net/web-security/websockets
- PortSwigger Web Security Academy, Cross-site WebSocket hijacking: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- CWE-1385, Missing Origin Validation in WebSockets: https://cwe.mitre.org/data/definitions/1385.html
- MDN, The WebSocket API: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API
- See also `kb/03-application/api-security.md`, `kb/03-application/graphql-security.md`, `kb/03-application/browser-client-side.md`, `kb/03-application/http-request-smuggling-and-cache-attacks.md`, `kb/07-offensive/pentest-methodology.md`
