# HTTP Request Smuggling and Web Cache Attacks

## What
Attacks that exploit disagreement between the components that handle one HTTP request: CDN, load balancer, reverse proxy, cache and origin server.
- **Request smuggling (HTTP desync)**: front end and back end disagree on where one request ends, so attacker bytes are treated as the start of the *next* request on a reused connection (CWE-444).
- **Web cache poisoning**: an input that is *not* part of the cache key (an unkeyed header or parameter) changes the response, and the poisoned response is then served to every user who requests that key.
- **Web cache deception**: the cache and the origin disagree on what a URL is, so a private, per-user page gets stored as a public static asset and the attacker fetches the victim's copy.

## Why it matters
- One malformed request can affect other users with no interaction: delivering XSS, stealing their requests (cookies, tokens), or replacing a widely cached page or script.
- Smuggled requests skip front-end controls: WAF rules, authentication at the proxy, path-based access restrictions (for example a blocked `/admin`).
- Modern stacks chain several HTTP implementations (CDN, cloud load balancer, ingress controller, app server), often with HTTP/2 at the edge downgraded to HTTP/1.1 internally. Each hop is a parser that can disagree.
- These flaws sit in infrastructure configuration, so application code review and most SAST tools never see them.

## Attacks
*For authorized testing only. Test on your own systems with cache busters so real users are never served a poisoned response.*

| Variant | Mechanism |
|---|---|
| CL.TE | Front end uses `Content-Length`, back end uses `Transfer-Encoding: chunked`; the leftover bytes become a new request |
| TE.CL | Front end uses `Transfer-Encoding`, back end uses `Content-Length` |
| TE.TE | Both support chunked, but one ignores an obfuscated header (`Transfer-Encoding : chunked`, `Transfer-Encoding: xchunked`, duplicated headers) |
| CL.0 | Back end ignores the body on some endpoints (static files, redirects) and treats it as the next request |
| H2.CL / H2.TE | HTTP/2 front end forwards an injected `content-length` or `transfer-encoding` when downgrading to HTTP/1.1; also CR/LF injected in HTTP/2 header values |
| Client-side desync | The browser's own connection to a vulnerable server is desynchronized, so a victim's browser poisons itself |

Web cache attacks:
- **Unkeyed headers**: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Host` reflected into absolute URLs, script sources or redirects, then cached.
- **Unkeyed or cloaked parameters**: parameters the cache strips or parses differently (`utm_*`, `;` versus `&` delimiters, "fat GET" bodies).
- **Cache key normalization**: the cache decodes or normalizes the path differently from the origin.
- **Cache-poisoned DoS**: an oversized or invalid header makes the origin return an error that the cache stores.
- **Cache deception**: `https://app.example.test/account/settings/x.css` or `/account/settings;.js` returns the private settings page (the origin ignores the suffix) and the cache stores it because the path looks static.

## Defenses

### Request smuggling
1. **Reject ambiguity at the front end.** RFC 9112 says a message with both `Transfer-Encoding` and `Content-Length` "ought to be handled as an error", a request whose final transfer coding is not `chunked` must get 400, and differing `Content-Length` values are an unrecoverable error. Configure proxies to return 400 and close the connection for: both headers present, duplicate or non-numeric `Content-Length`, malformed `Transfer-Encoding`, whitespace before the colon, bare CR or LF in headers, and obsolete line folding.
2. **Use HTTP/2 end to end** (or at least between the edge and the origin) so request boundaries are framed rather than inferred. Where downgrading is unavoidable, the front end must strip connection-specific headers and treat HTTP/2 requests carrying them, or CR/LF/NUL in field values, as malformed (RFC 9113 Section 8.2), and verify that `content-length` matches the DATA frames.
3. **Close the back-end connection after any parsing error** and avoid sharing one back-end connection between different clients where the risk justifies the cost.
4. **Keep every HTTP hop patched** (CDN config, load balancer, ingress controller, reverse proxy, app server). Desync bugs are regularly fixed in these products; track them in vulnerability management.
5. **Do not rely on the proxy alone for access control.** The back end authenticates and authorizes every request itself, so a smuggled `/admin` request still fails.
6. Prefer managed load balancers and proxies configured in strict or "defensive" HTTP parsing mode where the product offers one.

### Web cache poisoning
1. **Cache only what is meant to be shared**: static assets and explicitly public responses. Origin sends `Cache-Control: no-store` (or `private`) on anything personalized or authenticated.
2. **Key on every input that changes the response.** If the app uses a header, either add it to the cache key / `Vary` or strip it at the edge before it reaches the origin. Do not trust `X-Forwarded-*` from clients: the edge overwrites them.
3. Disable framework features that honor override headers (`X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`) unless required.
4. Do not cache error responses, or cache them only briefly.
5. Output-encode reflected header values, so a poisoned response cannot carry script anyway (`kb/03-application/browser-client-side.md`).

### Web cache deception
1. Cache decisions follow the origin's `Cache-Control` and `Content-Type`, not the URL extension. Some CDNs offer a check that the extension matches the returned content type (for example Cloudflare Cache Deception Armor).
2. The origin returns 404 (or redirects) for unexpected path suffixes and delimiters instead of ignoring them; frameworks should not match `/account/settings/anything`.
3. Authenticated pages always send `Cache-Control: no-store, private`.

### Detection
- Log and alert on 400 responses for conflicting length headers, requests carrying both `Content-Length` and `Transfer-Encoding`, and unexpected back-end responses that do not match a front-end request.
- Monitor cache hit ratios and response hashes for key pages and scripts; an unexpected change on a cached asset is an incident signal.

## How to verify
- Conflicting headers are rejected (expect `400` and a closed connection, on a host you own):
  ```bash
  printf 'POST / HTTP/1.1\r\nHost: app.example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' \
    | openssl s_client -quiet -connect app.example.test:443 -servername app.example.test 2>/dev/null | head -1
  ```
- Unkeyed header test with a cache buster: request `/?cb=$RANDOM` with `X-Forwarded-Host: canary.example.test`, then request the same URL without the header. The canary must not appear and the second response must not be a cache hit containing it (check `Age`, `X-Cache` or `CF-Cache-Status`).
- Cache deception test: logged in, open `/account/settings/test.css`; then fetch it from a logged-out session. You must get 404, a redirect, or a non-cached response, never the private page.
- Tooling (authorized scope): Burp Suite with the HTTP Request Smuggler and Param Miner extensions; OWASP WSTG test WSTG-INPV-15 (HTTP Splitting/Smuggling).
- Configuration review: list every HTTP hop and its protocol (client to CDN, CDN to load balancer, load balancer to app) and record which ones downgrade to HTTP/1.1 and which reuse connections.

## References
- RFC 9112 HTTP/1.1, Section 6 (message body length, CL/TE handling): https://www.rfc-editor.org/rfc/rfc9112#section-6
- RFC 9113 HTTP/2, Section 8.2 (field validity, connection-specific headers): https://www.rfc-editor.org/rfc/rfc9113#section-8.2
- RFC 9111 HTTP Caching (cache keys, `Cache-Control`, `Vary`): https://www.rfc-editor.org/rfc/rfc9111
- CWE-444 Inconsistent Interpretation of HTTP Requests: https://cwe.mitre.org/data/definitions/444.html
- PortSwigger Web Security Academy, Request smuggling: https://portswigger.net/web-security/request-smuggling · Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning · Web cache deception: https://portswigger.net/web-security/web-cache-deception
- James Kettle, "HTTP Desync Attacks: Request Smuggling Reborn" (2019) and "Practical Web Cache Poisoning" (2018), PortSwigger Research: https://portswigger.net/research
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- See also `kb/03-application/browser-client-side.md`, `kb/03-application/owasp-top10.md`, `kb/02-network/wireless-dns-ddos.md`, `kb/07-offensive/pentest-methodology.md`
