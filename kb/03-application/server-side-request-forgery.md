# Server-Side Request Forgery (SSRF)

## What
**SSRF** (CWE-918) is when an attacker makes a server send a request to a destination the attacker chooses. The request comes from inside your network with the server's identity, so it can reach things the attacker cannot: cloud instance metadata, internal admin panels, databases and caches, Kubernetes and Docker APIs, and other tenants' services.

Typical entry points are any feature that fetches a URL or a resource named by the user:
- Webhooks, "import from URL", link previews and unfurling, RSS/feed readers, avatar or image fetch by URL.
- HTML-to-PDF and screenshot services (headless browsers, wkhtmltopdf) that load `<img>`, `<iframe>` or CSS from attacker HTML.
- Document and image processing that follows external references: XXE in XML, SVG, office files (`kb/03-application/file-upload-security.md`).
- Identity protocol fetches: OIDC `request_uri` and `jwks_uri`, JWT `jku`/`x5u` headers, SAML metadata URLs (`kb/05-identity-crypto/oauth-oidc-security.md`).
- Server-side WebSocket, GraphQL and integration clients (`kb/03-application/websocket-security.md`, `kb/03-application/graphql-security.md`).

Variants: **basic** (response returned to the attacker), **blind** (no response, detected through out-of-band callbacks or timing), and **semi-blind** (status code, length or error message leaks).

SSRF is A10 in the OWASP Top 10:2021 (merged into Broken Access Control in the 2025 edition; see `kb/03-application/owasp-top10.md`) and API7:2023 in the OWASP API Security Top 10 (`kb/03-application/api-security.md`).

## Why it matters
- **Cloud credential theft**: from a VM, container or function, the instance metadata service returns temporary credentials for the attached role (MITRE ATT&CK T1552.005). The Capital One breach in 2019 used SSRF against IMDSv1 to obtain role credentials and read S3 data (`kb/04-cloud-infra/cloud-security.md`).
- **Pivot to internal services**: many internal services trust the network and have no authentication (Redis, Elasticsearch, Docker API, kubelet, admin consoles, actuator and debug endpoints).
- **Chains to RCE**: Microsoft Exchange ProxyLogon (CVE-2021-26855) was a pre-authentication SSRF chained with a file-write bug for code execution.
- **Hard to see**: the malicious request is ordinary outbound traffic from a trusted server; without egress logging it leaves little trace.

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Cloud metadata credentials | `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` on AWS IMDSv1; similar endpoints on GCP (`metadata.google.internal`, needs `Metadata-Flavor: Google`) and Azure (`169.254.169.254`, needs `Metadata: true`) | IMDSv2 required with hop limit 1 (AWS); block link-local in the fetcher; least-privilege role so stolen credentials are worth little; alert on instance credentials used outside the instance |
| Internal service access | `http://localhost:8080/admin`, `http://10.0.0.5:9200/_cat/indices`, kubelet `:10250`, Docker `:2375` | Destination allowlist; deny private, loopback and link-local ranges; network policy so the fetcher's subnet cannot reach internal services; authentication on every internal service |
| Alternate IP encodings | `2852039166`, `0xA9FEA9FE`, `0251.0376.0251.0376`, `127.1`, `0.0.0.0`, `[::]`, `[::ffff:169.254.169.254]` all reach blocked addresses | Never filter on the URL string; resolve, parse the result with a real IP library, unwrap IPv4-mapped IPv6, then check |
| DNS tricks | Hostname that resolves to `127.0.0.1` or an internal IP; **DNS rebinding** returns a public IP at check time and an internal one at connect time | Resolve once and connect to the checked IP (pinning), or route through an egress proxy that enforces the policy at connect time |
| Redirects | Allowed public URL answers `302 Location: http://169.254.169.254/` | Disable automatic redirects, or re-validate every hop with the same checks and cap the count |
| Scheme abuse | `file:///etc/passwd`, `gopher://` to speak raw Redis or SMTP, `dict://`, `ftp://`, `jar:` | Allow only `https` (and `http` if needed); use an HTTP client that supports nothing else |
| URL parser differentials | `https://allowed.example@evil.example/`, backslashes, mixed encodings: the validator and the HTTP client disagree on the host (Orange Tsai, "A New Era of SSRF", Black Hat USA 2017) | Parse once, then build the request from the parsed parts; reject userinfo, unusual characters and non-default ports |
| Headless browser and PDF rendering | Attacker HTML or SVG loads `http://169.254.169.254/`, internal pages or `file://` into the rendered output | Render in an isolated network with no route to internal ranges or metadata; disable local file access; block JavaScript where not needed |
| Blind SSRF | No response body, but the attacker sees a DNS or HTTP callback to a host they control, or measures timing to port-scan internal ranges | Same allowlist and egress controls; consistent errors and timeouts; alert on fetches to unusual destinations |
| Protocol fetches | Attacker-controlled `jku`/`x5u` header, `request_uri` or SAML metadata URL makes the server fetch from anywhere | Configure trusted keys and metadata statically; ignore `jku`/`x5u` unless matched against an allowlist |

## Defenses

### 1. Design out the URL
- Prefer not fetching user-supplied URLs at all: accept an upload instead of a URL, pick from a list of known integrations, or let the client fetch.
- When the destination is known per tenant (webhooks), register and verify it once (ownership challenge), store it, and send only to the stored value.

### 2. Validate the destination, not the string
Allow `https` only, an allowlist of hosts where possible, the default port, no credentials in the URL, and only globally routable IP addresses. Check every address the name resolves to, then connect to the address you checked so a second DNS lookup cannot change it. Do not follow redirects without re-checking. Minimal stdlib example (Python 3):

```python
import http.client, ipaddress, socket, ssl
from urllib.parse import urlsplit

ALLOWED_HOSTS = {"api.partner.example", "hooks.example.com"}  # empty set = any public host

def public_ips(host, port):
    """Resolve once; refuse if any answer is not a global unicast address."""
    ips = set()
    for *_, sockaddr in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.version == 6 and ip.ipv4_mapped:      # ::ffff:169.254.169.254
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise ValueError(f"blocked destination {ip}")
        ips.add(str(ip))
    return sorted(ips)

def check_url(url):
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ValueError("only https URLs without credentials")
    if ALLOWED_HOSTS and u.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not on allowlist")
    port = u.port or 443
    if port != 443:
        raise ValueError("port not allowed")
    return u, port, public_ips(u.hostname, port)[0]

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the IP that was checked, but verify TLS for the hostname."""
    def __init__(self, host, ip, port=443, timeout=5):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip
    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

def safe_get(url, max_bytes=1_000_000):
    u, port, ip = check_url(url)
    conn = PinnedHTTPSConnection(u.hostname, ip, port)
    conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""))
    resp = conn.getresponse()            # http.client never follows redirects
    if 300 <= resp.status < 400:
        raise ValueError("redirects are not followed")  # or re-run check_url on Location
    return resp.status, resp.read(max_bytes)
```

`is_global` rejects loopback, RFC 1918, link-local (metadata), carrier-grade NAT (`100.64.0.0/10`, which includes Alibaba Cloud's `100.100.100.200` metadata address) and other reserved ranges. Apply the same idea in other languages with a vetted library, and keep the HTTP client's own redirect and proxy settings explicit.

### 3. Enforce it in the network too
- Run fetchers (webhook senders, renderers, importers) in a dedicated subnet or namespace whose only egress is an **egress proxy** that denies internal and link-local ranges at connect time, for example Stripe's Smokescreen. Application checks then are a second layer, not the only one.
- Default-deny egress and Kubernetes NetworkPolicy so ordinary app pods cannot reach the metadata IP or internal admin ports unless they need them (`kb/04-cloud-infra/containers-kubernetes-iac.md`, `kb/02-network/network-security.md`).
- Authenticate internal services; "only reachable from inside" is not an access control (`kb/01-foundations/zero-trust-architecture.md`).

### 4. Harden metadata and credentials
- AWS: require IMDSv2 (`HttpTokens=required`) with `HttpPutResponseHopLimit=1` unless containers on the host need 2; disable IMDS where unused; set the account-level default and enforce with an SCP (`kb/04-cloud-infra/cloud-provider-baselines.md`).
- GCP and Azure metadata require a request header that a basic SSRF usually cannot set; do not rely on that alone, since some SSRF primitives allow headers.
- Least-privilege roles for workloads, and detections for instance credentials used from outside the instance (for example GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`; `kb/08-defensive/cloud-incident-response.md`).

### 5. Limit what a successful request returns
- Do not return raw upstream responses, headers or detailed errors to the user; return a fixed message and log the detail.
- Cap response size and time, set connect and read timeouts, and rate-limit fetch features per user.

### 6. Find it in code review
Look for user input reaching `requests.get`, `urllib.request.urlopen`, `httpx`, `fetch`, `axios`, `HttpClient`, `curl_exec`, `file_get_contents`, image libraries and PDF renderers. CodeQL and Semgrep include SSRF rules (for example CodeQL `py/full-ssrf`, `js/request-forgery`; `kb/06-secure-sdlc/secure-code-review.md`).

## How to verify
- Unit-test the validator with the bypass list: `http://169.254.169.254/`, `https://127.0.0.1/`, `https://2852039166/`, `https://[::ffff:169.254.169.254]/`, `https://localhost/`, `https://user:pw@allowed.example/`, non-443 ports, `file://`, `gopher://`, a hostname you control that resolves to `127.0.0.1`, and a public URL that redirects to the metadata IP. Every one must be refused.
- Out-of-band test in authorized scope: point each URL-taking parameter at a callback host you control (Burp Collaborator, interactsh) to find blind SSRF, including headers such as `Referer` that some servers fetch.
- From inside the fetcher's pod or host, confirm the network layer blocks it too: `curl -m 3 http://169.254.169.254/` and requests to internal admin ports must fail.
- AWS: list instances not enforcing IMDSv2:
  ```bash
  aws ec2 describe-instances \
    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens!=`required`].InstanceId' --output text
  ```
- Review egress proxy logs for denied internal destinations; any hit is either a bug or an attack.

## References
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-918, Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html
- OWASP Top 10:2021 A10 and OWASP API Security Top 10 2023 API7: https://owasp.org/Top10/ · https://owasp.org/API-Security/
- PortSwigger Web Security Academy, SSRF: https://portswigger.net/web-security/ssrf
- MITRE ATT&CK T1552.005, Unsecured Credentials: Cloud Instance Metadata API: https://attack.mitre.org/techniques/T1552/005/
- AWS, Use the Instance Metadata Service to access instance metadata (IMDSv2): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Stripe Smokescreen egress proxy: https://github.com/stripe/smokescreen
- Orange Tsai, "A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages!", Black Hat USA 2017
- Python `ipaddress` module documentation: https://docs.python.org/3/library/ipaddress.html
- See also `kb/03-application/owasp-top10.md`, `kb/03-application/api-security.md`, `kb/04-cloud-infra/cloud-security.md`, `kb/04-cloud-infra/serverless-security.md`, `kb/03-application/file-upload-security.md`, `kb/05-identity-crypto/oauth-oidc-security.md`
