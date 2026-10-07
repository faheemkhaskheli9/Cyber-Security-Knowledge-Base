# Wireless, DNS and DDoS

## What
Three network areas that sit outside the classic firewall/segmentation model: radio networks (Wi-Fi, Bluetooth), the naming system everything depends on (DNS), and availability attacks (DDoS).

## Why it matters
- Wi-Fi extends your network past the building walls.
- DNS hijacking redirects users and email silently, and DNS is a common exfiltration and C2 channel.
- DDoS takes revenue-critical services offline and is often used as a smokescreen for other attacks.

## Attacks
**Wireless**
- Evil twin / rogue AP
- Captive-portal credential phishing
- WPA2-PSK handshake/PMKID capture with offline cracking
- KRACK (unpatched clients)
- WPS PIN brute force
- Deauthentication floods (no 802.11w)
- Bluetooth: BLE sniffing, BlueBorne-class bugs

**DNS**
- Cache poisoning
- Domain or registrar account hijack
- Dangling CNAME leading to **subdomain takeover**
- NXDOMAIN/typosquatting
- DNS tunneling for exfiltration or C2
- Open resolvers abused for amplification

**DDoS**
- Volumetric: UDP/DNS/NTP/memcached amplification
- Protocol: SYN flood
- Application layer (L7): HTTP floods, HTTP/2 Rapid Reset (CVE-2023-44487), expensive search/login endpoints

## Defenses
**Wireless**
- WPA3-Enterprise (802.1X/EAP-TLS with certificates) for corporate; WPA3-SAE for small sites. Disable WPS.
- Enable Protected Management Frames (802.11w).
- Separate guest and IoT SSIDs on isolated VLANs.
- Wireless IDS to detect rogue APs.
- Clients must validate the RADIUS server certificate, otherwise evil-twin attacks capture credentials.

**DNS**
- Enable registrar lock and MFA on registrar and DNS-provider accounts.
- Sign zones with DNSSEC and validate on resolvers.
- Remove dangling records when deprovisioning cloud resources.
- Use protective DNS / RPZ filtering; send internal clients only through approved resolvers (block outbound 53, control DoH).
- Log DNS queries and alert on high-entropy or long subdomains (tunneling).
- Never run an open recursive resolver.
- Email: SPF, DKIM, DMARC `p=reject`, MTA-STS.

**DDoS**
- Use a CDN / anycast scrubbing provider (Cloudflare, Akamai, AWS Shield, Azure DDoS Protection, Google Cloud Armor).
- Hide origin IPs and allow only the CDN to reach the origin.
- Rate limiting, WAF bot rules, caching, autoscaling with cost caps.
- Patch web servers for HTTP/2 flaws.
- BCP 38 ingress filtering (anti-spoofing) on networks you operate.
- Keep a runbook with provider contacts; rehearse it.

## How to verify
- Wi-Fi: authorized survey with `airodump-ng`/Kismet. Confirm WPA3/PMF, no WPS, and certificate validation on clients.
- DNS:
  - `dig +dnssec example.com` shows the `ad` flag via a validating resolver.
  - Use `dnsviz.net`.
  - Scan for dangling CNAMEs (e.g., `subjack`, `nuclei` takeover templates) on your own domains.
  - Check DMARC with `dig TXT _dmarc.example.com`.
- DDoS: confirm the origin isn't directly reachable. Load-test only your own infrastructure, with provider approval.

## References
- NIST SP 800-153 (WLAN security) · Wi-Fi Alliance WPA3 spec
- NIST SP 800-81-2 (Secure DNS) · OWASP Subdomain Takeover guide
- CISA DDoS guidance · RFC 2827 / BCP 38
- See also `kb/02-network/network-security.md`
