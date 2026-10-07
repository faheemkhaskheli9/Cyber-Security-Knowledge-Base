# Email Security

## What
Protecting the email channel in both directions:
- **Domain authentication** stops others sending as your domain: SPF, DKIM, DMARC, plus ARC and BIMI.
- **Transport security** protects mail between servers: STARTTLS, MTA-STS, TLS-RPT, DANE.
- **Inbound defenses** cover phishing, BEC and malicious content: the gateway, users and payment processes.

## Why it matters
- Email is the most common initial-access vector (phishing) and the channel for business email compromise (BEC), which loses organizations more money than ransomware in FBI IC3 reporting.
- Without DMARC enforcement, anyone can send mail with your exact `From:` domain to customers and staff.
- SMTP STARTTLS is opportunistic by default: an on-path attacker can strip it and read or alter mail in transit.
- Gmail and Yahoo reject or junk unauthenticated bulk mail, so authentication is also a deliverability requirement.

## Attacks
| Attack | How it works |
|---|---|
| Phishing | Mass email that lures users to credential pages or malware |
| Spear phishing | Targeted lure built from OSINT (role, vendors, current projects) |
| BEC | Impersonated or compromised exec/vendor mailbox requests a wire, a bank-detail change or gift cards; often no link or attachment |
| Exact-domain spoofing | `From: ceo@example.com` sent from an attacker server; works when DMARC is missing or `p=none` |
| Lookalike domains | `examp1e.com`, `example-payments.com`, homoglyph/IDN domains, other TLDs; pass SPF/DKIM/DMARC for *their* domain |
| Display-name spoofing | `"Jane Doe (CEO)" <jane.doe.ceo@freemail.example>`; mobile clients often hide the address |
| Thread hijacking | Attacker uses a compromised mailbox (yours or a vendor's) to reply inside a real thread; inherits trust |
| QR phishing ("quishing") | URL inside an image QR code evades URL scanners and moves the victim to an unmanaged phone |
| OAuth consent phishing | Link to a real IdP consent screen for a malicious app requesting `Mail.Read`/`offline_access`; survives password resets |
| AitM phishing | Reverse-proxy kits relay the real login and steal the session cookie, bypassing OTP and push MFA |
| HTML smuggling | Attached HTML builds the payload in the browser (JavaScript blob), so the gateway never sees the file |
| Attachment abuse | Macro documents, archives/ISO/LNK containers, password-protected ZIPs that block scanning |
| Mailbox persistence | After takeover: inbox rules that hide or forward replies, external auto-forwarding, illicit OAuth grants |
| STARTTLS downgrade | On-path attacker strips STARTTLS or presents a fake MX certificate |

## Defenses
### SPF (RFC 7208)
Lists the hosts allowed to send for the envelope sender (`MAIL FROM` / Return-Path) domain.
```
example.com.  TXT  "v=spf1 ip4:192.0.2.10 ip6:2001:db8::10 include:_spf.mailprovider.example -all"
```
- **10-lookup limit**: `include`, `a`, `mx`, `ptr`, `exists` and `redirect` each cost a DNS lookup, nested includes count too. Over 10 lookups gives `permerror` (treated as a fail by many receivers). Remove unused vendors, prefer `ip4:`/`ip6:`, avoid `ptr`. Be careful with "SPF flattening": it breaks silently when the vendor changes IPs.
- Only one SPF record per name. End with `-all` (or `~all` while DMARC enforcement is doing the blocking).
- Non-sending domains and subdomains: `"v=spf1 -all"`.
- SPF breaks on forwarding and does not check the visible `From:`. DMARC fixes the second problem.

### DKIM (RFC 6376)
Signs headers and body. The public key is published at `<selector>._domainkey.<domain>`.
```
s2026a._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkqh...IDAQAB"
```
- RSA **2048-bit** keys (RFC 8301 forbids < 1024 and recommends ≥ 2048); Ed25519 (RFC 8463) can be added as a second signature.
- **Rotate** keys on a schedule (e.g., every 6–12 months) and immediately after a suspected leak. Publish the new selector, switch signing, wait for in-flight mail, then revoke the old one with an empty `p=`.
- Use a separate selector per sending service so each can be revoked on its own. Sign with your own domain (`d=example.com`), not the vendor's.

### DMARC (RFC 7489)
Requires SPF or DKIM to pass **and align** with the visible `From:` domain. Tells receivers what to do on failure and where to send reports.
```
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=r; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; fo=1"
```
- **Alignment**: relaxed (default) means the same organizational domain (`mail.example.com` aligns with `example.com`); strict (`s`) means an exact match. DKIM alignment survives forwarding, so make DKIM the primary path.
- **Rollout**:

| Stage | Policy | Exit criteria |
|---|---|---|
| 1. Monitor | `p=none; rua=...` | Every legitimate source found in reports and passing aligned SPF/DKIM |
| 2. Quarantine | `p=quarantine; pct=10` → `pct=100` | No legitimate mail failing for 2–4 weeks |
| 3. Reject | `p=reject` (+ `sp=reject`) | Steady state; keep monitoring reports |

- `rua` = daily aggregate XML reports (who sends as you, pass/fail counts). `ruf` = per-message failure reports; few receivers send them and they may contain personal data, so handle them as sensitive.
- Sending reports to another domain requires an authorization record there: `example.com._report._dmarc.reports.example.net TXT "v=DMARC1"`.
- Parked domains: `v=spf1 -all`, `p=reject`, null MX (`MX 0 .`, RFC 7505).

### ARC, transport and branding
- **ARC** (RFC 8617): intermediaries (mailing lists, forwarders, security gateways) seal the authentication results they saw. Receivers *may* trust the seals of known intermediaries when forwarding has broken SPF/DKIM. Configure the receiving side to trust your own gateway's ARC.
- **MTA-STS** (RFC 8461): makes TLS with a valid certificate mandatory for mail to your MX hosts.
  ```
  _mta-sts.example.com.  TXT  "v=STSv1; id=20261007T000000"
  # https://mta-sts.example.com/.well-known/mta-sts.txt
  version: STSv1
  mode: enforce
  mx: mx1.example.com
  mx: mx2.example.com
  max_age: 604800
  ```
  Start with `mode: testing`. Change `id` whenever the policy changes.
- **TLS-RPT** (RFC 8460): daily reports of TLS failures from senders. `_smtp._tls.example.com TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"`.
- **DANE for SMTP** (RFC 7672, TLSA RFC 6698): pins the MX certificate in DNS, e.g. `_25._tcp.mx1.example.com TLSA 3 1 1 <sha256-of-spki>`. Requires DNSSEC on the MX zone. Publish the next key's TLSA record before rolling certificates.
- **BIMI** (BIMI Group specification, not an RFC): shows your logo in supporting clients. `default._bimi.example.com TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"`. Needs DMARC at enforcement (`quarantine`/`reject`); Gmail also needs a mark certificate (VMC or CMC). BIMI is a brand feature, not a security control.

### Gmail / Yahoo bulk sender requirements (from February 2024)
- **All senders**: SPF or DKIM, valid forward and reverse DNS (PTR) for sending IPs, TLS for transmission, and a spam complaint rate below 0.3% (Google Postmaster Tools).
- **Bulk senders** (Google: about 5,000+ messages/day to Gmail accounts) must also have:
  - both SPF and DKIM
  - a DMARC record (at least `p=none`) with the `From:` domain aligned with SPF or DKIM
  - one-click unsubscribe for marketing mail (`List-Unsubscribe` + `List-Unsubscribe-Post`, RFC 8058), honored within 2 days

### Mail gateway and platform controls
- Anti-spoofing: enforce inbound DMARC. Flag display names that match executives or vendors but come from external addresses.
- **Lookalike detection**: alert on newly registered domains and close edit-distance or homoglyph matches. Defensively register key typos.
- **Link rewriting / time-of-click scanning** (e.g., Defender Safe Links, Proofpoint URL Defense): re-checks the URL at click time, catches links weaponized after delivery.
- **Sandboxing** (detonate attachments and links). Block or quarantine risky types: `.iso .img .vhd .lnk .hta .js .vbs .wsf`, macro documents from the internet, encrypted archives from unknown senders. Strip or inspect HTML attachments.
- QR codes: use gateways that decode QR images. Treat a QR code from an unknown sender as a link.
- **External sender banner** or tag (e.g., Exchange Online `Set-ExternalInOutlook -Enabled $true`). Keep it short so users do not learn to ignore it.
- Block automatic external forwarding by default. Alert on new inbox rules that forward, delete or move mail to RSS/Archive folders.
- OAuth: disable user consent to unverified apps, use an admin-consent workflow, and review grants regularly (see `kb/05-identity-crypto/identity-access.md`).
- Retire legacy authentication (POP/IMAP/SMTP AUTH with basic auth).

### People and process
- **Phishing-resistant MFA** (FIDO2/passkeys, smart cards) for email and IdP. OTP and push are bypassed by AitM kits. Add conditional access (device compliance, token binding where available).
- **Report button** in the mail client that sends to a triage mailbox or SOAR. Give fast feedback, auto-pull the same message from all inboxes, and measure report rate, not just click rate.
- **Training**: short, frequent, role-based (finance, HR, executives, assistants). Simulations should teach, not punish.
- **BEC payment-verification process** (written, mandatory, no exceptions for urgency or seniority):
  1. Any new payee or change of bank details is verified by **call-back to a number already on file**, never one from the email.
  2. Dual approval above a threshold. Separate the person who requests from the person who releases.
  3. Hold period for first payments to changed accounts. Bank confirmation of payee/account-name checks where available.
  4. Treat urgency, secrecy, "I'm in a meeting" and gift-card requests as red flags.
  5. Suspected fraud: call the bank to recall the transfer immediately, then follow the BEC playbook in `kb/08-defensive/soc-detection-ir.md`.

## How to verify
```bash
dig +short TXT example.com | grep spf1                 # exactly one record, ends -all/~all
dig +short TXT _dmarc.example.com                      # p=quarantine|reject, rua present
dig +short TXT s2026a._domainkey.example.com           # selector from a real message's DKIM-Signature s=
dig +short TXT _mta-sts.example.com
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt   # mode: enforce, mx lines match MX
dig +short TXT _smtp._tls.example.com
dig +dnssec TLSA _25._tcp.mx1.example.com              # if using DANE
openssl s_client -starttls smtp -connect mx1.example.com:25 -servername mx1.example.com </dev/null
```
- Count SPF lookups (include tree) with an SPF checker; it must stay ≤ 10.
- Send a test message to a mailbox you control. Check `Authentication-Results:` for `spf=pass`, `dkim=pass header.d=example.com`, `dmarc=pass`.
- **DMARC aggregate reports**: reports arrive as gzip/zip XML. Read them with a parser (e.g., the open-source `parsedmarc`) or a DMARC reporting service, or quickly:
  ```bash
  zcat report.xml.gz | xmllint --format - | grep -E "source_ip|<count>|disposition|<dkim>|<spf>"
  ```
  For each `source_ip` (e.g., `198.51.100.25`), decide whether it is legitimate. Fix SPF/DKIM for legitimate sources; unknown sources failing DMARC are spoofing, which enforcement blocks.
- Review TLS-RPT reports for failed sessions before switching MTA-STS to `enforce`.
- Gateway: test with harmless samples (EICAR file, a test URL that is benign but flagged), and confirm the external banner, link rewriting and the report button work.
- Process: run a BEC tabletop or simulated payment-change request against finance and check that the call-back step happens.

## References
- [RFC 7208 (SPF)](https://www.rfc-editor.org/rfc/rfc7208) · [RFC 6376 (DKIM)](https://www.rfc-editor.org/rfc/rfc6376) · RFC 8301 / RFC 8463 (DKIM crypto) · [RFC 7489 (DMARC)](https://www.rfc-editor.org/rfc/rfc7489) · RFC 8617 (ARC)
- RFC 8461 (MTA-STS) · RFC 8460 (TLS-RPT) · RFC 7672 / RFC 6698 (DANE/TLSA) · RFC 7505 (null MX) · RFC 8058 (one-click unsubscribe)
- Google "Email sender guidelines" · Yahoo "Sender best practices" · BIMI Group specification
- M3AAWG best practices · CISA BOD 18-01 · UK NCSC email security guidance · FBI IC3 BEC public service announcements
- MITRE ATT&CK T1566 (Phishing), T1027.006 (HTML Smuggling), T1528 (Steal Application Access Token)
- See also `kb/02-network/wireless-dns-ddos.md`, `kb/05-identity-crypto/identity-access.md`, `kb/08-defensive/soc-detection-ir.md`, `kb/10-emerging/iot-ot-social-physical.md`
