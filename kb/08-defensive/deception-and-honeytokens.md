# Deception and Honeytokens

## What
**Cyber deception** plants assets that no legitimate user or process should ever touch, so any interaction with them is a high-confidence alert. Forms:
- **Honeytokens / canary tokens**: fake credentials, API keys, documents, URLs, DNS names, database rows or email addresses that alert when used or opened.
- **Decoy accounts**: directory or cloud identities that look valuable (an "admin" or service account) but are never used.
- **Honeypots**: decoy hosts or services. Low-interaction ones emulate a login prompt or a port; high-interaction ones are real systems instrumented to watch an attacker.
- **Breadcrumbs**: lures (saved connections, config files, cached credentials) that point attackers toward the decoys.

MITRE Engage is the reference framework for planning adversary engagement, deception and denial; MITRE D3FEND lists **Deceive** as a defensive tactic; NIST SP 800-160 Vol. 2 Rev. 1 includes deception among its cyber resiliency techniques.

## Why it matters
- Detection rules on normal activity produce false positives and miss attackers who use valid accounts and built-in tools (living off the land). A decoy has no legitimate use, so a touch on it is a strong signal with little tuning.
- Attackers routinely search for credentials in files, code, browsers and memory and enumerate the directory; honeytokens sit exactly where that searching happens, which gives early detection of discovery and lateral movement (`kb/08-defensive/soc-detection-ir.md`).
- Leaked-secret detection: a unique token placed in a repository, a backup or a vendor-shared document tells you which copy leaked and when it was used.
- It is cheap to start: a fake AWS key in a config file or a decoy AD account needs no agents.

## Attacks
*How attackers find or defeat deception, for authorized testing only. Each item lists the defense.*
- **Fingerprinting decoys**: default banners, honeypot software signatures, hostnames like `honeypot01`, or empty systems with no history. Defense: names and content that match your real estate, realistic activity and age, varied configurations, no default vendor artifacts.
- **Identifying public canary services**: TruffleHog research showed that AWS keys from the free canarytokens.org service can be recognized statically by their AWS account IDs without triggering them. Defense: self-hosted or commercial token infrastructure for high-value placements, and tokens from your own cloud accounts.
- **Avoiding lures**: careful attackers use only credentials they observed in use. Defense: put decoys where real attacker tooling looks (Kerberoastable SPNs, LSASS-cached credentials, password-manager exports, `.aws/credentials`, CI variables), not only in obvious "passwords.txt" files.
- **Pivoting from a high-interaction honeypot**: a compromised decoy becomes a launch point. Defense: isolate honeypots in their own segment with egress blocked or tightly filtered, no trust relationships, no real credentials, monitoring of the honeypot itself.
- **Alert flooding**: an attacker who spots tokens triggers many to bury real activity. Defense: alert enrichment and grouping by source, rate limits per token, and treating any trigger as an incident lead.
- **Self-inflicted false alarms**: backup jobs, vulnerability scanners, EDR, search indexers and admins open the decoys. Defense: document exclusions at the source (scanner IPs, backup service accounts), place file tokens where indexers do not reach, and inform the few people who must know.

## Defenses

### 1. Plan
- Start from the threat model (`kb/01-foundations/threat-modeling.md`): which ATT&CK techniques you most need to catch early (credential access, discovery, lateral movement, exfiltration), and which assets attackers would target.
- Decide the response for each decoy before deploying: who receives the alert, what triage happens, and when it becomes an incident.
- Keep the deployment inventory (what, where, owner, alert route) in a restricted place; treat it as sensitive.
- Get legal and privacy review for internet-facing honeypots and for anything that records attacker data; deception is for detection and research on your own systems, never for "hacking back".

### 2. Placements that pay off
| Placement | Signal | Notes |
|---|---|---|
| Fake cloud access key in developer configs, CI variables, golden images, backups | Use of the key (seen in the provider's audit log, e.g. AWS CloudTrail) | Key with no permissions in an isolated account; alert on any API call |
| Decoy AD user with an SPN (honey Kerberoast) | Event 4769 service ticket request for that SPN | Long random password, no group memberships with access; any request is Kerberoasting (`kb/05-identity-crypto/active-directory-security.md`) |
| Decoy privileged-looking account (directory or IdP) | Any authentication attempt (4625/4624/4768, IdP sign-in logs) | Disabled interactive logon where possible; monitor for password spray hits |
| Canary documents and file shares | Document opened or share accessed (token callback, 4663 file access auditing) | Name them like real finance/HR data |
| Database canary rows or fake customer records | Row read in query logs, or the fake email/phone receives contact | Detects bulk exports and leaked dumps (`kb/04-cloud-infra/database-security.md`) |
| Unique canary URL or DNS name in internal wikis, password-manager entries, source code | DNS resolution or HTTP request from anywhere | Works even after data leaves the network |
| Low-interaction honeypot (SSH, RDP, SMB, admin web UI) in user and server segments | Any connection | Internal decoys see little legitimate traffic, so connections are meaningful |
| Fake mailbox or email address in contact lists | Inbound mail to it | Detects address harvesting and leaked lists |

### 3. Integrate with detection and response
- Send every trigger to the SIEM/SOAR with the context of what was touched, from where, and by which account; map each decoy to the ATT&CK technique it detects.
- Tier the response: a decoy credential being used is treated as a confirmed intrusion lead, not an informational event.
- Pair deception with normal telemetry: the decoy tells you something is wrong; EDR, identity and network logs tell you how far it went (`kb/08-defensive/dfir-malware-threat-intel.md`).

### 4. Maintain
- Refresh decoys as the estate changes so they keep looking real; remove ones whose context is gone.
- Review each decoy's alerting path after every SIEM, log pipeline or IdP change.
- Track metrics: decoy coverage per segment and identity tier, alert-path test pass rate, mean time from trigger to triage.

## How to verify
- For each decoy type, trigger it in a controlled test (use the fake key from an approved host, request a service ticket for the honey SPN, open a canary document) and confirm the alert arrives at the right queue with usable context within the expected time. Repeat on a schedule and after pipeline changes.
- Include deception in purple-team exercises (`kb/07-offensive/red-team-and-bug-bounty.md`): record which decoys the red team touched, which alerts fired, and how long triage took.
- Check the false-positive log: every non-attacker trigger needs a root cause and either an exclusion or a moved decoy.
- Confirm honeypot isolation: from the honeypot, attempts to reach production segments and the internet are blocked and logged.
- Confirm decoy accounts have no effective privileges (BloodHound or IdP role reports, authorized use).

## References
- MITRE Engage: https://engage.mitre.org/
- MITRE D3FEND (Deceive tactic): https://d3fend.mitre.org/
- NIST SP 800-160 Vol. 2 Rev. 1, Developing Cyber-Resilient Systems: https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final
- Thinkst, Canarytokens' new member: AWS API key Canarytoken (2017): https://blog.thinkst.com/2017/09/canarytokens-new-member-aws-api-key.html
- Thinkst, A "Safety Net" for AWS Canarytokens (2022): https://blog.thinkst.com/2022/02/a-safety-net-for-aws-canarytokens.html
- Canarytokens (open source, self-hostable): https://github.com/thinkst/canarytokens
- Microsoft Learn, Event 4769 (A Kerberos service ticket was requested): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- MITRE ATT&CK T1558.003 (Kerberoasting), T1552 (Unsecured Credentials), T1087 (Account Discovery)
- See also `kb/08-defensive/soc-detection-ir.md`, `kb/05-identity-crypto/active-directory-security.md`, `kb/02-network/network-security.md`
