# Attack Surface Management

## What
**Attack surface management (ASM)** is the continuous discovery, inventory, classification and reduction of everything an attacker could reach: domains and subdomains, IP ranges, internet-facing services and edge devices, cloud accounts and storage, SaaS tenants, APIs, code repositories, leaked credentials and third-party-hosted assets. **External ASM (EASM)** looks from the internet inward, as an attacker's reconnaissance would. ASM feeds vulnerability management (`kb/09-governance/vulnerability-management.md`): you cannot scan or patch what is not in the inventory. Continuous Threat Exposure Management (CTEM, a Gartner framing) wraps it in a cycle of scoping, discovery, prioritization, validation and mobilization.

## Why it matters
- **Unknown assets are unpatched assets**: forgotten test servers, acquired companies' domains, shadow-IT SaaS and old marketing sites sit outside scanning and patching.
- **Edge devices are a leading initial-access path**: VPNs, firewalls, file-transfer appliances and remote-access gateways appear repeatedly in CISA's Known Exploited Vulnerabilities catalog, and attackers mass-scan for them soon after disclosure.
- **Attackers inventory you anyway**: certificate transparency logs, passive DNS, search engines for internet-connected devices and public code hosts give anyone a map of your exposure (MITRE ATT&CK Reconnaissance, TA0043).
- **Cloud changes fast**: a single developer can expose a storage bucket, database or admin port in minutes; point-in-time inventories go stale quickly.
- **Requirements**: CIS Controls 1 and 2 (enterprise and software asset inventory), NIST CSF 2.0 ID.AM, and for US federal agencies CISA BOD 23-01 (automated asset discovery and vulnerability enumeration on a fixed cadence).

## Attacks
*Attacker reconnaissance and the exposures it finds. Each pattern lists its main defense.*

| Exposure / technique | How it is found or abused | Defense |
|---|---|---|
| Subdomain enumeration | Certificate transparency logs (crt.sh), passive DNS, brute force and search engines list hostnames you forgot | Enumerate the same way yourself; every hostname has an owner or is removed; wildcard certificates hide names from CT but do not hide the hosts |
| Subdomain takeover | DNS CNAME points to a deprovisioned cloud resource (storage site, app service, CDN) that an attacker re-registers | Delete DNS records before resources; scan for dangling records (`kb/02-network/wireless-dns-ddos.md`) |
| Exposed admin and management interfaces | Internet scanning finds RDP, SSH, database ports, Kubernetes API, CI servers, router and hypervisor admin pages | No management interfaces on the internet; access via VPN, bastion or identity-aware proxy (`kb/01-foundations/zero-trust-architecture.md`) |
| Vulnerable edge devices | Mass scanning for a newly disclosed VPN or firewall flaw within days of disclosure | Inventory every edge device with version; treat KEV entries on them as emergencies; vendor end-of-life devices replaced |
| Forgotten and staging environments | `dev.`, `test.`, `old.` hosts with default credentials, debug modes or outdated software | Owner and expiry for every non-production environment; restrict by IP or SSO; auto-decommission |
| Public cloud storage and data stores | Listing or reading public buckets, open databases and search clusters | Account-level public-access blocks; CSPM rules; regular external checks (`kb/04-cloud-infra/cloud-security.md`) |
| Leaked secrets and code | Public repositories, paste sites, package registries and container images containing keys or internal hostnames | Secret scanning on public and private code, revoke and rotate on discovery (`kb/05-identity-crypto/secrets-management.md`) |
| Exposed APIs and documentation | Public OpenAPI/Swagger files, GraphQL introspection, old API versions still live | API inventory with versions and owners; retire old versions (`kb/03-application/api-security.md`) |
| Shadow IT and SaaS | Teams sign up for SaaS with corporate email; data and SSO sit outside governance | SaaS discovery from SSO, expense and email signals (`kb/04-cloud-infra/saas-security.md`) |
| Third-party and acquired assets | Agencies, vendors and acquisitions host your brand or data on infrastructure you do not monitor | Include them in scope by contract; integrate acquisition assets on day one (`kb/09-governance/third-party-risk-management.md`) |
| Lookalike domains | Typosquats used for phishing or credential harvesting | Monitor new registrations and CT for lookalikes; register key variants; DMARC on all domains (`kb/02-network/email-security.md`) |

## Defenses

### 1. Build the seed inventory
- Collect authoritative sources: registrar accounts and domain list, DNS zones, IP allocations and ASNs (RDAP), cloud accounts/subscriptions/projects, CDN and WAF configurations, SaaS tenants from the IdP, code organizations, certificates issued (CT).
- Record for each asset: owner (team, not a person), business service, environment, data sensitivity, internet exposure, and source of discovery.
- Feed the inventory into the CMDB or asset system the vulnerability program already uses; one inventory, not one per tool.

### 2. Discover continuously
- Run discovery on a fixed cadence and on change events: CT log monitoring for your domains, DNS enumeration, port and service scanning of owned ranges, cloud API inventory of public IPs, load balancers, buckets and functions.
- Use internet-wide scan datasets (for example Shodan or Censys) and an EASM product or open-source tooling (OWASP Amass, subfinder, httpx, nuclei) to see what an attacker sees; scan only assets you own or are authorized to test.
- Compare discovered assets with the inventory: unknown assets go to triage, inventory assets that no longer resolve are retired.

### 3. Prioritize and reduce
- Prioritize by exposure plus exploitability plus business impact: internet-facing, KEV-listed or remotely exploitable flaws on high-value assets first (`kb/09-governance/vulnerability-management.md`).
- Reduce the surface, not just patch it: remove unused hosts, close ports, put admin interfaces behind identity-aware access, retire old API versions and domains.
- Default-deny for new exposure: cloud guardrails (organization policies, SCPs) that block public storage, public database endpoints and wide-open security groups unless an approved exception exists, with an expiry.
- Validate high-risk findings (is it really reachable and exploitable?) with safe checks or authorized testing before escalation, and re-test after the fix (`kb/07-offensive/pentest-methodology.md`).

### 4. Ownership and process
- Every asset has an owner; unowned assets get a deadline to be claimed or are shut down.
- Fold ASM findings into the existing ticketing, SLA and exception process (`templates/vulnerability-finding.md`), with evidence and an exception expiry.
- Hook decommissioning into change management: DNS, certificates, cloud resources and firewall rules removed together.
- Publish `/.well-known/security.txt` (RFC 9116) so outsiders who find exposures can report them (`templates/SECURITY.md`).

### 5. Metrics
Report with explicit denominators: share of discovered assets with an owner, unknown assets found per period and time to triage, internet-exposed management interfaces (target zero), KEV exposures on internet-facing assets and time to remediate, dangling DNS records.

## How to verify
- Pull certificates for your domains from crt.sh (`https://crt.sh/?q=%25.example.com`) and confirm every hostname is in the inventory with an owner.
- Compare cloud public IPs and load balancers from each account's API with the external scan scope; any gap is a finding.
- Run an authorized external port scan of owned ranges; every open port maps to an approved service, and no management protocol (RDP, SSH, database, Kubernetes API) is open to the internet without an exception.
- Check for dangling CNAMEs and unclaimed cloud endpoints on your domains.
- Pick a recently decommissioned system and confirm its DNS, certificates, firewall rules and cloud resources are gone.
- Search public code hosts and your secret-scanning alerts for your domains and key prefixes; confirm findings were rotated.
- Confirm `https://<domain>/.well-known/security.txt` exists, is current and has a valid `Expires` field.

## References
- CISA BOD 23-01, Improving Asset Visibility and Vulnerability Detection on Federal Networks: https://www.cisa.gov/news-events/directives/bod-23-01-improving-asset-visibility-and-vulnerability-detection-federal-networks
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA Cyber Hygiene Services (free external vulnerability scanning for eligible organizations): https://www.cisa.gov/cyber-hygiene-services
- CIS Critical Security Controls v8, Controls 1 and 2: https://www.cisecurity.org/controls
- NIST Cybersecurity Framework 2.0 (ID.AM asset management): https://www.nist.gov/cyberframework
- MITRE ATT&CK Reconnaissance (TA0043), incl. T1595 Active Scanning and T1596 Search Open Technical Databases: https://attack.mitre.org/tactics/TA0043/
- RFC 9162, Certificate Transparency Version 2.0: https://www.rfc-editor.org/rfc/rfc9162
- RFC 9116, security.txt: https://www.rfc-editor.org/rfc/rfc9116
- Microsoft, Prevent dangling DNS entries and avoid subdomain takeover: https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover
- Tools: crt.sh https://crt.sh/, OWASP Amass https://github.com/owasp-amass/amass, subfinder https://github.com/projectdiscovery/subfinder, httpx https://github.com/projectdiscovery/httpx, nuclei https://github.com/projectdiscovery/nuclei
- See also `kb/09-governance/vulnerability-management.md`, `kb/02-network/wireless-dns-ddos.md`, `kb/04-cloud-infra/cloud-security.md`, `kb/07-offensive/pentest-methodology.md`, `kb/09-governance/third-party-risk-management.md`, `kb/02-network/edge-device-security.md`
