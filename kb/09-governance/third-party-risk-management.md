# Third-Party and Vendor Risk Management

## What
**Third-party risk management (TPRM)** is the process of finding, assessing, contracting for, monitoring and exiting the suppliers that handle your data, connect to your systems or deliver services you depend on: SaaS and cloud providers, managed service providers (MSPs), software vendors, contractors, payment and data processors, and their own suppliers (**fourth parties**). NIST calls the wider discipline **cybersecurity supply chain risk management (C-SCRM)**; NIST CSF 2.0 makes it a Govern category (GV.SC). This file covers the vendor lifecycle. Software component risk (SBOM, signing, dependencies) is in `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, and technical controls inside SaaS tenants are in `kb/04-cloud-infra/saas-security.md`.

## Why it matters
- One supplier can affect many customers at once. Examples: the 2023 mass exploitation of MOVEit Transfer (CVE-2023-34362) by the Cl0p group exposed data of organizations that never ran the product themselves, through their payroll, benefits and other service providers (CISA AA23-158A); the 2021 Kaseya VSA ransomware attack spread through MSPs to their customers; the 2020 SolarWinds Orion compromise delivered a backdoor through a signed update.
- Availability risk is third-party risk too: the faulty CrowdStrike Falcon content update of 19 July 2024 crashed Windows hosts worldwide, with no attacker involved.
- You keep the accountability. Regulations and frameworks place obligations on the buyer: GDPR controller-processor contracts, HIPAA business associate agreements, PCI DSS service provider management, and EU DORA, which requires financial entities to keep a register of information on ICT third-party arrangements (`kb/09-governance/grc-compliance-privacy.md`).
- Vendors often hold standing access (VPN accounts, OAuth grants, API keys, remote support tools) that bypasses your own controls and is rarely reviewed.

## Attacks
*Each pattern lists its main defense.*

| Attack / failure | Example | Defense |
|---|---|---|
| Vendor breach exposing your data | Processor's file-transfer server exploited; your customer records stolen | Data minimization, contract breach-notification terms, encryption, knowing which vendors hold which data |
| Compromised MSP or remote-support access | Attacker uses the MSP's RMM tool or shared admin accounts to reach every client | Named, MFA-protected vendor accounts, just-in-time access, session recording, separate RMM per client, alerting on vendor sessions |
| Malicious or compromised software update | Backdoored signed update from a trusted vendor | Staged rollout, egress restrictions for servers, vendor secure-development attestations, behavior monitoring |
| Stolen integration credentials | Vendor's OAuth tokens or API keys used against customer tenants | Least-privilege scopes, IP restrictions, token inventory, revocation runbook (`kb/05-identity-crypto/oauth-oidc-security.md`) |
| Vendor-induced outage | Bad update or cloud region failure takes down a critical service | Business impact analysis, tested fallbacks, staged deployment rings, exit and continuity plans |
| Shadow vendors | Teams buy SaaS or AI tools with a card; no review, no DPA | Procurement and expense controls, SSO/OAuth discovery, an easy fast-track review path |
| Fourth-party concentration | Many suppliers depend on the same hosting provider or subprocessor | Ask for subprocessor lists, map concentration, plan for the shared dependency failing |
| Paper compliance | Questionnaire answered "yes" to everything; certificate scope excludes the service you buy | Evidence over self-attestation, check report scope and period, validate key controls technically |

## Defenses

### 1. Inventory and tiering
- One inventory of third parties, built from procurement, accounts payable, contracts, SSO and OAuth app lists, firewall/VPN vendor accounts and DNS/proxy logs. Record owner, service, data types, access type, criticality and subprocessors.
- Tier by **impact**: the data the vendor holds or processes, the access it has into your environment, and how critical the service is to operations. Example tiers (adapt to your risk appetite): tier 1 for restricted data, privileged network access or critical services; tier 2 for confidential data or limited access; tier 3 for no data and no access.
- The tier decides the depth of review, contract terms and monitoring frequency.

### 2. Due diligence before contract
- Proportionate to tier. Reuse standard instruments instead of bespoke questionnaires: Shared Assessments SIG, CSA CAIQ and the STAR registry for cloud providers, and for software vendors the CISA/FBI Secure by Demand questions and the CISA Software Acquisition Guide.
- Prefer independent evidence: SOC 2 Type II reports (check the period, the systems in scope, exceptions and the **complementary user entity controls** you must operate yourself), ISO/IEC 27001 certificates with their statement of applicability scope, penetration test summaries, PCI DSS attestations of compliance for card processing.
- For software products ask for an SBOM, a vulnerability disclosure policy, secure-by-default settings (MFA available without extra cost, logging included) and the support and patching commitments.
- Validate a few key controls technically for tier 1: SSO and MFA support, encryption, data location, log export, admin access model, external attack-surface scan of the vendor's exposed service.
- Record residual risks and accepted exceptions with an owner and an expiry date (`templates/vulnerability-finding.md`).

### 3. Contract terms
- Security requirements and the right to evidence or audit; notice of material changes and of new subprocessors.
- Incident notification within a defined time after discovery, with cooperation duties and named contacts. Set the period to meet your own regulatory deadlines.
- Data protection: DPA/BAA where required, data location, encryption, retention, return and certified deletion at exit.
- Access rules: named accounts, MFA, least privilege, logging of vendor actions, prohibition of sharing credentials.
- Vulnerability handling: timeframes for fixing vulnerabilities in the product or service, and notification of exploited ones.
- Service levels, continuity and disaster recovery commitments, and exit assistance.

### 4. Technical controls on vendor access
- Vendor users go through your IdP with phishing-resistant MFA where possible, or a privileged access gateway with session recording; no shared accounts (`kb/05-identity-crypto/identity-access.md`).
- Just-in-time, time-boxed access approved per task; network access limited to the systems needed (`kb/01-foundations/zero-trust-architecture.md`).
- Integrations get dedicated non-human accounts with minimal scopes, an owner and an expiry; review grants at least quarterly.
- Send vendor-session and integration activity to the SIEM and alert on unusual times, volumes or targets.

### 5. Ongoing monitoring
- Re-assess on a schedule set by tier (for example annually for tier 1) and when the service, data or access changes.
- Track vendor security incidents and advisories (vendor status pages, CISA KEV for products you run, news and breach notifications).
- Security ratings and attack-surface services can flag changes, but they see only the outside of the vendor and produce false positives; use them as a trigger for questions, not as a risk verdict.
- Map concentration: which critical services depend on the same provider or subprocessor.

### 6. Incident and exit
- Keep a runbook for "vendor X is breached": which data and access they have, how to revoke their accounts, tokens and VPN access, who decides on notification, and how to rotate shared secrets (`kb/08-defensive/soc-detection-ir.md`).
- Plan exit for tier 1 vendors before signing: data export format, transition time, alternative provider or manual fallback.
- At contract end: revoke every account, token and network path, retrieve data and get written confirmation of deletion.

## How to verify
- Reconcile the vendor inventory against accounts-payable records, SSO app lists and OAuth grants; anything paid or connected but not in the inventory is a finding.
- Sample tier 1 vendors: a current assessment exists, evidence is in date (SOC 2 period, certificate expiry), exceptions have owners and unexpired dates, and the contract contains the incident-notification and deletion clauses.
- List all vendor accounts and integrations in the IdP, VPN and PAM tools; each maps to an active contract, an owner and MFA, and none is unused for longer than the agreed limit.
- Run a tabletop for a tier 1 vendor breach: measure the time to identify affected data and to revoke the vendor's access.
- Check offboarding: for vendors terminated in the last period, confirm accounts, tokens and firewall rules are gone and deletion confirmation is on file.

## References
- NIST SP 800-161 Rev. 1 (Update 1, November 2024), Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations: https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final
- NIST Cybersecurity Framework 2.0 (GV.SC, Cybersecurity Supply Chain Risk Management): https://www.nist.gov/cyberframework
- CISA and FBI, Secure by Demand Guide (August 2024): https://www.cisa.gov/news-events/alerts/2024/08/06/cisa-releases-secure-demand-guidance
- CISA AA23-158A, CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
- ISO/IEC 27036 series, Cybersecurity – Supplier relationships (ISO/IEC standard, multi-part)
- Cloud Security Alliance, STAR Registry and CAIQ: https://cloudsecurityalliance.org/star
- Shared Assessments, Standardized Information Gathering (SIG) questionnaire: https://sharedassessments.org/sig/
- EU Regulation 2022/2554 (DORA), Chapter V ICT third-party risk: https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- See also `kb/09-governance/grc-compliance-privacy.md`, `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/04-cloud-infra/saas-security.md`, `kb/08-defensive/insider-threat.md`, `kb/03-application/browser-extension-security.md`
