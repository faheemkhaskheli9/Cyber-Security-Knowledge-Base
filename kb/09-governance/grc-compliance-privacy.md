# Governance, Risk, Compliance & Privacy

## What
- **Governance**: who decides, who is accountable and how security is directed (board oversight, CISO mandate, policies, metrics).
- **Risk management**: identify assets → threats/vulns → likelihood × impact → treat (mitigate/transfer/avoid/accept) → monitor.
- **Compliance**: showing, with evidence, that you meet external obligations (laws, contracts, certifications).
- **Privacy**: lawful, minimal and transparent handling of personal data. Security protects data; privacy decides whether you should hold it at all.

| Role | Accountability |
|------|----------------|
| Board / executive committee | Sets risk appetite, approves the program, receives risk reporting (NIS2 and DORA make management bodies personally accountable) |
| CISO / security lead | Runs the program, owns the policy set, reports residual risk |
| DPO (GDPR Art. 37–39, where required) | Independent privacy advice, DPIAs, contact point for the regulator |
| Risk owners (business) | Accept or fund treatment of risks in their area |
| Control owners | Operate controls and produce evidence |
| Internal audit (3rd line) | Independent assurance that controls work |

## Why it matters
- Fines are significant: GDPR up to €20M or 4% of worldwide annual turnover (whichever is higher); NIS2 up to €10M or 2% for essential entities.
- Customers and partners require SOC 2 reports or ISO 27001 certificates before signing contracts.
- Without a risk register, security spend follows the loudest voice instead of the largest risk.
- Regulators now judge *timeliness*: late breach notification is a separate violation from the breach itself.

## Attacks
Common governance and compliance failures (each has caused fines or failed audits):
- **Checkbox compliance**: policies exist but are not operated; certificate held, controls not working ("compliant but breached").
- **Scope games**: certifying a small slice (one data center, one product) and implying it covers the whole company.
- **Stale risk register**: no owners, no review dates, risks "accepted" by people without authority.
- **Shadow vendors / SaaS**: personal data sent to processors with no DPA, no security review, no exit plan.
- **Missed notification clocks**: no one knows the GDPR 72 h or NIS2 24 h trigger; legal learns about the breach days later.
- **Over-collection and indefinite retention**: data you never needed becomes breach impact.
- **Unhandled DSARs**: requests lost in a support queue past the legal deadline.
- **Evidence scramble**: screenshots gathered once a year before the audit; controls drift in between.
- **Exceptions without expiry**: risk acceptances and patch exceptions that never get revisited.

## Defenses
### Risk management
Process (ISO/IEC 27005, NIST RMF / SP 800-37, SP 800-30 for assessments, FAIR for quantitative):
1. Define context and risk appetite (approved by leadership).
2. Inventory assets and data flows (see `kb/01-foundations/threat-modeling.md`).
3. Assess likelihood × impact; quantify with FAIR where money decisions need it.
4. Treat: **mitigate** (controls), **transfer** (insurance, contracts), **avoid** (stop the activity), **accept** (signed by an authorized risk owner, with expiry).
5. Monitor, re-assess on change and at least annually.

Risk register columns: `ID | Asset/process | Threat & vulnerability | Inherent likelihood | Inherent impact | Existing controls | Residual rating | Treatment | Owner | Due date | Status | Review date | Linked incidents/findings`.

### Frameworks & regulations
| Standard | Applies to | Type | Key obligations |
|----------|-----------|------|-----------------|
| ISO/IEC 27001:2022 / 27002 | Any org (voluntary) | Certifiable ISMS | ISMS clauses 4–10, risk assessment, Statement of Applicability; Annex A has 93 controls in 4 themes |
| SOC 2 (AICPA) | Service organizations (US-centric) | Attestation report | Trust Services Criteria: Security (required), Availability, Processing Integrity, Confidentiality, Privacy. Type I = design at a point in time; Type II = operating effectiveness over a period |
| NIST CSF 2.0 (2024) | Any org (voluntary) | Outcome framework | Functions: Govern, Identify, Protect, Detect, Respond, Recover; profiles and tiers |
| NIST SP 800-53 Rev. 5 / 800-171 | US federal systems / contractors handling CUI | Control catalog | Baselines (Low/Moderate/High); 800-171 for CUI, basis of CMMC |
| CIS Controls v8 | Any org | Prioritized controls | Implementation Groups IG1–IG3 |
| PCI DSS 4.0 (4.0.1) | Anyone storing, processing or transmitting card data | Contractual standard | 12 requirements; future-dated requirements mandatory since 31 Mar 2025 (e.g. MFA for all CDE access, script integrity on payment pages) |
| HIPAA | US covered entities and business associates | Law | Privacy, Security and Breach Notification Rules; BAAs with vendors |
| GDPR / UK GDPR | Processing personal data of people in the EU/UK | Law | Lawful basis, data subject rights, DPIA, records of processing, DPAs, 72 h breach notice |
| CCPA / CPRA | Businesses meeting California thresholds | Law | Notice, right to know/delete/correct, opt-out of sale/sharing, sensitive-data limits |
| EU NIS2 | Essential and important entities in listed sectors | Directive (national laws) | Risk-management measures, supply-chain security, management accountability, staged incident reporting |
| EU DORA (applies from 17 Jan 2025) | EU financial entities and critical ICT providers | Regulation | ICT risk framework, incident reporting, resilience testing (TLPT for some), ICT third-party register |
| EU AI Act (in force Aug 2024, phased) | Providers/deployers of AI systems in the EU | Regulation | Prohibited practices, high-risk system obligations, GPAI transparency; dates phase in 2025–2027, check current status |
| EU Cyber Resilience Act (in force Dec 2024) | Products with digital elements sold in the EU | Regulation | Secure-by-design, SBOM, vulnerability handling and support period; exploited-vuln reporting from Sept 2026, main obligations from Dec 2027 |
| CMMC, FedRAMP | US defense supply chain / cloud for US government | Certification / authorization | 800-171 / 800-53-based assessments |

Map controls once to many frameworks (common control framework) instead of running separate programs.

### Minimal policy set
Information security policy (top-level, board-approved) · acceptable use · access control and password/MFA · data classification and handling · incident response · backup/DR and business continuity · vendor/third-party risk · change management · secure development · vulnerability and patch management · logging and monitoring · BYOD/remote work · privacy notice and retention schedule. Each: owner, version, annual review, exceptions process.

### Data classification
| Level | Examples | Minimum handling |
|-------|----------|-----------------|
| Public | Marketing site | Integrity controls |
| Internal | Org charts, wikis | SSO, no public sharing |
| Confidential | Customer data, contracts, source code | Need-to-know, encryption at rest/in transit, DLP |
| Restricted | Credentials, card data, health data, special-category data | Strong isolation, MFA, logging of all access, tokenization |

### Third-party risk
1. Inventory all vendors and SaaS (include OAuth apps and AI tools); tier by data access and criticality.
2. Due diligence proportional to tier: SOC 2 Type II / ISO certificate review, questionnaire (SIG, CAIQ), pentest summary.
3. Contract: DPA, security clauses, breach notice timeline, right to audit, subprocessor list, exit/data return.
4. Monitor: annual re-review for critical vendors, track their breaches, offboard and revoke access at contract end.

### Privacy engineering (privacy by design)
- Data minimization, purpose limitation, consent where it is the lawful basis, retention schedules with automated deletion.
- DPIA for high-risk processing (new tech, large-scale special-category data, monitoring).
- Pseudonymization/anonymization, encryption (`kb/05-identity-crypto/cryptography.md`), vendor DPAs.
- Privacy-friendly defaults (opt-in, shortest retention, least visibility).
- **DSARs**: verify identity, search all systems (including backups and logs per policy), respond within GDPR 1 month (extendable by two further months for complex requests) or CCPA 45 days (extendable once by 45). Keep a request log.

### Breach notification timelines
| Regime | Who to notify | Deadline |
|--------|---------------|----------|
| GDPR | Supervisory authority | Within 72 h of becoming aware (unless unlikely to result in risk) |
| GDPR | Data subjects | Without undue delay if high risk |
| NIS2 | CSIRT / competent authority | Early warning 24 h, notification 72 h, final report within 1 month |
| HIPAA | Individuals; HHS; media if 500+ in a state | Without unreasonable delay, no later than 60 days of discovery |
| DORA | Financial supervisor | Staged initial/intermediate/final reports for major ICT incidents (short deadlines set in technical standards) |
| US SEC (public companies) | Investors (Form 8-K) | 4 business days after determining an incident is material |
| US states | Residents / AGs | Varies by state; check each |

Pre-draft templates and a decision tree in the IR plan (`kb/08-defensive/soc-detection-ir.md`).

### Vulnerability management
Asset inventory → scan (Nessus, OpenVAS, Qualys, Trivy) → prioritize (CVSS + EPSS + KEV + asset criticality) → remediate with SLAs (e.g. Critical 7d, High 30d) → verify → report. Patch management, exception process. Detail: `kb/09-governance/vulnerability-management.md`.

### Business continuity
BIA, RTO/RPO, 3-2-1 backups (immutable/offline), DR tests, tabletop exercises.

### Awareness
Phishing simulations, role-based training, reporting culture without blame. See `kb/10-emerging/iot-ot-social-physical.md`.

### Continuous compliance
- Evidence as code: pull control evidence automatically from cloud APIs, IdP, CI and ticketing (compliance automation platforms, AWS Config / Azure Policy / Security Hub, CSPM).
- Controls as code: policy-as-code in CI (`kb/06-secure-sdlc/cicd-security.md`), IaC scanning.
- Metrics dashboard: % controls with fresh evidence, overdue risks, open exceptions, vendor reviews due.

## How to verify
- Risk register: every risk has owner, treatment, review date in the last 12 months; acceptances signed by authorized owner with expiry.
- Statement of Applicability / control matrix maps each control to evidence and owner.
- Audit evidence sample: access reviews (quarterly), joiner/mover/leaver tickets, change approvals, backup restore test records, training completion, vuln SLA reports, IR tabletop minutes.
- Run a breach-notification tabletop: time from detection to legal/DPO decision should fit inside 24 h.
- Submit a test DSAR end-to-end; measure completeness and response time.
- Vendor inventory reconciled against finance/SSO data to find shadow SaaS.
- Data discovery scan (DLP/DSPM) confirms Restricted data lives only where classification allows.

## References
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001 · ISO/IEC 27005
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST RMF: https://csrc.nist.gov/projects/risk-management · SP 800-30, 800-37, 800-53 Rev. 5, 800-171
- CIS Controls v8: https://www.cisecurity.org/controls
- PCI Security Standards Council: https://www.pcisecuritystandards.org
- GDPR text: https://eur-lex.europa.eu/eli/reg/2016/679/oj · HHS HIPAA: https://www.hhs.gov/hipaa/index.html
- CCPA/CPRA: https://oag.ca.gov/privacy/ccpa · ENISA (NIS2 guidance): https://www.enisa.europa.eu
- AICPA SOC 2 Trust Services Criteria · FAIR Institute: https://www.fairinstitute.org
- See also `kb/09-governance/vulnerability-management.md`, `kb/01-foundations/frameworks-attack-models.md`, `kb/08-defensive/soc-detection-ir.md`, `templates/`
