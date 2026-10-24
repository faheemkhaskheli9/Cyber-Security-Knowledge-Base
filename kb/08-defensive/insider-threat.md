# Insider Threat

## What
An **insider threat** is the potential for someone with authorized access (employee, contractor, vendor staff, partner) to harm the organization's confidentiality, integrity or availability, on purpose or by accident. CISA groups insiders as **malicious** (theft, sabotage, fraud, espionage), **negligent** (ignores policy, mishandles data) and **unintentional** (mistakes, being phished). A related case is the **compromised insider**: an outside attacker using a real employee's account, or a fraudulent hire who is the attacker. An insider risk program combines HR, legal, security, IT and management to deter, detect and respond, while respecting privacy and employment law.

## Why it matters
- Insiders already hold valid credentials and know where the valuable data is, so perimeter controls and malware detection rarely fire; ATT&CK maps this to T1078 (Valid Accounts).
- Harm is often discovered late, after a departure or a customer complaint, and is costly to investigate without prepared logs and legal process.
- Documented cases: Coinbase disclosed in May 2025 (SEC Form 8-K) that criminals bribed overseas customer-support contractors to copy customer data, which was then used for extortion and social engineering of customers. The FBI warned in January 2025 that North Korean IT workers hired remotely under false identities were stealing source code and extorting employers.
- Regulators and frameworks expect a program: NIST SP 800-53 Rev. 5 PM-12 (Insider Threat Program) and PS (Personnel Security) controls; ISO/IEC 27001 Annex A people controls (screening, terms of employment, disciplinary process, responsibilities after termination).

## Attacks
*Patterns to detect and prevent; each lists its main defense.*

| Pattern | Typical indicators | Defense |
|---|---|---|
| Data theft before departure | Bulk downloads, sync to personal cloud storage (T1567), USB copies (T1052), mail forwarding to personal addresses, spikes after resignation notice | Departure risk window monitoring, DLP on endpoints/email/SaaS (`kb/09-governance/data-security-and-dlp.md`), block personal storage and removable media by default |
| Privilege abuse | Admin reads mailboxes, customer records or HR data without a ticket; queries outside normal scope | Least privilege, just-in-time admin, access tied to tickets, audit of privileged reads |
| Sabotage | Logic bombs, deleted backups or repositories, disabled monitoring, changes outside change windows, often by a disgruntled admin before or after leaving | Separation of duties, two-person rule for destructive actions, immutable backups, fast offboarding |
| Fraud | Payment detail changes, fake vendors, self-approved refunds | Dual approval, segregation of duties in ERP, reconciliation |
| Bribed or recruited insider | Support or operations staff looking up many unrelated customers; access from new devices; external recruitment (some ransomware groups openly offer payment for access) | Access minimization per role, query rate limits and alerts on lookups, reporting channel, awareness of recruitment approaches |
| Fraudulent remote hire | Identity documents that do not match, camera refusal in interviews, laptop shipped to an address unrelated to the hire, remote-control tools and VPN/proxy egress on the corporate laptop | Identity verification at hiring (in person or verified live video, document checks), ship devices only to verified addresses, alert on remote-access tools and anonymizing egress |
| Negligent or unintentional | Data sent to wrong recipient, shared links set to "anyone", sensitive data pasted into unapproved AI tools, falling for phishing | Secure defaults (internal-only sharing), labelling and DLP, approved tools, training, phishing-resistant MFA |
| Lingering access after leaving | Accounts, tokens, API keys, OAuth grants or shared passwords still valid after the last day | Deprovisioning from HR system via IdP and SCIM, revoke sessions and tokens, rotate shared secrets (`kb/05-identity-crypto/identity-access.md`) |

## Defenses

### 1. Program and governance
- Charter approved by leadership with a named owner, and a working group of HR, legal, privacy, security, IT and the business. Legal and privacy review of what is monitored, where, and who may see it.
- Define what counts as a reportable concern, how cases are triaged, who may open an investigation, and how evidence is handled (chain of custody, `kb/08-defensive/dfir-malware-threat-intel.md`).
- Publish an acceptable use and monitoring notice; monitoring must be lawful, proportionate and transparent (GDPR and works councils in the EU, local employment law elsewhere).
- Focus on behaviour and access, never on protected characteristics.

### 2. Prevent
- **Least privilege and need-to-know**: role-based access, periodic access reviews, no standing admin rights (PAM, just-in-time elevation).
- **Separation of duties** for payments, production changes, backup deletion and security-tool configuration; two-person approval for destructive or bulk actions.
- **Data controls**: classification, sharing defaults, DLP, blocking personal cloud storage and USB mass storage on managed devices.
- **Hiring and contractor controls**: background screening where lawful and proportionate to the role; identity verification for remote hires; same access and monitoring standards for contractors and vendor staff (`kb/09-governance/third-party-risk-management.md`).
- **Joiner / mover / leaver**: movers lose old access; leavers are disabled at or before the time they are told, for high-risk roles; sessions, tokens and keys revoked; devices recovered.
- **Positive culture**: clear reporting channel (including anonymous), fair processes and employee assistance. CERT's guidance stresses that perceived unfair treatment is a common precursor to sabotage.

### 3. Detect
- Collect identity, endpoint, email, SaaS, cloud and database audit logs in the SIEM (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Use UEBA or rules for deviations from a user's or peer group's baseline: volume of downloads, new data repositories, access outside role, off-hours admin actions, printing or USB use.
- Enrich with HR context (notice given, performance plan, contract end) through an agreed, privacy-reviewed feed.
- Place honeytokens in sensitive shares, code repositories and CRM records; legitimate users have no reason to touch them (`kb/08-defensive/deception-and-honeytokens.md`).
- Watch high-value systems specifically: source code, customer support tools, finance, backups, IdP admin.

### 4. Respond
- Playbook in the SOC runbook (`kb/08-defensive/soc-detection-ir.md`) with HR and legal involved from the first step; decide early whether to preserve quietly or contain immediately.
- Preserve evidence before confronting the person: logs, mailbox, endpoint image, cloud audit trails.
- Contain: disable accounts and sessions, revoke tokens and keys, recover devices, rotate shared credentials, check backups and recent changes for sabotage.
- After the case: fix the control gap, update detections, and handle notification duties if personal data was taken (`kb/09-governance/grc-compliance-privacy.md`).

## How to verify
- Offboarding test: for a sample of recent leavers, confirm IdP disablement time vs last day, no active sessions or tokens, no remaining SaaS, VPN, cloud or code-hosting accounts, and rotated shared secrets.
- Access review evidence: quarterly reviews completed for privileged and sensitive-data roles; removed entitlements recorded.
- Detection tests in a sanctioned exercise: bulk download from a sensitive share, upload to personal cloud storage, USB copy, mass customer lookups; each should alert within the expected time.
- Separation of duties: attempt to approve your own payment, production change or backup deletion; it must be blocked.
- Hiring controls: review identity verification records and device shipping addresses for remote hires.
- Tabletop an insider scenario at least yearly with HR, legal and executives.

## References
- CISA Insider Threat Mitigation (topic page): https://www.cisa.gov/topics/physical-security/insider-threat-mitigation
- CISA Insider Threat Mitigation Guide: https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide
- Carnegie Mellon SEI CERT, Common Sense Guide to Mitigating Insider Threats, Seventh Edition: https://insights.sei.cmu.edu/library/common-sense-guide-to-mitigating-insider-threats-seventh-edition/
- National Insider Threat Task Force (NITTF): https://www.dni.gov/index.php/ncsc-how-we-work/ncsc-nittf
- NIST SP 800-53 Rev. 5 (PM-12 Insider Threat Program, PS Personnel Security, AC-5 Separation of Duties, AC-6 Least Privilege): https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- FBI IC3 PSA, North Korean IT Workers Conducting Data Extortion (January 2025): https://www.ic3.gov/PSA/2025/PSA250123
- Coinbase, Form 8-K filed with the US SEC (May 2025), disclosure of bribed support contractors
- MITRE ATT&CK T1078 (Valid Accounts), T1567 (Exfiltration Over Web Service), T1052 (Exfiltration Over Physical Medium), T1213 (Data from Information Repositories): https://attack.mitre.org
- See also `kb/08-defensive/soc-detection-ir.md`, `kb/09-governance/data-security-and-dlp.md`, `kb/05-identity-crypto/identity-access.md`, `kb/08-defensive/deception-and-honeytokens.md`, `kb/10-emerging/iot-ot-social-physical.md`
