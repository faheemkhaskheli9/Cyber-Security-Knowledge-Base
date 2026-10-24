# Data Security and Data Loss Prevention (DLP)

## What
Data security protects the data itself, wherever it is stored or copied: knowing what sensitive data exists and where (**discovery and classification**), limiting who can reach it (**access governance**), making stolen copies useless (**encryption, tokenization, masking**), stopping it from leaving through approved and unapproved channels (**DLP**), and deleting it when it is no longer needed (**retention and sanitization**). It is the "Data" pillar of zero trust (`kb/01-foundations/zero-trust-architecture.md`) and CIS Controls v8 Control 3 (Data Protection). Classification levels and privacy duties are defined in `kb/09-governance/grc-compliance-privacy.md`; database-specific controls are in `kb/04-cloud-infra/database-security.md`.

## Why it matters
- Most breaches end in data theft or exposure, and extortion groups increasingly steal data instead of, or as well as, encrypting it (`kb/08-defensive/ransomware-resilience.md`).
- Sensitive data spreads: copies in analytics warehouses, test environments, logs, spreadsheets, SaaS exports, backups and AI tools are often less protected than the source system.
- In 2024 attackers used stolen credentials, on accounts without MFA, to export data from many customers' Snowflake instances (Mandiant, UNC5537); the platform was not breached, the customers' data access controls were the gap.
- Privacy and sector laws (GDPR, HIPAA, PCI DSS) require knowing where regulated data is and protecting it; you cannot answer a regulator or notify affected people without that inventory.

## Attacks
*Each pattern lists its main defense.*

| Path | How data leaves or is exposed | Defense |
|---|---|---|
| Public or over-shared storage | Bucket, blob container, file share or SaaS link set to public or "anyone with the link"; ATT&CK T1530 (Data from Cloud Storage) | Block public access at the org level, internal-only sharing defaults, DSPM / CSPM alerts (`kb/04-cloud-infra/cloud-security.md`) |
| Credential-based bulk export | Stolen or phished account exports a whole dataset through the normal UI or API | Phishing-resistant MFA, network policies on data platforms, export limits and alerts on volume |
| Exfiltration over web services | Upload to personal cloud storage, paste sites, webmail, or code hosting (T1567) | Endpoint and network DLP, CASB / SWG controls on unsanctioned apps, egress filtering (`kb/02-network/network-security.md`) |
| Email | Sensitive attachment or body sent to personal or wrong external recipients; auto-forwarding rules | Email DLP, block auto-forwarding to external domains, recipient warnings (`kb/02-network/email-security.md`) |
| Removable media and print | USB mass storage, phone sync, printing (T1052) | Device control on managed endpoints; block or require approval and log |
| Shadow copies | Production data restored into test, dev, analytics or a vendor's environment with weaker access | Masked or synthetic test data, data-flow inventory, contracts and controls for vendors (`kb/09-governance/third-party-risk-management.md`) |
| Logs and telemetry | Tokens, card numbers, health or personal data written to logs and sent to third-party observability tools | Redaction at the logger, field allowlists (`kb/06-secure-sdlc/security-logging-and-monitoring.md`) |
| AI tools | Staff paste confidential data into unapproved generative AI services; assistants with broad access surface data users should not see | Approved tools with data-use terms, DLP on AI destinations, fix over-permissive access before enabling assistants (`kb/10-emerging/ai-llm-security.md`) |
| Backups and decommissioned media | Unencrypted backup copied, old disks or devices resold without sanitization | Encrypted backups with separate keys, media sanitization per NIST SP 800-88 with records |
| Encoding and evasion | Data zipped with a password, split, encrypted or exfiltrated over DNS to evade content inspection | Do not rely on content inspection alone: combine with access minimization, volume and behaviour analytics, and blocking unsanctioned destinations |

## Defenses

### 1. Discover and classify
- Build a data inventory: systems, data categories, owners, location (region), retention and who it is shared with. Start from the privacy record of processing and the asset inventory.
- Run automated discovery across cloud storage, databases, SaaS and endpoints (DSPM tools, Amazon Macie, Google Cloud Sensitive Data Protection, Microsoft Purview) and reconcile it with the inventory.
- Apply labels (for example Public / Internal / Confidential / Restricted) at creation where possible: default labels per site or repository, automatic labelling on detected content, and user labelling for documents.

### 2. Minimize and govern access
- Collect and keep less: data minimization and retention schedules enforced by automatic deletion jobs, not policy text alone.
- Access by role and need-to-know; access reviews on Restricted data stores; remove broad groups ("Everyone", "All employees") from sensitive shares and sites.
- Separate production data from non-production: masked, tokenized or synthetic data in test and analytics unless an approved exception exists.

### 3. Protect the data itself
- Encrypt in transit (TLS everywhere, `kb/05-identity-crypto/pki-and-tls.md`) and at rest with managed keys (KMS/HSM); know what at-rest encryption does and does not cover (TDE and disk encryption do not stop a logged-in user or SQL query).
- For the most sensitive fields, use application-level or field-level encryption, or **tokenization** (replace a value such as a card number with a token; the mapping lives in a separately secured vault), so most systems never hold the real value (`kb/05-identity-crypto/cryptography.md`).
- Separate key administrators from data administrators; log key usage; customer-managed keys where the threat model needs them.
- Label-based protection (sensitivity labels that apply encryption and usage rights) keeps documents protected after they leave the repository.

### 4. Data loss prevention
- Cover the main channels: **endpoint** (USB, print, upload, clipboard), **email**, **web / network** (SWG, proxy), **cloud and SaaS** (CASB, API-based scanning of sharing).
- Detection methods, from most to least precise: exact data match or fingerprints of known records and documents, labels, validated patterns (card numbers with Luhn check, national ID formats), keywords and trainable classifiers.
- Roll out in stages: monitor, then warn with user justification, then block for the highest-confidence, highest-impact rules. Tune false positives before blocking.
- Route alerts to an owner with context; repeated or bulk events go to the SOC or insider risk process (`kb/08-defensive/insider-threat.md`).
- DLP reduces accidental and casual loss; it will not stop a determined, technical attacker on its own, so pair it with access control, egress filtering and monitoring.

### 5. Retain, back up and dispose
- Retention per category with legal hold support; automated deletion.
- Backups encrypted, access-restricted and immutable (`kb/08-defensive/ransomware-resilience.md`); deletion requests reach backups by expiry.
- Sanitize media at end of life (clear, purge or destroy per NIST SP 800-88) and keep a certificate or record per asset.

## How to verify
- Coverage: compare automated discovery results with the data inventory; every store holding Restricted data has an owner, a label and an access review date.
- Public exposure: org-level public-access blocks are on (`aws s3control get-public-access-block --account-id <id>`, Azure storage `allowBlobPublicAccess=false`, GCP `constraints/storage.publicAccessPrevention`); SaaS sharing reports show no "anyone" links on Restricted content.
- DLP tests with synthetic test data only (for example test card numbers published by payment networks): email to an external address, upload to a personal storage site, copy to USB, print; confirm the expected monitor, warn or block action and the alert.
- Non-production: sample test and analytics databases for real personal data.
- Encryption and keys: KMS key policies limit decrypt to the intended roles; key usage is logged.
- Retention: pick records past their retention period and confirm they are deleted, including from replicas and exports.
- Sanitization: review records for a sample of retired devices.

## References
- CIS Critical Security Controls v8, Control 3 Data Protection: https://www.cisecurity.org/controls/data-protection
- NIST SP 1800-28, Data Confidentiality: Identifying and Protecting Assets Against Data Breaches: https://www.nccoe.nist.gov/data-confidentiality-identifying-and-protecting-assets-against-data-breaches
- NIST SP 800-122, Guide to Protecting the Confidentiality of PII: https://csrc.nist.gov/pubs/sp/800/122/final
- NIST SP 800-88, Guidelines for Media Sanitization: https://csrc.nist.gov/pubs/sp/800/88/r1/final
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- PCI SSC Information Supplement, PCI DSS Tokenization Guidelines
- Microsoft Purview Data Loss Prevention: https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
- Amazon Macie: https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html
- Google Cloud Sensitive Data Protection: https://cloud.google.com/sensitive-data-protection/docs
- Mandiant, UNC5537 targets Snowflake customer instances for data theft and extortion (June 2024): https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- MITRE ATT&CK Exfiltration tactic (TA0010), T1530 (Data from Cloud Storage): https://attack.mitre.org/tactics/TA0010/
- See also `kb/09-governance/grc-compliance-privacy.md`, `kb/04-cloud-infra/database-security.md`, `kb/08-defensive/insider-threat.md`, `kb/01-foundations/zero-trust-architecture.md`
