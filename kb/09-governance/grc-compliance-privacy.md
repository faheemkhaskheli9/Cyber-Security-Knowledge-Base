# Governance, Risk, Compliance & Privacy

## Risk management
Identify assets → threats/vulns → likelihood × impact → treat (mitigate/transfer/avoid/accept) → monitor. Keep a risk register with owners and review dates. Standards: ISO 27005, NIST RMF/800-30, FAIR (quantitative).

## Frameworks & regulations
| Standard | Focus |
|----------|-------|
| ISO/IEC 27001/27002 | ISMS certification |
| SOC 2 | Trust criteria for service orgs |
| NIST CSF 2.0 / 800-53 / 800-171 | US control catalogs |
| CIS Controls v8 | Prioritized practical controls |
| PCI DSS 4.0 | Card data |
| HIPAA | US health data |
| GDPR / UK GDPR / CCPA | Privacy law |
| NIS2 / DORA | EU operational resilience |
| CMMC, FedRAMP | US gov supply chain/cloud |

## Privacy engineering
Data minimization, purpose limitation, consent, DSAR handling, retention schedules, DPIA, pseudonymization/anonymization, encryption, vendor DPAs, breach notification (GDPR 72 h).

## Vulnerability management
Asset inventory → scan (Nessus, OpenVAS, Qualys, Trivy) → prioritize (CVSS + EPSS + KEV + asset criticality) → remediate with SLAs (e.g. Critical 7d, High 30d) → verify → report. Patch management, exception process.

## Policies to have
Acceptable use, access control, incident response, backup/DR, data classification, vendor risk, change management, secure development, BYOD, password/MFA.

## Business continuity
BIA, RTO/RPO, 3-2-1 backups (immutable/offline), DR tests, tabletop exercises.

## Awareness
Phishing simulations, role-based training, reporting culture without blame.
