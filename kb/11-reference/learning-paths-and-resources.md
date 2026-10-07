# Learning Paths & Resources

## What
Role-based learning paths, legal practice platforms, certifications and reference material for building security skills, from beginner to specialist. Use this file together with the rest of the KB: each step points to KB files that cover the topic.

## Why it matters
- Security is broad; without a path, learners collect tools and certificates without the fundamentals that make them useful.
- Employers hire on demonstrated skill: write-ups, detections, code and lab results matter as much as certifications.
- Practicing on systems you do not own is illegal in most jurisdictions (e.g. US CFAA, UK Computer Misuse Act). Legal labs remove that risk.

## Attacks
Common learning pitfalls and how to avoid them:
| Pitfall | Fix |
|---------|-----|
| Tool-first learning (running Metasploit/sqlmap without understanding the bug) | Learn the protocol or bug class by hand first, then automate |
| Skipping fundamentals (networking, Linux, HTTP, scripting) | Do step 1 of the suggested path before specializing |
| Practicing on real targets without permission | Use only legal labs, CTFs, your own systems or bug bounty programs within scope (`kb/07-offensive/red-team-and-bug-bounty.md`) |
| Certification collecting with no hands-on proof | Pair each cert with a lab portfolio |
| Walkthrough dependency | Attempt each box/challenge alone for a set time before reading hints |
| Red-only focus | Learn how each attack is detected and fixed; defenders and builders are most of the jobs |
| No notes | Keep a personal wiki/write-ups; review weekly |
| Burnout from trying every topic | Pick one track for 6–12 months |

## Defenses
### Suggested path
1. Networking + Linux + Python basics → 2. Security fundamentals → 3. Pick track (SOC / AppSec / Pentest / Cloud / GRC) → 4. Labs + CTFs weekly → 5. Build portfolio (write-ups, tools, detections) → 6. Certification.

Foundations for every track: TCP/IP, DNS, HTTP, TLS; Linux and Windows administration; Bash/PowerShell and Python; Git; core concepts (`kb/01-foundations/core-concepts.md`), threat modeling (`kb/01-foundations/threat-modeling.md`), glossary (`kb/11-reference/glossary.md`).

### SOC analyst / blue team
1. Windows event logs, Sysmon, Linux logs, network traffic (Wireshark, Zeek).
2. SIEM queries (Splunk SPL, KQL, Elastic) and MITRE ATT&CK mapping (`kb/01-foundations/frameworks-attack-models.md`).
3. Alert triage, phishing analysis, incident response lifecycle (`kb/08-defensive/soc-detection-ir.md`).
4. Detection engineering: write Sigma/YARA rules, test with Atomic Red Team in a lab.
5. DFIR and threat intel (`kb/08-defensive/dfir-malware-threat-intel.md`).
Practice: CyberDefenders, LetsDefend, Blue Team Labs Online, TryHackMe SOC paths, Splunk Boss of the SOC datasets, DetectionLab-style home lab.

### Penetration tester / red team (authorized targets only)
1. Web fundamentals and OWASP Top 10 (`kb/03-application/owasp-top10.md`).
2. Enumeration, privilege escalation (Linux/Windows), Active Directory attacks and their detections.
3. Methodology and reporting (`kb/07-offensive/pentest-methodology.md`): scope, rules of engagement, evidence, remediation advice.
4. Bug bounty within program scope; red team and C2 concepts later.
Practice: Hack The Box, TryHackMe, PortSwigger Web Security Academy, OverTheWire (Bandit first), picoCTF, VulnHub-style VMs, Metasploitable, Juice Shop.

### AppSec / DevSecOps
1. Build a small web app; learn its framework's security features.
2. OWASP Top 10, ASVS, API security (`kb/03-application/api-security.md`); code review for injection, authZ, deserialization.
3. SAST/DAST/SCA, secrets scanning, SBOM (`kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`).
4. CI/CD hardening (`kb/06-secure-sdlc/cicd-security.md`), threat modeling of designs.
Practice: PortSwigger Web Security Academy, OWASP Juice Shop, WebGoat, fixing findings in your own repos with `scripts/audit.sh`.

### Cloud security
1. One provider deeply (AWS, Azure or GCP): IAM, networking, logging, KMS.
2. Misconfiguration classes and CSPM (`kb/04-cloud-infra/cloud-security.md`).
3. Containers, Kubernetes, IaC scanning (`kb/04-cloud-infra/containers-kubernetes-iac.md`).
4. Cloud IR and detection (CloudTrail/Activity Logs).
Practice: flAWS and flAWS2, CloudGoat, provider free tiers with budget alerts, Kubernetes Goat.

### GRC
1. Frameworks: ISO 27001, NIST CSF 2.0, SOC 2, CIS Controls (`kb/09-governance/grc-compliance-privacy.md`).
2. Risk assessment, risk registers, policy writing, vendor risk.
3. Privacy law basics (GDPR, CCPA) and breach notification.
4. Audit evidence and continuous compliance automation; vulnerability management metrics (`kb/09-governance/vulnerability-management.md`).
Practice: write a policy set and risk register for a fictional company; map controls across two frameworks; run a tabletop.

### Practice (legal labs)
TryHackMe · HackTheBox · PortSwigger Academy · OverTheWire · picoCTF · CyberDefenders · Blue Team Labs · flAWS (cloud) · Juice Shop · Metasploitable · DetectionLab.

| Platform | Focus | Level |
|----------|-------|-------|
| TryHackMe | Guided rooms, all tracks | Beginner–intermediate |
| Hack The Box (incl. Academy) | Machines, pro labs, AD | Intermediate–advanced |
| PortSwigger Web Security Academy | Web vulnerabilities, free labs | All |
| OverTheWire | Linux and wargames | Beginner |
| picoCTF | CTF for learners | Beginner |
| CyberDefenders | Blue team investigations (pcaps, memory, logs) | Intermediate |
| LetsDefend | SOC analyst simulation | Beginner–intermediate |
| Blue Team Labs Online | Investigations and challenges | Intermediate |
| flAWS / flAWS2 | AWS misconfigurations | Beginner–intermediate |
| CloudGoat | Vulnerable-by-design AWS scenarios (deploy in your own account) | Intermediate |
| OWASP Juice Shop / Metasploitable | Self-hosted vulnerable targets | All |
| DetectionLab | Self-hosted detection lab (check maintenance status) | Intermediate |

### Certifications
Entry: CompTIA Security+, ISC2 CC · Blue: GCIH, BTL1, CySA+ · Red: OSCP, PNPT, eJPT · Cloud: AWS Security Specialty, AZ-500 · Mgmt: CISSP, CISM, CRISC · AppSec: GWEB, CSSLP.

| Track | Entry | Intermediate | Advanced |
|-------|-------|--------------|----------|
| General | ISC2 CC, CompTIA Security+ | CompTIA CySA+ | CISSP |
| SOC / DFIR | BTL1 | GCIH, GCIA, CySA+ | GCFA, GREM |
| Pentest | eJPT | PNPT, OSCP, HTB CPTS | OSEP, OSWE |
| AppSec | Burp Suite Certified Practitioner | GWEB, CSSLP | OSWE |
| Cloud | Cloud provider fundamentals | AWS Certified Security – Specialty, AZ-500, CKS | CCSP |
| GRC / management | ISO 27001 Foundation | ISO 27001 Lead Implementer/Auditor, CISA, CIPP/E | CISM, CRISC, CISSP |

Check each vendor's current exam objectives and experience requirements before committing.

### Standards & references
OWASP (Top 10, ASVS, Cheat Sheet Series, WSTG) · MITRE ATT&CK/CWE/CAPEC · NIST (CSF, 800-53, 800-61, 800-63) · CIS Benchmarks · SANS reading room · CISA KEV · NVD.

### Essential cheat sheets
OWASP Cheat Sheet Series covers auth, session, input validation, XSS, SQLi, CSRF, secrets, logging, Docker, K8s, REST, GraphQL, and more. Command references: `kb/11-reference/tools-and-cheatsheets.md`.

## How to verify
Measure progress with evidence, not hours:
- [ ] Explain a full HTTPS request (DNS, TCP, TLS, HTTP) from memory.
- [ ] Complete beginner paths on one platform without walkthroughs; track solve rate and time per challenge.
- [ ] Publish write-ups (retired boxes / CTFs only, per platform rules) or a blog.
- [ ] Blue: write 5+ detections that fire on Atomic Red Team tests in your lab.
- [ ] Red: produce a professional pentest report from a lab engagement.
- [ ] AppSec: find and fix real issues in your own repo; add CI security checks.
- [ ] Cloud: deploy, break and fix a lab environment; pass a CSPM scan.
- [ ] GRC: complete a risk register and control mapping for a sample org.
- [ ] Pass one certification aligned to your track, and review the KB file for each step quarterly.

## References
- OWASP: https://owasp.org · Cheat Sheet Series: https://cheatsheetseries.owasp.org
- MITRE ATT&CK: https://attack.mitre.org · CWE: https://cwe.mitre.org
- NIST CSRC: https://csrc.nist.gov · CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog · NVD: https://nvd.nist.gov
- TryHackMe: https://tryhackme.com · Hack The Box: https://www.hackthebox.com
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OverTheWire: https://overthewire.org · picoCTF: https://picoctf.org
- CyberDefenders: https://cyberdefenders.org · LetsDefend: https://letsdefend.io
- flAWS: http://flaws.cloud · CloudGoat: https://github.com/RhinoSecurityLabs/cloudgoat
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- See also `kb/11-reference/glossary.md`, `kb/11-reference/tools-and-cheatsheets.md`
