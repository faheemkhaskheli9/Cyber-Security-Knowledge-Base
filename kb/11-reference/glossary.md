# Glossary

Alphabetical. Acronyms first, expansion second, one-line meaning third. See topic files for depth.

## A
- **AAA** – Authentication, Authorization, Accounting.
- **ABAC** – Attribute-Based Access Control; decisions from user/resource/environment attributes.
- **ACL** – Access Control List; per-object list of who may do what.
- **AD / AD CS** – Active Directory / AD Certificate Services (common privilege-escalation target).
- **AEAD** – Authenticated Encryption with Associated Data (AES-GCM, ChaCha20-Poly1305).
- **AES** – Advanced Encryption Standard; symmetric block cipher.
- **APT** – Advanced Persistent Threat; well-resourced, long-term intrusion actor.
- **ASLR** – Address Space Layout Randomization; memory-corruption mitigation.
- **ASM** – Attack Surface Management; continuous discovery of exposed assets.
- **ATO** – Account Takeover; also Authority To Operate (US gov).
- **ATT&CK** – MITRE knowledge base of adversary tactics and techniques.

## B
- **BEC** – Business Email Compromise.
- **BOLA / IDOR** – Broken Object Level Authorization / Insecure Direct Object Reference.
- **Botnet** – network of compromised hosts under attacker control.
- **Brute force / Credential stuffing** – guessing passwords / replaying leaked credential pairs.
- **BYOD** – Bring Your Own Device.

## C
- **C2 / C&C** – Command and Control infrastructure.
- **CA** – Certificate Authority.
- **CASB** – Cloud Access Security Broker.
- **CIA triad** – Confidentiality, Integrity, Availability.
- **CIS Benchmarks / Controls** – consensus hardening guides / prioritized control set.
- **CNAPP** – Cloud-Native Application Protection Platform (CSPM + CWPP + more).
- **CORS** – Cross-Origin Resource Sharing.
- **CRL / OCSP** – Certificate Revocation List / Online Certificate Status Protocol.
- **CSP** – Content Security Policy (browser); also Cloud Service Provider.
- **CSPM** – Cloud Security Posture Management.
- **CSRF** – Cross-Site Request Forgery.
- **CT** – Certificate Transparency logs.
- **CTI** – Cyber Threat Intelligence.
- **CVE** – Common Vulnerabilities and Exposures identifier.
- **CVSS** – Common Vulnerability Scoring System (severity, not risk).
- **CWE** – Common Weakness Enumeration.
- **CWPP** – Cloud Workload Protection Platform.

## D
- **DAST / SAST / IAST / SCA** – dynamic / static / interactive app testing / software composition analysis.
- **DDoS** – Distributed Denial of Service.
- **DEP / NX** – Data Execution Prevention / No-eXecute bit.
- **DFIR** – Digital Forensics and Incident Response.
- **DKIM / SPF / DMARC** – email authentication standards.
- **DLP** – Data Loss Prevention.
- **DMZ** – screened subnet between internet and internal network.
- **DNSSEC** – signed DNS records.
- **DoH / DoT** – DNS over HTTPS / TLS.
- **DPA / DPIA** – Data Processing Agreement / Data Protection Impact Assessment.

## E
- **ECC / ECDSA / ECDH** – elliptic-curve cryptography, signatures, key exchange.
- **EDR / XDR / MDR** – endpoint / extended detection & response / managed detection & response.
- **EPSS** – Exploit Prediction Scoring System (probability of exploitation in 30 days).
- **Exfiltration** – unauthorized data transfer out of an environment.

## F–H
- **FIDO2 / WebAuthn / Passkey** – phishing-resistant public-key authentication.
- **FIM** – File Integrity Monitoring.
- **Fuzzing** – feeding malformed/random input to find crashes and bugs.
- **GRC** – Governance, Risk, Compliance.
- **HMAC** – keyed hash for message authentication.
- **HSM** – Hardware Security Module.
- **HSTS** – HTTP Strict Transport Security.

## I–K
- **IaC** – Infrastructure as Code.
- **IAM** – Identity and Access Management.
- **IDS / IPS** – Intrusion Detection / Prevention System.
- **IOC / IOA** – Indicator of Compromise / Attack.
- **IR** – Incident Response.
- **ISMS** – Information Security Management System (ISO 27001).
- **JWT / JWS / JWE** – JSON Web Token / signed / encrypted.
- **KDF** – Key Derivation Function (Argon2id, scrypt, PBKDF2, HKDF).
- **KEV** – CISA Known Exploited Vulnerabilities catalog.
- **KMS** – Key Management Service.

## L–N
- **Lateral movement** – pivoting from one compromised host to others.
- **LOLBin / LOTL** – Living-off-the-Land binary / technique (abusing built-in tools).
- **MFA** – Multi-Factor Authentication.
- **MITM / AitM** – (Adversary-)in-the-Middle.
- **mTLS** – mutual TLS; both sides present certificates.
- **NAC** – Network Access Control.
- **NDR** – Network Detection and Response.
- **NGFW** – Next-Generation Firewall.
- **NIST CSF / SP 800-53** – NIST Cybersecurity Framework / control catalog.

## O–P
- **OAuth 2.0 / OIDC** – delegated authorization / identity layer on top.
- **OSINT** – Open-Source Intelligence.
- **OT / ICS / SCADA** – Operational Technology / Industrial Control Systems.
- **OWASP** – Open Worldwide Application Security Project.
- **PAM** – Privileged Access Management (also Pluggable Authentication Modules on Linux).
- **Persistence** – attacker mechanisms to survive reboot/credential change.
- **Phishing / Spear-phishing / Smishing / Vishing** – social engineering via email / targeted / SMS / voice.
- **PII / PHI** – Personally Identifiable / Protected Health Information.
- **PKCE** – Proof Key for Code Exchange (OAuth).
- **PKI** – Public Key Infrastructure.
- **PoC** – Proof of Concept.
- **PQC** – Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA).
- **Privilege escalation** – gaining higher rights than granted.
- **Purple team** – red and blue teams working together to improve detection.

## R
- **RBAC** – Role-Based Access Control.
- **RCE** – Remote Code Execution.
- **Red / Blue team** – adversary emulation / defenders.
- **RPO / RTO** – Recovery Point / Recovery Time Objective.
- **RSA** – public-key algorithm (≥ 3072-bit for new keys).

## S
- **SASE / SSE** – Secure Access Service Edge / Security Service Edge.
- **SBOM** – Software Bill of Materials (SPDX, CycloneDX).
- **Sigma / YARA / Snort** – detection rule formats for logs / files / network.
- **SIEM / SOAR** – log analytics & correlation / security orchestration & automated response.
- **SLSA** – Supply-chain Levels for Software Artifacts.
- **SOC** – Security Operations Center; also SOC 2 audit report.
- **SQLi** – SQL injection.
- **SSO / SAML** – Single Sign-On / XML-based federation protocol.
- **SSRF** – Server-Side Request Forgery.
- **STRIDE** – Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege.

## T–Z
- **TLS** – Transport Layer Security (use 1.2+; prefer 1.3).
- **TOTP / HOTP** – time / counter-based one-time passwords.
- **TPM** – Trusted Platform Module.
- **TTP** – Tactics, Techniques, and Procedures.
- **UEBA** – User and Entity Behavior Analytics.
- **VDP** – Vulnerability Disclosure Policy.
- **VPN / ZTNA** – Virtual Private Network / Zero Trust Network Access.
- **WAF** – Web Application Firewall.
- **XSS** – Cross-Site Scripting (reflected, stored, DOM).
- **XXE** – XML External Entity injection.
- **Zero-day** – flaw exploited before a vendor fix exists.
- **Zero trust** – never trust network location; verify every request (NIST SP 800-207).
