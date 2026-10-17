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
- **ARC** – Authenticated Received Chain; forwarders sign the auth results they saw so mail survives forwarding (RFC 8617).
- **ASLR** – Address Space Layout Randomization; memory-corruption mitigation.
- **ASM** – Attack Surface Management; continuous discovery of exposed assets.
- **AS-REP roasting** – cracking the AS-REP returned for AD accounts that do not require Kerberos preauthentication.
- **ASVS** – OWASP Application Security Verification Standard; testable requirements in three levels (current version 5.0).
- **ATO** – Account Takeover; also Authority To Operate (US gov).
- **ATT&CK** – MITRE knowledge base of adversary tactics and techniques.

## B
- **BEC** – Business Email Compromise.
- **BeyondCorp** – Google's zero trust model: access proxy plus device inventory and user identity instead of a VPN.
- **BIMI** – Brand Indicators for Message Identification; shows a verified logo, requires DMARC at enforcement.
- **BOLA / IDOR** – Broken Object Level Authorization / Insecure Direct Object Reference.
- **Botnet** – network of compromised hosts under attacker control.
- **Break-glass account** – emergency admin account with strong MFA, kept for IdP outages and alerted on every use.
- **Brute force / Credential stuffing** – guessing passwords / replaying leaked credential pairs.
- **BYOD** – Bring Your Own Device.

## C
- **C2 / C&C** – Command and Control infrastructure.
- **CA** – Certificate Authority.
- **CAE / CAEP** – Continuous Access Evaluation / OpenID Shared Signals profile; revoke sessions in near real time on risk change.
- **CASB** – Cloud Access Security Broker.
- **CBOM** – Cryptography Bill of Materials; inventory of algorithms, keys and certificates, the starting point of a post-quantum migration.
- **CIA triad** – Confidentiality, Integrity, Availability.
- **CIS Benchmarks / Controls** – consensus hardening guides / prioritized control set.
- **CNAPP** – Cloud-Native Application Protection Platform (CSPM + CWPP + more).
- **Confused deputy** – a privileged service tricked into acting for an attacker (cloud fix: external ID / source-account conditions).
- **Consent phishing** – tricking a user into granting a malicious OAuth app access; survives password resets.
- **CORS** – Cross-Origin Resource Sharing.
- **CRL / OCSP** – Certificate Revocation List / Online Certificate Status Protocol; CRLs are mandatory for public CAs, OCSP is optional.
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
- **DANE / TLSA** – DNSSEC-signed record pinning the certificate or key a TLS server must present (RFC 6698, 7672).
- **DAST / SAST / IAST / SCA** – dynamic / static / interactive app testing / software composition analysis.
- **DCSync** – abusing AD replication rights to pull password hashes (incl. krbtgt) from a domain controller.
- **DDoS** – Distributed Denial of Service.
- **DEP / NX** – Data Execution Prevention / No-eXecute bit.
- **Dependency confusion** – a public package with the same name as an internal one (and a higher version) wins dependency resolution.
- **DFIR** – Digital Forensics and Incident Response.
- **DKIM / SPF / DMARC** – email authentication standards.
- **DLP** – Data Loss Prevention.
- **DMARC alignment** – the domain that passed SPF/DKIM must match the visible From: domain (relaxed or strict).
- **DMZ** – screened subnet between internet and internal network.
- **DNSSEC** – signed DNS records.
- **DoH / DoT** – DNS over HTTPS / TLS.
- **Double extortion** – ransomware that steals data before encrypting it and threatens to leak it if not paid.
- **DPA / DPIA** – Data Processing Agreement / Data Protection Impact Assessment.

## E
- **ECC / ECDSA / ECDH** – elliptic-curve cryptography, signatures, key exchange.
- **EDR / XDR / MDR** – endpoint / extended detection & response / managed detection & response.
- **EPSS** – Exploit Prediction Scoring System (probability of exploitation in 30 days).
- **Exfiltration** – unauthorized data transfer out of an environment.

## F–H
- **Fail closed / fail open** – on error, a control denies (closed) or allows (open); security checks must fail closed (OWASP A10:2025).
- **FIDO2 / WebAuthn / Passkey** – phishing-resistant public-key authentication.
- **FIM** – File Integrity Monitoring.
- **Format string vulnerability** – user input used as a printf-style format; can leak or write memory.
- **Fuzzing** – feeding malformed/random input to find crashes and bugs.
- **Gadget chain** – existing classes chained during deserialization to reach code execution.
- **gMSA** – Group Managed Service Account; AD manages and rotates its long random password.
- **Golden / Silver Ticket** – forged Kerberos TGT (krbtgt key) / service ticket (service or computer account key).
- **GRC** – Governance, Risk, Compliance.
- **Harvest now, decrypt later (HNDL)** – recording encrypted traffic today to decrypt it once quantum computers can break RSA/ECC.
- **HMAC** – keyed hash for message authentication.
- **HSM** – Hardware Security Module.
- **HSTS** – HTTP Strict Transport Security.
- **HTML smuggling** – HTML/JS assembles a payload in the browser so mail and web gateways never see the file.

## I–K
- **IaC** – Infrastructure as Code.
- **IAM** – Identity and Access Management.
- **IDS / IPS** – Intrusion Detection / Prevention System.
- **IMDS / IMDSv2** – cloud instance metadata service; IMDSv2 (AWS) adds session tokens that block most SSRF credential theft.
- **Immutable backup** – backup copy that storage-level object lock or WORM media prevents anyone, including admins, from deleting or changing before its retention ends.
- **IOC / IOA** – Indicator of Compromise / Attack.
- **IR** – Incident Response.
- **ISMS** – Information Security Management System (ISO 27001).
- **JNDI injection** – user input reaching a Java naming lookup that can load remote code (the Log4Shell mechanism).
- **JWT / JWS / JWE** – JSON Web Token / signed / encrypted.
- **KDF** – Key Derivation Function (Argon2id, scrypt, PBKDF2, HKDF).
- **Kerberoasting** – requesting service tickets for accounts with SPNs and cracking their passwords offline.
- **Kerberos delegation** – unconstrained / constrained / RBCD; lets a service act as a user; common escalation path when misconfigured.
- **KEV** – CISA Known Exploited Vulnerabilities catalog.
- **KMS** – Key Management Service.
- **krbtgt** – AD account whose key signs all TGTs; rotate twice after compromise.

## L–N
- **LAPS** – Windows Local Administrator Password Solution; unique, rotated local admin password per machine.
- **Lateral movement** – pivoting from one compromised host to others.
- **Lethal trifecta** – an AI agent with private data, exposure to untrusted content and an outbound channel; injected instructions can exfiltrate data.
- **LFI / RFI** – Local / Remote File Inclusion; user input controls which file include/require loads.
- **Log injection** – user input with CR/LF or forged fields that writes fake log entries; prevented by structured logging and encoding.
- **LOLBin / LOTL** – Living-off-the-Land binary / technique (abusing built-in tools).
- **Managed identity** – Azure-managed identity for a resource; no secret to store or rotate.
- **Mass assignment** – binding a request body directly to a model so a client can set fields such as `role` or `owner_id`.
- **MCP** – Model Context Protocol; standard for connecting AI agents to tools and data servers.
- **MFA** – Multi-Factor Authentication.
- **Microsegmentation** – identity/label-based allow rules between workloads; east-west denied by default.
- **MITM / AitM** – (Adversary-)in-the-Middle.
- **ML-KEM / ML-DSA / SLH-DSA** – NIST post-quantum key encapsulation and signature standards (FIPS 203 / 204 / 205).
- **MTA-STS** – policy (DNS + HTTPS) requiring senders to use validated TLS to your MX hosts (RFC 8461).
- **mTLS** – mutual TLS; both sides present certificates.
- **NAC** – Network Access Control.
- **NDR** – Network Detection and Response.
- **NGFW** – Next-Generation Firewall.
- **NIST CSF / SP 800-53** – NIST Cybersecurity Framework / control catalog.
- **NTLM relay** – forwarding captured NTLM authentication to another service; blocked by signing, channel binding and EPA.

## O–P
- **OAuth 2.0 / OIDC** – delegated authorization / identity layer on top.
- **OSINT** – Open-Source Intelligence.
- **OT / ICS / SCADA** – Operational Technology / Industrial Control Systems.
- **OWASP** – Open Worldwide Application Security Project.
- **PAM** – Privileged Access Management (also Pluggable Authentication Modules on Linux).
- **PAW / Tier 0** – Privileged Access Workstation / the identity control plane (DCs, AD CS, Entra Connect) in the Enterprise Access Model.
- **PE / PA / PEP / PDP** – Policy Engine / Policy Administrator / Policy Enforcement Point; PE + PA = Policy Decision Point (NIST SP 800-207).
- **Persistence** – attacker mechanisms to survive reboot/credential change.
- **Phishing / Spear-phishing / Smishing / Vishing** – social engineering via email / targeted / SMS / voice.
- **PII / PHI** – Personally Identifiable / Protected Health Information.
- **PKCE** – Proof Key for Code Exchange (OAuth).
- **PKI** – Public Key Infrastructure.
- **PoC** – Proof of Concept.
- **PPE** – Poisoned Pipeline Execution; attacker-controlled code (PR, build script, CI config) runs in a pipeline that holds secrets.
- **PQC** – Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA).
- **Privilege escalation** – gaining higher rights than granted.
- **Prompt injection** – instructions hidden in user input or retrieved content that override an LLM application's intended behavior (direct or indirect).
- **Prototype pollution** – injecting __proto__ / constructor.prototype keys to alter properties of all JavaScript objects.
- **Purple team** – red and blue teams working together to improve detection.

## Q–R
- **Quishing** – QR-code phishing; hides the URL from link scanners and moves the victim to a phone.
- **RaaS** – Ransomware-as-a-Service; operators rent the encryptor and leak site to affiliates who break in.
- **RBAC** – Role-Based Access Control.
- **RCE** – Remote Code Execution.
- **RCP** – AWS Resource Control Policy; org-level cap on permissions allowed on resources.
- **Red / Blue team** – adversary emulation / defenders.
- **ReDoS** – Regular-expression Denial of Service via catastrophic backtracking.
- **RPO / RTO** – Recovery Point / Recovery Time Objective.
- **RSA** – public-key algorithm (≥ 3072-bit for new keys).

## S
- **SAMM** – OWASP Software Assurance Maturity Model; five business functions scored 0–3.
- **SASE / SSE** – Secure Access Service Edge / Security Service Edge.
- **SBOM** – Software Bill of Materials (SPDX, CycloneDX).
- **SCP** – AWS Service Control Policy; caps maximum permissions in member accounts, never grants.
- **SIEM / SOAR** – log analytics & correlation / security orchestration & automated response.
- **Sigma / YARA / Snort** – detection rule formats for logs / files / network.
- **Sigstore / cosign** – keyless artifact signing with short-lived certificates (Fulcio) and a transparency log (Rekor).
- **Slopsquatting** – registering package names that AI coding assistants hallucinate, so suggested installs pull malware.
- **SLSA** – Supply-chain Levels for Software Artifacts.
- **SOC** – Security Operations Center; also SOC 2 audit report.
- **Source / Sink / Taint analysis** – where untrusted data enters / where it can do harm / tracking data from one to the other.
- **SPIFFE / SPIRE / SVID** – workload identity standard / its reference implementation / the short-lived X.509 or JWT identity document.
- **SQLi** – SQL injection.
- **SRI** – Subresource Integrity; `integrity="sha384-..."` hash on a script or stylesheet so a modified CDN file is refused.
- **SSDF** – NIST Secure Software Development Framework (SP 800-218).
- **SSO / SAML** – Single Sign-On / XML-based federation protocol.
- **SSRF** – Server-Side Request Forgery.
- **SSTI** – Server-Side Template Injection; user input rendered as a template, often leading to RCE.
- **SSVC** – Stakeholder-Specific Vulnerability Categorization; decision tree (Track / Track* / Attend / Act) used by CISA to prioritize vulnerabilities.
- **STRIDE** – Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege.

## T–Z
- **Thread hijacking** – replying inside a real email conversation from a compromised mailbox to borrow its trust.
- **TLS** – Transport Layer Security (use 1.2+; prefer 1.3).
- **TLS-RPT** – daily reports from senders about TLS delivery failures to your domain (RFC 8460).
- **TOTP / HOTP** – time / counter-based one-time passwords.
- **TPM** – Trusted Platform Module.
- **Trusted Types** – browser API and CSP directive that only lets typed, policy-created values reach DOM XSS sinks such as `innerHTML`.
- **TTP** – Tactics, Techniques, and Procedures.
- **Typosquatting** – publishing a package or domain with a near-identical name to a popular one (`reqeusts`).
- **UEBA** – User and Entity Behavior Analytics.
- **VDP** – Vulnerability Disclosure Policy.
- **VEX** – Vulnerability Exploitability eXchange; machine-readable statement that a product is or is not affected by a CVE.
- **VPC Service Controls** – GCP perimeter that blocks access to and exfiltration from Google-managed services outside approved projects.
- **VPN / ZTNA** – Virtual Private Network / Zero Trust Network Access.
- **WAF** – Web Application Firewall.
- **Workload identity federation** – exchanging an external OIDC/SAML token (e.g. GitHub Actions) for short-lived cloud credentials.
- **XS-Leaks** – cross-site leaks; side channels (timing, frame counts, error events) that reveal cross-origin information.
- **XSS** – Cross-Site Scripting (reflected, stored, DOM).
- **XXE** – XML External Entity injection.
- **Zero trust** – never trust network location; verify every request (NIST SP 800-207).
- **Zero-day** – flaw exploited before a vendor fix exists.
- **ZTMM** – CISA Zero Trust Maturity Model; 5 pillars, 3 cross-cutting capabilities, 4 stages.
