# Zero Trust Architecture

## What
Zero trust (ZT) is a security model that removes implicit trust based on network location. Every request to a resource is authenticated, authorized and encrypted, per session, using dynamic policy about the user, the device, the workload and the context. "Never trust, always verify; assume breach." ZT is a strategy and an architecture, not a product.

### NIST SP 800-207 tenets (2020)
1. All data sources and computing services are **resources**.
2. All communication is **secured regardless of network location** (being on the internal network grants nothing).
3. Access is granted **per session**, with least privilege.
4. Access is decided by **dynamic policy**: identity, application/service, the requesting asset's state, and other behavioral and environmental attributes.
5. The enterprise **monitors the integrity and security posture** of all owned and associated assets.
6. Authentication and authorization are **dynamic and strictly enforced before access** is allowed.
7. The enterprise **collects telemetry** on assets, network and communications and uses it to improve policy.

### Logical components (NIST SP 800-207)
| Component | Role |
|---|---|
| **Policy Engine (PE)** | Makes the grant/deny/revoke decision with a *trust algorithm*, using policy plus inputs (identity, device posture, threat intel, logs, SIEM, PKI) |
| **Policy Administrator (PA)** | Executes the PE's decision: sets up or tears down the session path, issues session credentials/tokens, and instructs the PEP |
| **Policy Decision Point (PDP)** | PE + PA together |
| **Policy Enforcement Point (PEP)** | Sits in the data path (agent, gateway, proxy, sidecar). It enables, monitors and terminates connections. Nothing reaches the resource except through it |

NIST also names three deployment approaches: **enhanced identity governance**, **microsegmentation**, and **network infrastructure / software-defined perimeter**. Most real deployments mix all three.

| NIST deployment model | Where the PEP sits | Typical example |
|---|---|---|
| Device agent / gateway | Agent on the endpoint + gateway in front of the resource | ZTNA client + app connector |
| Enclave gateway | Gateway in front of a group of resources (an enclave) | Legacy app segment behind one gateway |
| Resource portal | Single portal/proxy, no client agent | Identity-aware reverse proxy, browser access |
| Application sandboxing | Trusted app isolated on the device | Managed browser / app container on BYOD |

The **trust algorithm** can be *criteria-based* (all attributes must match) or *score-based* (confidence score vs threshold), and *singular* (each request alone) or *contextual* (uses recent history). Contextual scoring catches anomalies but is harder to explain and audit.

### CISA Zero Trust Maturity Model v2.0 (2023)
| Pillar | Example "Optimal" outcome |
|---|---|
| **Identity** | Phishing-resistant MFA everywhere, continuous identity validation, just-in-time / just-enough access |
| **Devices** | Real-time inventory and posture feeding every access decision; automated remediation |
| **Networks** | Microsegmentation around apps, all traffic encrypted, no reliance on a flat trusted LAN |
| **Applications & Workloads** | Apps reachable only through policy-enforcing access paths, never directly from the internet; continuous testing in CI/CD |
| **Data** | Data inventoried, classified and labelled; access and DLP enforced on labels; encryption at rest and in transit |

**Cross-cutting capabilities**: *Visibility and Analytics*, *Automation and Orchestration*, *Governance*.
**Maturity stages**: **Traditional** → **Initial** (added in v2) → **Advanced** → **Optimal**. Each pillar progresses on its own, so assess them separately.

### Reference implementations and building blocks
- **BeyondCorp** (Google, published from 2014): moved employees off the VPN. Access goes through an internet-facing **access proxy** and depends on a managed **device inventory** and user identity, so the corporate network is treated as untrusted. The proof that ZT works at scale.
- **ZTNA vs VPN**:

| | Traditional VPN | ZTNA |
|---|---|---|
| Grants access to | A network segment (IP range) | One application/resource per session |
| Trust decision | At connect time, mostly identity | Every request/session: identity + device posture + context |
| Exposure | Internet-facing concentrator (big target) | Apps hidden behind a broker/proxy; outbound-only connectors possible |
| Lateral movement after compromise | Easy (routable network) | Limited to the authorized apps |

- **Microsegmentation**: fine-grained, identity- or label-based allow rules between workloads (host firewalls, Kubernetes NetworkPolicy, service mesh, cloud security groups). It replaces flat VLANs with default deny east-west.
- **Device posture**: OS version, patch level, disk encryption, EDR running, MDM-managed, certificate in the TPM. Posture is evaluated at login *and* during the session.
- **Continuous access evaluation (CAE)**: the IdP and resource providers exchange events (user disabled, password reset, location/risk change, device non-compliant) so sessions are revoked in near real time rather than when the token expires. This is standardized as the OpenID **Shared Signals Framework** (CAEP, RISC).
- **SSE / SASE**: Security Service Edge (SWG + CASB + ZTNA, often FWaaS/DLP) delivered from the cloud. SASE = SSE + SD-WAN. These deliver PEPs for users. They are not ZT by themselves.
- **Workload identity**: services authenticate to each other with short-lived cryptographic identities, not IPs or static API keys. **SPIFFE** defines the ID format (`spiffe://trust-domain/path`) and SVIDs (X.509 or JWT). **SPIRE** (a CNCF graduated project) attests workloads (node + process/k8s attributes) and issues and rotates SVIDs. Services then use **mTLS** with authorization on the peer identity. Service meshes (Istio, Linkerd) automate this. See `kb/05-identity-crypto/pki-and-tls.md`.

## Why it matters
Perimeter models assume that whoever is "inside" is trustworthy. In practice, attackers get inside through phishing, stolen credentials or edge-device exploits, then move laterally to domain admin, backups and data. Cloud, SaaS, remote work and third-party access mean there is no single perimeter left to defend. ZT shrinks the blast radius of every compromise to what that identity, device and session were allowed. It also makes access decisions explicit, logged and auditable. US federal agencies are required to move to ZT (OMB M-22-09), and that requirement drives vendor and regulatory expectations more widely.

## Attacks
### What zero trust is meant to stop
| Threat | How it plays out without ZT | ZT control |
|---|---|---|
| **Implicit trust in flat networks / lateral movement** | One phished laptop reaches every server: SMB/RDP/WinRM, AD enumeration, ransomware spread | Microsegmentation, per-app access, admin tiering, no standing privileges |
| **VPN appliance exploits** | Internet-facing VPN/edge bugs give pre-auth RCE or credential theft and a foothold on the internal network, e.g. Pulse Secure CVE-2019-11510, Fortinet CVE-2018-13379, Citrix CVE-2023-3519, Ivanti Connect Secure CVE-2023-46805 + CVE-2024-21887, Palo Alto GlobalProtect CVE-2024-3400 (all in CISA KEV) | Remove broad network-level VPN access; broker access per app; patch edge devices on KEV timelines; assume the edge is compromised |
| **Token theft / session hijack bypassing MFA** | AitM phishing kits (e.g. Evilginx), infostealer cookie theft, or memory leaks (Citrix Bleed CVE-2023-4966) replay a session issued *after* MFA | Phishing-resistant MFA (FIDO2/passkeys), token binding to the device (Entra token protection, DPoP, Device Bound Session Credentials), CAE revocation, short session lifetimes, anomaly detection on token reuse |
| **Stolen valid accounts** | Credential stuffing or password spray against SSO; the account then works from anywhere | Risk-based conditional access, device requirement, impossible-travel/UEBA signals |

### How ZT deployments fail
- **Policy-engine misconfiguration**: overly broad rules ("All users → All apps"), report-only conditional access never switched to enforce, exclusion groups that grow without limit, or fail-open when the PDP is unreachable. The PE becomes a single point of compromise. Admin access to it is equivalent to access to everything.
- **"ZT-washing"**: a VPN, firewall or SWG is relabelled "zero trust" while the network stays flat, access stays network-level and nothing about trust decisions changes. Ask what implicit trust was actually removed.
- **Allowlist gaps**: wildcard destinations (`*.corp.example`), "any port" app definitions, broad CIDR rules in microsegmentation, or service accounts and CI runners excluded from policy. Attackers pivot through whatever is still allowed.
- **Legacy app exceptions**: mainframes, OT, thick clients, NTLM/Kerberos-only and unmanaged devices are granted permanent bypasses (a "temporary" VPN, a jump-host carve-out). These become the attack path. See `kb/10-emerging/iot-ot-social-physical.md`.
- **Posture checks that trust the client**: a device-health agent that is self-reported and spoofable, or posture checked only at login.
- **Identity becomes the new perimeter but stays weak**: SMS/push MFA (MFA fatigue), unprotected help-desk resets, over-privileged IdP admins, unmonitored OAuth app consents. See `kb/05-identity-crypto/identity-access.md`.
- **No telemetry loop**: PEP logs are not sent to the SOC, so policy is never tuned and abuse goes unseen (tenet 7 ignored).

## Defenses
Phased roadmap (map each phase to CISA ZTMM stages per pillar):

| Phase | Focus | Key actions | Exit criteria |
|---|---|---|---|
| **0. Plan** | Governance, scope | Name an owner; inventory users, devices, apps, data flows and "protect surfaces" (crown jewels); baseline each pillar against CISA ZTMM; threat model (`kb/01-foundations/threat-modeling.md`) | Current/target ZTMM profile approved |
| **1. Identity** | Strong, central identity | Single IdP + SSO for all apps; phishing-resistant MFA (admins first); remove legacy auth protocols; PAM and JIT admin; disable standing privileges | 100% of apps behind SSO; no SMS/OTP for admins |
| **2. Devices** | Know and assess every device | MDM/EDR on all managed endpoints; device certificates (TPM-backed); posture signals into conditional access; unmanaged = browser-only, limited access | Access policies require compliant device for sensitive apps |
| **3. Access path** | Replace network-level VPN | Deploy ZTNA/identity-aware proxy app by app; outbound-only connectors; shrink then retire the VPN; patch and isolate remaining edge devices | No internet-exposed VPN concentrator, or one with a documented end-of-life |
| **4. Network & workloads** | East-west default deny | Microsegment crown jewels first; Kubernetes NetworkPolicy / mesh mTLS (`kb/04-cloud-infra/containers-kubernetes-iac.md`); SPIFFE/SPIRE or cloud workload identity instead of static keys (`kb/05-identity-crypto/secrets-management.md`) | Lateral-movement test from a user VLAN fails |
| **5. Data** | Protect the data itself | Classify and label; DLP and access tied to labels; encryption with managed keys; audit access to sensitive data | Sensitive data stores have label-aware access policies |
| **6. Continuous** | Optimal stage | CAE/Shared Signals revocation; risk scoring from UEBA; policy-as-code with review and tests; PEP/PDP logs in SIEM (`kb/08-defensive/soc-detection-ir.md`); automated response | Session revocation measured in minutes; policy changes go through PR review |

Design rules:
- **Deny by default; fail closed** when the PDP or posture source is unavailable, with a break-glass account that is monitored and alerted.
- Every exception has an owner, a compensating control (isolated segment, jump host with session recording) and an expiry date.
- Protect the control plane: IdP, PDP and MDM admin roles are Tier 0 and need phishing-resistant MFA, PAM and alerting.
- Encrypt everything in transit, internal traffic included (`kb/02-network/network-security.md`).

## How to verify
- **Lateral movement test**: from a standard user device, attempt to reach servers and ports outside the user's entitlements (e.g. `nmap` of internal ranges, SMB/RDP to peers). Expect no route or a blocked connection. Run this only on systems you are authorized to test.
- **Policy review**: export conditional access / ZTNA / segmentation rules and flag "all users", "all apps", wildcards, report-only policies and exclusions without an expiry date.
- **Token replay test**: in an authorized test, replay a captured session cookie from another device. It should fail (device binding) or be revoked quickly (CAE).
- **Revocation timing**: disable a test user or mark its device non-compliant and measure how long until access to each app stops.
- **Posture enforcement**: an unmanaged or out-of-date device is denied or downgraded to limited access.
- **Workload identity**: there are no long-lived service credentials in code or CI (secret scanning). Service-to-service traffic is mTLS with identity-based authorization (check mesh/SPIRE config and attempt a plaintext call).
- **Edge exposure**: external attack surface scan shows no forgotten VPN/RDP endpoints. Every edge device is on the KEV patch SLA (`kb/09-governance/vulnerability-management.md`).
- **Maturity**: CISA ZTMM self-assessment per pillar is repeated at least yearly, with evidence for each claimed stage.

## References
- NIST SP 800-207, *Zero Trust Architecture* (2020): https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A, *A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Location Environments* (2023)
- NIST SP 1800-35, *Implementing a Zero Trust Architecture* (NCCoE)
- CISA Zero Trust Maturity Model v2.0 (April 2023): https://www.cisa.gov/zero-trust-maturity-model
- OMB Memorandum M-22-09, *Moving the U.S. Government Toward Zero Trust Cybersecurity Principles* (2022)
- Google BeyondCorp papers, *;login:* magazine (Ward & Beyer, "BeyondCorp: A New Approach to Enterprise Security", 2014, and follow-ups)
- SPIFFE / SPIRE: https://spiffe.io
- OpenID Shared Signals Framework (CAEP, RISC), OpenID Foundation
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- See also `kb/05-identity-crypto/identity-access.md`, `kb/02-network/network-security.md`, `kb/04-cloud-infra/cloud-security.md`, `kb/01-foundations/core-concepts.md`
