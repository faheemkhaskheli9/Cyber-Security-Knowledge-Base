# Edge Device and VPN Appliance Security

## What
**Edge devices** sit on the boundary between your network and the internet or a partner: VPN concentrators and SSL-VPN gateways, firewalls, routers, load balancers and application delivery controllers, email security gateways, managed file transfer servers, remote-access gateways and SOHO routers used by staff. They are usually closed appliances: a vendor OS you cannot harden or monitor like a normal server, often without an EDR agent, exposed to the internet by design, and holding credentials, keys and a privileged position in the network.

This file covers securing and monitoring those devices and responding when one is exploited. General network design is in `kb/02-network/network-security.md`; replacing network-level VPN with per-app access is in `kb/01-foundations/zero-trust-architecture.md`; finding forgotten exposure is in `kb/09-governance/attack-surface-management.md`.

## Why it matters
- **Leading initial-access path**: VPNs, firewalls and file-transfer appliances appear repeatedly in CISA's Known Exploited Vulnerabilities (KEV) catalog, and attackers mass-scan for them soon after a flaw is disclosed (MITRE ATT&CK T1190, Exploit Public-Facing Application; T1133, External Remote Services). Examples include Pulse Secure CVE-2019-11510, Citrix CVE-2023-3519 and CVE-2023-4966 (Citrix Bleed), Ivanti Connect Secure CVE-2023-46805 with CVE-2024-21887, and Palo Alto GlobalProtect CVE-2024-3400.
- **Pre-authentication and pre-MFA**: many edge bugs are exploitable without credentials, so MFA on the VPN does not stop them.
- **Patching is not always enough**: attackers who already have access can survive the fix. CISA reported in 2024 that the Ivanti integrity checker could miss compromise of Ivanti Connect Secure and that actors might keep root-level persistence despite factory resets; Fortinet reported in 2025 that attackers kept read-only access to previously compromised FortiGate devices through a symbolic link that survived patching; Barracuda told customers to replace Email Security Gateway appliances compromised through CVE-2023-2868 rather than only patch them.
- **Limited visibility**: device logs are often short-lived, stored on the device the attacker controls, and not forwarded. Several campaigns (for example the 2024 ArcaneDoor campaign against Cisco firewalls) included tampering with logging or in-memory implants.
- **End-of-life devices become botnets**: CISA and partners reported in 2024 that Volt Typhoon used end-of-life SOHO routers to hide its traffic (advisory AA24-038A).

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Exploiting a disclosed edge CVE | Mass scanning within days of disclosure for the vulnerable version, then pre-auth RCE or file read | Inventory with versions; patch or apply vendor mitigation on emergency timelines for KEV entries; subscribe to vendor PSIRT advisories (`kb/09-governance/vulnerability-management.md`) |
| Exposed management interface | Admin web UI, SSH or API reachable from the internet is brute-forced or exploited | Management only from an internal management network or jump host; CISA BOD 23-02 sets this expectation for US federal agencies |
| Credential attacks on VPN | Password spraying and credential stuffing against VPN portals, often against local accounts that skip SSO | VPN authenticates via the IdP with phishing-resistant MFA (or device certificate plus MFA); disable local VPN accounts except break-glass; lockout and alerting (`kb/05-identity-crypto/identity-access.md`) |
| Credential and session harvesting on the device | Implant or memory leak captures VPN users' passwords, session tokens, LDAP bind credentials and private keys passing through the appliance (ATT&CK T1556.004) | Least-privilege, monitored service account for directory binds; short VPN sessions; after a compromise rotate everything the device saw |
| Firmware or image tampering | Attacker modifies the system image or boot components so implants survive reboot and upgrade (ATT&CK T1601, Modify System Image) | Vendor image signing and secure boot where offered; vendor integrity checks plus external verification; rebuild from known-good images after compromise |
| Configuration changes | New admin accounts, new VPN users, rules allowing inbound access, port forwards, or added packet captures | Configuration backup and diff on every change; change alerts to the SIEM; AAA with per-admin accounts (TACACS+/RADIUS), no shared admin |
| Log tampering and blind spots | Clearing or disabling logs on the device, or using in-memory implants that leave few on-box traces | Forward logs off-box in real time; alert when a device stops sending logs; monitor traffic to and from the device's own address |
| Lateral movement from the device | A compromised VPN or firewall reaches internal networks with its own trusted address and credentials | VPN termination in a DMZ; VPN address pools reach only needed apps; alert on device-originated SSH, SMB, LDAP or RDP to internal hosts |
| End-of-life and unmanaged devices | Out-of-support firewalls, routers and SOHO devices with known, unpatched flaws | Replace before end of support; ban unmanaged SOHO routers for remote staff where feasible; track support dates in the inventory |

## Defenses

### 1. Inventory and reduce
- Every internet-facing device listed with owner, vendor, model, version, support end date, exposed services and the identity it uses. Reconcile with external scans of your own address ranges (`kb/09-governance/attack-surface-management.md`).
- Turn off features you do not use (web portals, clientless VPN, legacy IKEv1, unused admin protocols); each one is attack surface.
- Plan the exit: move from network-level VPN to per-app access through an identity-aware proxy where feasible, so fewer appliances need to face the internet (`kb/01-foundations/zero-trust-architecture.md`).

### 2. Patch and procure for security
- Treat a KEV entry or vendor "exploited in the wild" note for an edge device as an emergency with a defined, short deadline and an owner; apply vendor mitigations the same day when no patch exists.
- Choose vendors and products with a published PSIRT process, signed images, off-box logging, and memory-safe or hardened components; ask for these in procurement (`kb/09-governance/third-party-risk-management.md`, `kb/06-secure-sdlc/product-security-incident-response.md`).
- Replace devices before end of support.

### 3. Harden access to the device
- Management interfaces only on an internal management network; admin logins through a jump host with phishing-resistant MFA; per-admin accounts via TACACS+ or RADIUS backed by the IdP; one vaulted local break-glass account.
- Disable default accounts and change default credentials; use SSH keys or certificates for automation; SNMPv3 only (`kb/02-network/network-security.md`).
- Directory integration uses a dedicated, least-privilege service account over LDAPS, never a domain admin.

### 4. Contain the blast radius
- Put VPN termination and appliances in a DMZ; firewall what the device itself may reach internally.
- VPN users land in pools that reach only the applications they need, not the whole network.
- Alert on traffic initiated by the device's own management or inside address to internal hosts.

### 5. Logging and integrity monitoring
- Forward system, authentication, configuration-change and VPN session logs to the SIEM over an encrypted channel, with synchronized NTP; keep them off-box for at least your incident-response window (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on: new admin accounts, configuration changes outside a change window, firmware changes, log forwarding stopping, VPN logins from unusual countries or hosting providers, many failed logins, and successful logins for accounts that never use VPN.
- Back up configurations automatically (for example with Oxidized or RANCID) and diff each version; an unexplained change is an incident.
- Run vendor integrity tools after any relevant advisory, and do not treat a clean result as proof: verify images against vendor hashes from an independent source when the vendor supports it.

### 6. Respond to a suspected compromise
- Follow the vendor's and CISA's specific guidance for the CVE; collect device logs, configuration and, where the vendor supports it, core dumps or forensic images before you reset (`kb/08-defensive/soc-detection-ir.md`).
- Assume credentials and keys the device handled are exposed: rotate VPN user passwords and sessions, the directory bind account, local admin accounts, API keys, and the device's TLS and VPN private keys and certificates (`kb/05-identity-crypto/secrets-management.md`, `kb/05-identity-crypto/pki-and-tls.md`).
- Hunt inside the network from the device's addresses and the time of first exploitation, not from the time of the advisory.
- Rebuild from known-good images, or replace the hardware when the vendor advises it.

## How to verify
- External scan of your own address ranges (authorized scope) for management ports and portals; compare with the inventory: `nmap -Pn -p 22,23,80,443,4443,8443,10443 <your-public-ranges>`. Every management interface reachable from the internet is a finding.
- Check edge vendors in your inventory against the KEV catalog (example uses the public JSON feed and `jq`):
  ```bash
  curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
    | jq -r '.vulnerabilities[] | select(.vendorProject|test("Ivanti|Fortinet|Citrix|Palo Alto|Cisco";"i"))
             | [.dateAdded, .cveID, .vendorProject, .product] | @tsv' | sort -r | head -20
  ```
  Each entry that matches a model and version you run has a closed ticket or an approved exception with expiry.
- From the VPN address pool, confirm only the intended applications are reachable.
- Stop log forwarding on a test device and confirm the "device silent" alert fires; make a test configuration change and confirm the diff and alert.
- Try logging in to the VPN with a local account and with a password-only factor; both must fail.
- Tabletop the response to "our VPN appliance was exploited two weeks ago": who collects evidence, which credentials are rotated, and how long a rebuild takes.

## References
- CISA Known Exploited Vulnerabilities catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA Binding Operational Directive 23-02, Mitigating the Risk from Internet-Exposed Management Interfaces (2023)
- CISA advisory AA24-060B, Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways (2024)
- CISA advisory AA24-038A, PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure (Volt Typhoon, 2024)
- ASD's ACSC with international partners, Security Considerations for Edge Devices and Mitigation Strategies for Edge Devices (2025)
- NSA, Network Infrastructure Security Guide
- NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy: https://csrc.nist.gov/pubs/sp/800/41/r1/final
- MITRE ATT&CK T1190, Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/ · T1133, External Remote Services: https://attack.mitre.org/techniques/T1133/ · T1556.004, Network Device Authentication: https://attack.mitre.org/techniques/T1556/004/ · T1601, Modify System Image: https://attack.mitre.org/techniques/T1601/
- Cisco Talos, ArcaneDoor campaign report (April 2024); Fortinet PSIRT blog on symbolic-link persistence (April 2025); Barracuda ESG CVE-2023-2868 advisory (2023)
- CIS Benchmarks for network devices: https://www.cisecurity.org/cis-benchmarks
- See also `kb/02-network/network-security.md`, `kb/01-foundations/zero-trust-architecture.md`, `kb/09-governance/attack-surface-management.md`, `kb/09-governance/vulnerability-management.md`, `kb/08-defensive/ransomware-resilience.md`
