# IoT, OT/ICS, Social Engineering, Physical & Quantum

## What
Four domains where security fails outside the classic IT stack:
- **IoT**: connected consumer and enterprise devices (cameras, routers, sensors, smart building gear).
- **OT / ICS / SCADA**: systems that control physical processes (PLCs, RTUs, HMIs, safety systems, historians).
- **Social engineering**: manipulating people into giving access, money or data.
- **Physical**: getting hands on buildings, devices and media.
Plus a short note on quantum risk (full detail in `kb/10-emerging/post-quantum-cryptography.md`).

Social engineering and physical testing content here is for defense and authorized assessments with written scope only.

## Why it matters
- Mirai (2016) built a massive DDoS botnet from IoT devices with default passwords.
- OT attacks have physical consequences: Stuxnet (centrifuges), Ukraine grid outages (2015, 2016 Industroyer), Triton/Trisis targeting a safety instrumented system.
- IT incidents spill into OT: Colonial Pipeline (2021) shut down pipeline operations after IT ransomware.
- Most breaches involve the human element (Verizon DBIR); MFA fatigue enabled the Uber 2022 breach; a deepfake video call led to a reported ~US$25M fraud at Arup (2024).
- Physical access defeats most logical controls (unlocked console, rogue device plugged into the LAN).

## Attacks
### IoT
- Default or hard-coded credentials, exposed Telnet/SSH/web admin (found via Shodan/Censys).
- Unsigned firmware, no updates, outdated components; debug ports (UART/JTAG) left open.
- Insecure cloud APIs and mobile companion apps; cleartext MQTT/CoAP.
- OWASP IoT Top 10 categories: weak passwords, insecure network services, insecure ecosystem interfaces, lack of update mechanism, insecure/outdated components, insufficient privacy protection, insecure data transfer/storage, lack of device management, insecure default settings, lack of physical hardening.

### OT / ICS / SCADA
- Legacy protocols (Modbus, DNP3, OPC) lack auth: any host that can reach a PLC can write to it.
- Flat IT/OT networks, dual-homed engineering workstations, vendor remote access (VPN/TeamViewer) bypassing the DMZ.
- Internet-exposed HMIs and PLCs; unpatchable systems running decades-old OS versions.
- Malware frameworks: Industroyer/CrashOverride, Triton, PIPEDREAM/Incontroller. Mapped in MITRE ATT&CK for ICS.

### Social engineering
| Type | Channel | Red flags |
|------|---------|-----------|
| Phishing / spear-phishing / whaling | Email (generic / targeted / executives) | Urgency, lookalike domain, credential page |
| Vishing | Phone | "IT help desk" asking for MFA codes or password reset |
| Smishing / QR phishing (quishing) | SMS, QR codes | Short links, parking/delivery lures, QR in email bypassing URL filters |
| Pretexting | Any | Invented scenario (auditor, new hire, vendor) to justify the request |
| BEC | Email from compromised/spoofed exec or vendor | Changed bank details, gift cards, secrecy |
| MFA fatigue / push bombing | Push notifications | Many unexpected prompts, followed by a "help desk" call |
| Help-desk reset abuse | Phone to service desk | Caller asks to reset MFA for a privileged account |
| Deepfake voice/video | Calls, video meetings | Familiar voice/face, unusual payment or access request |
| Baiting / USB drops | Physical media | Found USB stick or "free" device |

### Physical
- Tailgating/piggybacking through controlled doors.
- Badge cloning: legacy 125 kHz proximity cards can be read and copied from short range.
- Unlocked screens, documents on desks, unshredded paper, unencrypted lost laptops.
- Rogue devices (network implants, keystroke injectors) plugged into open ports.
- Lock bypass, propped fire doors, unescorted visitors.

## Defenses
### IoT
Unique credentials, signed firmware + secure boot, OTA updates, disable unused services/ports (UART/JTAG), network isolation, MQTT/CoAP over TLS. Standard: OWASP IoT Top 10, ETSI EN 303 645.
- **ETSI EN 303 645** baseline: no universal default passwords; a vulnerability disclosure policy; keep software updated (stated support period); plus secure storage, secure communication, minimal attack surface, data protection.
- Regulation: UK PSTI regime (in force 2024) and EU Cyber Resilience Act (`kb/09-governance/grc-compliance-privacy.md`).
- Buyer checklist: support period stated, update mechanism, no default password, disclosure contact, SBOM on request.
- Deploy on a dedicated VLAN/SSID with egress allowlist; block inbound from the internet; inventory with NAC (`kb/02-network/network-security.md`).

### OT / ICS / SCADA
Purdue model segmentation, DMZ between IT/OT, passive monitoring (Claroty, Nozomi, Zeek), legacy protocols (Modbus, DNP3, OPC) lack auth → isolate, safety first (availability > confidentiality), IEC 62443, NIST 800-82.

| Purdue level | Contents | Control |
|--------------|----------|---------|
| 4–5 | Enterprise IT, internet | Standard IT security |
| 3.5 | IT/OT DMZ | Jump hosts, historian replicas, patch servers; no direct IT→OT traffic |
| 3 | Site operations (historian, engineering workstations) | Hardened, application allowlisting |
| 2 | Supervisory (HMI, SCADA) | Zone firewalls, no internet |
| 1 | Controllers (PLC, RTU) | Key switch in RUN, protocol-aware firewall |
| 0 | Physical process (sensors, actuators) | Physical security, safety systems independent |

- **IEC 62443**: zones and conduits, security levels SL 1–4, requirements for asset owners, integrators and product vendors.
- **Safety first**: never active-scan production PLCs without the process owner; test in a lab or during outages. Safety instrumented systems stay isolated.
- **Passive monitoring**: SPAN/TAP into OT-aware IDS for asset inventory and anomaly detection.
- Remote access: brokered, MFA, time-boxed, recorded sessions; no always-on vendor VPNs.
- Offline, tested backups of PLC logic and configs; manual operation playbooks; OT-specific IR plan.
- Use CISA ICS advisories to prioritize patches and compensating controls.

### Social engineering
Phishing, spear-phishing, vishing, smishing, pretexting, BEC, QR phishing, deepfake voice/video. Defenses: phishing-resistant MFA, DMARC enforcement, out-of-band verification for payments/credentials, reporting button, training.
- **Phishing-resistant MFA** (FIDO2/passkeys) defeats credential phishing and MFA fatigue; if push is used, enable number matching and rate limits (`kb/05-identity-crypto/identity-access.md`).
- **Email auth**: SPF, DKIM, DMARC at `p=reject`; flag external senders and lookalike domains.
- **Verification callbacks**: payment or bank-detail changes and MFA/password resets require a callback to a number from the system of record, never the one in the message; dual approval above a threshold.
- **Deepfake defense**: code words or pre-agreed verification for high-value requests; treat urgency + secrecy as a stop signal.
- **Help desk**: strict identity verification for resets of privileged accounts (video + manager approval).
- **Awareness program**: short, role-based, frequent training; phishing simulations that teach, not shame; measure report rate, not just click rate.
- **Reporting culture**: one-click report button, fast feedback, no blame for reporting a mistake.

### Physical
Badges, tailgating prevention, locks, cameras, clean desk, device encryption, USB controls, visitor logs, secure disposal.
- Badges: replace 125 kHz prox with secure credentials (e.g. MIFARE DESFire EV2/EV3, SEOS) or mobile credentials; badge + PIN for sensitive areas.
- Tailgating: mantraps/turnstiles at high-security doors, "challenge politely" training, door-held alarms.
- CCTV covering entrances and server rooms with retention; quality locks and key control.
- Clean desk and clear screen (auto-lock), full-disk encryption, USB device control, 802.1X on wired ports.
- Visitors: sign-in, ID check, escort, badge return. Secure disposal: shredding, certified media destruction.

### Quantum
"Harvest now, decrypt later" risk. Inventory crypto, adopt crypto-agility, plan hybrid PQ (ML-KEM, ML-DSA) migration. See `kb/10-emerging/post-quantum-cryptography.md`.

## How to verify
- IoT: scan your ranges for Telnet/default logins (authorized only); confirm devices are on isolated VLANs and firmware is current; check vendor support dates.
- OT: passive asset inventory matches the documented architecture; no direct routes IT→Level 2 or below (firewall rule review); remote-access sessions are logged.
- Social engineering: track phishing simulation report rate and time-to-report; test callback procedure with an authorized vishing exercise; DMARC aggregate reports show `p=reject` and alignment.
- Physical: authorized physical assessment (tailgating, badge, clean desk walk-through) with written scope; audit badge logs vs. HR roster; check CCTV coverage and retention.

## References
- ETSI EN 303 645 · OWASP IoT Project: https://owasp.org/www-project-internet-of-things/
- IEC 62443 series (ISA/IEC) · NIST SP 800-82 Rev. 3 (OT security)
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/ · CISA ICS: https://www.cisa.gov/topics/industrial-control-systems
- CISA phishing guidance and phishing-resistant MFA fact sheets: https://www.cisa.gov
- Verizon Data Breach Investigations Report (annual)
- See also `kb/02-network/network-security.md`, `kb/05-identity-crypto/identity-access.md`, `kb/07-offensive/red-team-and-bug-bounty.md`, `kb/10-emerging/post-quantum-cryptography.md`
