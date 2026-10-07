# SOC, Detection Engineering & Incident Response

## What
The people, processes and tooling that detect malicious activity and respond to incidents.
- **SOC tiers**: L1 triage → L2 investigation → L3 hunting/engineering (plus SOC manager, detection engineers, threat intel).
- **Tools**: SIEM (Splunk, Elastic, Sentinel, Wazuh), EDR/XDR, SOAR, NDR, ticketing/case management.
- **Detection engineering**: building, testing and maintaining detections as code.
- **Incident response (IR)**: the NIST SP 800-61 lifecycle and playbooks.

## Why it matters
- Prevention eventually fails; dwell time and response speed decide the impact.
- Ransomware and BEC are the most common high-impact incidents. Both are survivable with preparation (backups, playbooks, out-of-band comms) and costly without it.
- Regulators set notification clocks: GDPR 72h to the supervisory authority, NIS2 24h early warning / 72h notification, SEC 4 business days after a materiality determination for US public companies.

## Attacks
What the SOC must catch, by ATT&CK tactic (examples):
| Tactic | Common technique | Key data source |
|---|---|---|
| Initial access | Phishing (T1566), exploit public-facing app (T1190), valid accounts (T1078) | Email gateway, WAF/web logs, IdP sign-ins |
| Execution | PowerShell (T1059.001), LOLBins (`mshta`, `rundll32`, `certutil`) | EDR, Sysmon 1, 4688, 4104 |
| Persistence | Run keys, services (7045), scheduled tasks (4698), cron, new OAuth apps | EDR, Sysmon 13, cloud audit |
| Credential access | LSASS access (T1003.001), Kerberoasting (4769 RC4), password spraying (4625/IdP failures) | EDR, DC logs, IdP |
| Lateral movement | RDP/SMB/WinRM with valid creds (4624 type 3/10) | DC + host auth logs, NDR |
| Command & control | Beaconing over HTTPS/DNS | Proxy, DNS, NDR, Zeek |
| Exfil / impact | Cloud storage upload, mass encryption (T1486), backup deletion (`vssadmin delete shadows`) | Proxy, EDR, backup logs |
| BEC | Mailbox rules forwarding/deleting mail, MFA fatigue, payment-change emails | M365/Google audit, IdP |

## Defenses
### Log sources (priority order)
1. EDR telemetry on all endpoints and servers
2. Identity: IdP/SSO sign-ins, AD DCs (4624/4625/4768/4769/4720/4728/4732), MFA events
3. Cloud and SaaS audit (CloudTrail, Azure Activity/Entra, GCP Audit, M365 Unified Audit Log)
4. Email security gateway
5. DNS and web proxy / secure web gateway
6. Firewall/VPN, then NDR/Zeek
7. Windows process creation 4688 (with command line) or Sysmon, PowerShell 4104 script block logging
8. Critical application and database logs
Centralize, sync time (NTP), retain ≥ 90 days hot and 1 year searchable where feasible.

### SIEM use cases (starter set)
- Impossible travel / sign-in from new country + new device; MFA push spam
- Password spraying: many accounts, one source, few attempts each
- New admin/privileged group membership; new service (7045) or scheduled task on servers
- Encoded/obfuscated PowerShell; Office app spawning a shell
- LSASS memory access by non-allowlisted process
- Mailbox forwarding rule to external domain; new OAuth app consent with mail scopes
- Mass file rename/modify; shadow copy or backup deletion
- Audit log cleared (1102) or logging disabled (CloudTrail `StopLogging`)
- Rare parent-child processes, beaconing (regular interval connections), LOLBins misuse

### Detection engineering lifecycle (detection-as-code)
Hypothesis → data source check → rule → test (Atomic Red Team) → tune → document → review. In practice:
1. Write rules in **Sigma** (convert to SIEM query), **YARA** for files, **Suricata** for network; store in Git.
2. Each rule has: ATT&CK mapping, data source, false-positive notes, severity, triage steps, owner.
3. CI: lint/validate (`sigma check`), convert (`sigma convert -t splunk -p sysmon rules/`), unit test against sample logs.
4. Emulate the technique (e.g., Atomic Red Team test for T1059.001) in a lab; confirm the alert fires.
5. Deploy, measure FP rate, tune with narrow allowlists, review quarterly; retire dead rules.

Sample Sigma rule:
```yaml
title: Suspicious Encoded PowerShell Command Line
id: de4ff0a8-781b-4cc9-8be6-d510d4ecfdc3
status: experimental
description: Detects PowerShell started with an encoded command, often used to hide intent.
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_enc:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
  condition: selection_img and selection_enc
falsepositives:
  - Management/deployment tools (SCCM, Intune scripts); allowlist by parent process and signer
level: high
```

### ATT&CK coverage mapping
- Tag every rule with technique IDs; export to an **ATT&CK Navigator** layer (score = tested detection, partial, none). DeTT&CT can score data-source visibility.
- Prioritize techniques used by threat groups targeting your sector (from intel, see `kb/08-defensive/dfir-malware-threat-intel.md`), not 100% coverage.
- Count only detections validated by emulation as "covered".

### Threat hunting
Hypothesis-driven (ATT&CK technique, intel report, anomaly). Look for: rare parent-child processes, beaconing, new persistence (Run keys, cron, services), unusual auth, LOLBins misuse. Turn successful hunts into detections.

### Alert triage (L1/L2)
1. Read the alert and rule documentation; check asset criticality and user role.
2. Enrich: IP/domain/hash reputation, user's recent sign-ins, process tree, related alerts on host/user (±24h).
3. Decide: false positive (tune), benign true positive (document), or true positive → open incident, assign severity.
4. Record evidence and reasoning in the case; escalate per SLA (e.g., Critical: 15 min).

### Metrics
MTTD (mean time to detect), MTTR (mean time to respond/contain), false-positive rate per rule, ATT&CK coverage, % alerts triaged within SLA, dwell time, % incidents detected internally vs reported externally.

### Incident response lifecycle (NIST SP 800-61)
**Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-incident review.** SP 800-61r3 (2025) reorganizes this around the NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover), with preparation and lessons learned as continuous activities.
- Contain first (isolate host, disable account, block IOCs), preserve evidence (memory, disk image, logs) before wiping (see `kb/08-defensive/dfir-malware-threat-intel.md`).
- Keep a timeline; chain of custody; communicate via out-of-band channel; involve legal/PR/regulators (GDPR 72h notification).
- Playbooks: phishing, ransomware, compromised credentials, web shell, insider, data breach, cloud key leak.
- Ransomware readiness: offline/immutable backups, tested restores, segmentation, EDR, MFA, patching, no RDP exposure.

**Playbook outline: ransomware**
1. Detect/declare: mass encryption alerts, ransom note, backup deletion. Activate IR team and out-of-band comms (assume email/chat compromised).
2. Contain: isolate affected hosts via EDR (don't power off; memory is evidence), disable compromised accounts, block C2, cut VPN/trusts if spreading; protect backups.
3. Scope: patient zero, initial access vector, accounts used, data exfiltrated (double extortion)?
4. Eradicate: remove persistence, reset privileged creds (krbtgt twice, service accounts), patch entry point.
5. Recover: rebuild from known-good images, restore from verified clean backups, monitor closely.
6. Notify: legal, insurer, law enforcement, regulators/customers as required. Payment decisions involve legal and leadership (sanctions screening).

**Playbook outline: business email compromise (BEC)**
1. Triggers: suspicious payment-change request, user report, forwarding rule alert.
2. Contain: reset password, revoke sessions/refresh tokens, re-register MFA, remove malicious inbox rules and OAuth grants.
3. Scope: audit log for sign-ins, mail access (MailItemsAccessed), sent mail, rules; find other targeted users.
4. Financial: contact bank immediately to recall transfers; report to law enforcement (e.g., FBI IC3 in the US).
5. Harden: phishing-resistant MFA, conditional access, external-sender banners, out-of-band verification for payment changes.

### Tabletop exercises
- Run at least twice a year with technical and executive participants; scenario per top risk (ransomware, BEC, cloud key leak, insider).
- Inject timed events; test decision points: who declares, who isolates, who talks to regulators, where backups are, ransom stance.
- Output: gaps, owners, due dates. CISA Tabletop Exercise Packages (CTEPs) provide ready scenarios.

### Post-incident
Blameless review, root cause, detection gaps, action items with owners.

## How to verify
- Run Atomic Red Team tests for top techniques in a lab; each should produce an alert with correct ATT&CK tag.
- Log source health dashboard: every critical source reporting in the last hour; alert on silence.
- Navigator layer of validated coverage reviewed quarterly; MTTD/MTTR trending down.
- Tabletop and restore tests completed on schedule; action items closed.
- Purple-team exercise results (see `kb/07-offensive/red-team-and-bug-bounty.md`).

## References
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK: https://attack.mitre.org · ATT&CK Navigator
- Sigma: https://github.com/SigmaHQ/sigma
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- CISA #StopRansomware: https://www.cisa.gov/stopransomware
- CISA Tabletop Exercise Packages (CTEPs)
- SANS Incident Handler's Handbook
- See also `kb/08-defensive/dfir-malware-threat-intel.md`, `kb/05-identity-crypto/identity-access.md`
