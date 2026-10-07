# Attack Frameworks & Models

## What
Shared models for describing how attacks unfold (kill chains, ATT&CK), analyzing intrusions (Diamond Model, Pyramid of Pain), choosing countermeasures (D3FEND), and organizing a security program (NIST CSF, CIS Controls). Plus the identifiers used to track vulnerabilities (CVE/CWE/CVSS/EPSS/KEV).

### Attack lifecycle models
- **Lockheed Martin Cyber Kill Chain**: Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions on objectives. Linear and perimeter/malware focused; useful for "break the chain early" thinking, weak on insiders and cloud/identity attacks.
- **Unified Kill Chain**: 18 phases merging the Kill Chain and ATT&CK, covering the full path (initial foothold → network propagation → action on objectives).
- **MITRE ATT&CK**: Tactics (the "why") with techniques/sub-techniques (the "how", IDs like `T1566.001`). Matrices exist for Enterprise (incl. cloud, containers), Mobile and ICS. Use to map detections and coverage gaps (ATT&CK Navigator).

| ID | Enterprise tactic | ID | Enterprise tactic |
|---|---|---|---|
| TA0043 | Reconnaissance | TA0007 | Discovery |
| TA0042 | Resource Development | TA0008 | Lateral Movement |
| TA0001 | Initial Access | TA0009 | Collection |
| TA0002 | Execution | TA0011 | Command and Control (C2) |
| TA0003 | Persistence | TA0010 | Exfiltration |
| TA0004 | Privilege Escalation | TA0040 | Impact |
| TA0005 | Defense Evasion | | |
| TA0006 | Credential Access | | |

### Analysis models
- **Diamond Model**: adversary, capability, infrastructure, victim. Pivot between vertices (e.g., from a C2 IP to other victims using the same infrastructure) to cluster intrusions.
- **Pyramid of Pain** (David Bianco): hashes → IPs → domains → network/host artifacts → tools → TTPs; hunt higher up. Blocking a hash costs the attacker seconds; detecting a TTP forces them to change behavior.

### Defensive and program frameworks
- **MITRE D3FEND**: defensive countermeasure knowledge graph, organized by tactics (Model, Harden, Detect, Isolate, Deceive, Evict, Restore) and mapped to ATT&CK techniques via digital artifacts.
- **NIST CSF 2.0** (2024): Govern, Identify, Protect, Detect, Respond, Recover. Govern is new in 2.0 and covers strategy, roles, policy and supply-chain risk. Use Profiles (current vs target) and Tiers.
- **CIS Controls v8/v8.1**: 18 prioritized controls (asset inventory, software inventory, data protection, secure configuration, account and access management, vulnerability management, audit logs, ... penetration testing) split into Implementation Groups IG1 (essential cyber hygiene) → IG2 → IG3.

### Vulnerability identifiers
- **CVE / CWE / CVSS / EPSS / KEV**: identifier, weakness class, severity, exploit probability, known-exploited list (prioritize KEV).

## Why it matters
Frameworks give a common language between red, blue, engineering and leadership. They turn "are we secure?" into measurable questions: which ATT&CK techniques do we detect, which CSF outcomes are at target, which CIS IG1 safeguards are missing. They also stop vulnerability triage from being driven by CVSS score alone.

### When to use which
| Need | Use |
|---|---|
| Map detections, plan purple-team exercises, describe adversary behavior | MITRE ATT&CK (+ Navigator) |
| Pick countermeasures for a technique | MITRE D3FEND |
| Explain an intrusion's stages to non-specialists | Cyber Kill Chain / Unified Kill Chain |
| Cluster and attribute intrusions, pivot on CTI | Diamond Model |
| Decide which indicators are worth detecting | Pyramid of Pain |
| Structure a whole security program, report to the board | NIST CSF 2.0 |
| Concrete prioritized to-do list for a small/medium org | CIS Controls v8 (start with IG1) |
| Prioritize patching | KEV first, then EPSS + CVSS + asset criticality |

## Attacks
Common failure modes when using frameworks:
- **Coverage theater**: coloring ATT&CK cells green because a tool "has a rule", without testing that it fires.
- **Treating ATT&CK as a checklist**: not every technique is relevant; prioritize those used by threat groups targeting your sector.
- **IOC-only detection**: living at the bottom of the Pyramid of Pain (hash/IP blocklists) that attackers rotate trivially.
- **Kill-chain perimeter bias**: ignoring insiders, stolen valid accounts (`T1078`) and SaaS/cloud attacks that skip "weaponize/deliver".
- **CVSS-only patching**: chasing every 9.8 while an actively exploited 7.5 on the internet edge stays open.
- **Compliance = security**: CSF/CIS mapping on paper without implementation or measurement.

## Defenses
1. Build a **threat profile**: pick the ATT&CK groups and techniques relevant to your sector and tech stack.
2. Map existing detections and controls to ATT&CK in Navigator; mark gaps; map gaps to D3FEND countermeasures.
3. Write behavior-based detections (TTPs) rather than IOC lists; use Sigma for portable rules (see `kb/08-defensive/soc-detection-ir.md`).
4. Validate detections with **atomic tests** (e.g., Atomic Red Team, MITRE Caldera) on authorized lab or production-like systems only.
5. Run a CSF 2.0 current/target profile once a year; implement CIS IG1 first if you have no baseline.
6. Patch prioritization: CISA KEV entries on exposed assets → high EPSS → CVSS + asset criticality (see `kb/09-governance/vulnerability-management.md`).
7. Tag incidents and threat-intel reports with ATT&CK IDs so trends become visible.

## How to verify
- An ATT&CK Navigator layer exists, is version-controlled, and each "covered" technique links to a detection rule *and* a dated test result.
- Purple-team exercise results show detection rate per tested technique.
- Detection content includes rules above the "tools" level of the Pyramid of Pain.
- Vulnerability SLAs reference KEV (and EPSS), not just CVSS.
- A CSF 2.0 profile and CIS Controls self-assessment (e.g., CIS CSAT) exist with owners and dates.

## References
- MITRE ATT&CK: https://attack.mitre.org
- MITRE D3FEND: https://d3fend.mitre.org
- Lockheed Martin Cyber Kill Chain: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- CIS Critical Security Controls: https://www.cisecurity.org/controls
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/ · FIRST CVSS: https://www.first.org/cvss/
- CVE: https://www.cve.org · CWE: https://cwe.mitre.org
- Diamond Model of Intrusion Analysis (Caltagirone, Pendergast, Betz, 2013) · Pyramid of Pain (David Bianco, 2013)
- See also `kb/08-defensive/dfir-malware-threat-intel.md`, `kb/07-offensive/red-team-and-bug-bounty.md`
