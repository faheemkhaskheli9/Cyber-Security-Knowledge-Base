# Red Teaming and Bug Bounty

> **Authorized use only.** Every activity here requires written permission and a defined scope (your own systems, a signed engagement, or a published bug bounty program). Out-of-scope testing is illegal in most jurisdictions.

## What
- **Pentest**: time-boxed effort to find as many vulnerabilities as possible in a defined scope (see `pentest-methodology.md`).
- **Red team**: objective-driven adversary emulation (e.g., "reach the payment database") that tests people, process and detection, not just bugs. Usually covert to the blue team.
- **Purple team**: red and blue work together, running technique by technique to build and tune detections.
- **Bug bounty / VDP**: public or private programs inviting researchers to report vulnerabilities under published rules, with or without payment.

## Why it matters
Scanners find known weaknesses. Red teams reveal whether an organization can actually **detect and respond** to a realistic attacker. Bug bounties provide continuous, diverse testing at scale.

## Red team engagement lifecycle
1. **Rules of engagement (RoE)**:
   - Scope, objectives and out-of-bounds systems
   - Allowed techniques (social engineering? physical?)
   - Testing windows, emergency contacts and a stop condition
   - Data handling
   - A signed authorization letter carried by testers
2. **Threat intel-led planning**: pick a realistic adversary and map their TTPs to MITRE ATT&CK.
3. **Execution**: initial access → establish C2 → privilege escalation → lateral movement → objective. Log every action with a timestamp for deconfliction.
4. **Reporting**:
   - Attack narrative and timeline
   - Detection gaps: for each step, whether it was detected, alerted and responded to
   - Prioritized fixes
5. **Purple-team replay** to convert gaps into detections.

Common frameworks: TIBER-EU, CBEST, and ATT&CK-based emulation plans such as the CTID Adversary Emulation Library. Common tooling for authorized use: Atomic Red Team, MITRE Caldera, Sliver/Mythic C2.

## Bug bounty: for researchers
- Read the program policy fully: scope, excluded vulnerability classes, rate limits, safe harbor.
- Recon only in-scope assets. Never pivot, exfiltrate real user data, or cause DoS.
- Prove impact minimally (your own test accounts; read one record, not thousands).
- Write reports with a clear title, affected asset, steps to reproduce, impact, PoC and suggested fix.
- Common high-value classes: IDOR/BOLA, auth bypass, SSRF, account takeover, business logic flaws.

## Bug bounty: for organizations
1. Start with a **VDP** (`SECURITY.md`, `/.well-known/security.txt`, safe-harbor language). Add paid bounty only once triage capacity and vulnerability management are mature.
2. Define scope, a severity-based reward table and response SLAs (triage ≤ 3 business days).
3. Use a platform (HackerOne, Bugcrowd, Intigriti, YesWeHack) or self-host.
4. Feed findings into root-cause fixes and SAST rules, not just one-off patches.

## How to verify
- Red team: % of ATT&CK techniques detected, time to detect, time to contain, and whether the objective was reached.
- Bounty: time to triage, time to fix, duplicate rate, and recurring bug classes trending down.

## References
- MITRE ATT&CK: https://attack.mitre.org · CTID Adversary Emulation Library
- TIBER-EU framework · disclose.io safe-harbor terms: https://disclose.io
- RFC 9116 (security.txt) · ISO/IEC 29147 & 30111 (vulnerability disclosure and handling)
