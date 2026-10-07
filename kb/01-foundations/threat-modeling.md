# Threat Modeling

## What
A structured way to find design-level security flaws before they are built. Ask four questions (Shostack): **What are we building? What can go wrong? What are we going to do about it? Did we do a good job?**

Output: a diagram, a list of threats with mitigations and owners, and tracked follow-up work. It is cheapest at design time, but any existing system can be modeled.

## Why it matters
Scanners and code review find implementation bugs; they rarely find missing authorization between services, an unauthenticated internal queue, or an admin path that bypasses MFA. Design flaws are expensive to fix after launch. OWASP Top 10 2021 added **A04 Insecure Design** for this reason.

## Attacks
STRIDE categories, with typical threats and mitigations:

| Threat | Property violated | Example | Mitigations |
|---|---|---|---|
| **S**poofing | Authentication | Forged JWT, stolen session, service impersonation | MFA, strong session management, mTLS/workload identity, signature validation |
| **T**ampering | Integrity | Modified request params, altered files/messages, DB writes | Input validation, HMAC/signatures, TLS, write ACLs, immutable storage |
| **R**epudiation | Non-repudiation | "I never made that transfer" with no audit trail | Tamper-evident audit logs, signed transactions, synchronized time |
| **I**nformation disclosure | Confidentiality | Verbose errors, IDOR, unencrypted backups | Encryption at rest/in transit, ACLs, object-level authZ, data minimization |
| **D**enial of service | Availability | Unbounded queries, resource exhaustion, queue floods | Rate limits, quotas, timeouts, pagination, redundancy, autoscaling |
| **E**levation of privilege | Authorization | User reaches admin API, container escape | AuthZ checks on every call, least privilege, sandboxing |

Common failure modes of the process itself: modeling once and never updating; diagrams that do not match reality; listing threats without owners; skipping trust boundaries inside the cloud ("it's all in our VPC").

## Defenses
### Steps
1. Draw a data-flow diagram: actors, processes, data stores, data flows, **trust boundaries**.
   - Trust boundaries are where privilege or control changes: internet ↔ app, app ↔ DB, tenant ↔ tenant, your code ↔ third-party API, user browser ↔ server, CI ↔ production.
   - Label each flow with protocol, authN method and data classification.
2. Enumerate threats per element with **STRIDE** (table above). Rule of thumb: external entities → S, R; processes → all six; data stores → T, R, I, D; data flows → T, I, D. Focus on flows that cross a trust boundary.
3. Rate risk (DREAD, CVSS, or simple High/Med/Low × likelihood).
4. Choose mitigation: eliminate, mitigate, transfer, accept.
5. Record in the repo (`docs/threat-model.md`) and revisit on architecture change.

### Lightweight per-feature process (30–60 min)
- Trigger: new external endpoint, new data store, new auth flow, new third-party integration, new trust boundary, or handling of sensitive data.
- Attendees: feature dev, a reviewer, optionally a security champion.
- Update the DFD → run STRIDE on boundary-crossing flows → file a ticket per accepted mitigation → link the model in the PR/design doc.
- Definition of done: every High threat has a mitigation merged or a documented, owner-signed risk acceptance.

### Other methods
PASTA (risk-centric), LINDDUN (privacy), attack trees, OCTAVE, MITRE ATT&CK-based modeling, **OWASP Threat Dragon** / **pytm** for diagrams-as-code.

| Method | Best for |
|---|---|
| STRIDE | Default for software and APIs; per-element threat enumeration |
| PASTA | 7-stage, risk- and business-impact-centric; larger orgs |
| LINDDUN | Privacy threats: Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance |
| Attack trees | Deep dive on one goal (e.g., "steal payment data"); OR/AND nodes with cost or likelihood |
| OCTAVE | Organizational/operational risk assessment |
| ATT&CK-based | Validating detections against realistic adversary behavior |

### Tools
- **OWASP Threat Dragon**: free diagramming with STRIDE/LINDDUN rule engine.
- **pytm**: threat model as Python code; generates DFDs and threat reports in CI.
- **Microsoft Threat Modeling Tool**: Windows app, STRIDE-per-element with Azure templates.
- Plain Markdown + Mermaid diagrams in the repo is often enough.

### Quick template
| Element | Threat (STRIDE) | Impact | Mitigation | Owner | Status |
|---|---|---|---|---|---|
| `POST /api/transfer` (flow, internet → API) | T: amount tampered | High | Server-side validation, signed request | @team-payments | Done |
| Orders DB (store) | I: backup unencrypted | High | KMS-encrypted snapshots | @platform | Open |

## How to verify
- `docs/threat-model.md` (or equivalent) exists, has a DFD with trust boundaries, and was updated within the last architecture change.
- Every High/Critical threat maps to a ticket, a merged mitigation, or a signed risk acceptance with an expiry date.
- Mitigations have tests (e.g., an authZ test proving a user cannot reach another tenant's object).
- Pentest and incident findings are fed back: was the issue in the model? If not, why not ("Did we do a good job?").
- The PR template or design-review checklist asks "Does this change a trust boundary?"

## References
- Threat Modeling Manifesto: https://www.threatmodelingmanifesto.org
- OWASP Threat Modeling Cheat Sheet · OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- OWASP pytm: https://github.com/OWASP/pytm
- LINDDUN: https://linddun.org
- Adam Shostack, *Threat Modeling: Designing for Security* (Wiley, 2014)
- Microsoft Threat Modeling Tool documentation (Microsoft Learn)
- See also `kb/01-foundations/core-concepts.md`, `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/10-emerging/ai-llm-security.md`
