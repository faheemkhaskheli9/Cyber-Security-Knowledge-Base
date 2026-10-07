# Threat Modeling

Ask four questions (Shostack): **What are we building? What can go wrong? What are we going to do about it? Did we do a good job?**

## Steps
1. Draw a data-flow diagram: actors, processes, data stores, data flows, **trust boundaries**.
2. Enumerate threats per element with **STRIDE**:
   - **S**poofing → authentication · **T**ampering → integrity · **R**epudiation → logging/non-repudiation
   - **I**nformation disclosure → encryption/ACLs · **D**enial of service → rate limits/redundancy · **E**levation of privilege → authZ/least privilege
3. Rate risk (DREAD, CVSS, or simple High/Med/Low × likelihood).
4. Choose mitigation: eliminate, mitigate, transfer, accept.
5. Record in the repo (`docs/threat-model.md`) and revisit on architecture change.

## Other methods
PASTA (risk-centric), LINDDUN (privacy), attack trees, OCTAVE, MITRE ATT&CK-based modeling, **OWASP Threat Dragon** / **pytm** for diagrams-as-code.

## Quick template
| Element | Threat (STRIDE) | Impact | Mitigation | Owner | Status |
