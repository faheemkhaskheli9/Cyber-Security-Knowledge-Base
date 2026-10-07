# Core Concepts

## What
The shared vocabulary and design principles behind every other file in this KB: what we protect (CIA), how access is governed (AAA), how controls are layered, and how risk is reasoned about.

### CIA triad (+)
- **Confidentiality**: only authorized parties read data (encryption, access control).
- **Integrity**: data is not altered undetected (hashes, signatures, MACs, change control).
- **Availability**: systems work when needed (redundancy, backups, DDoS protection).
- Extended: **Authenticity**, **Non-repudiation**, **Accountability**, **Privacy**.

### AAA
| Function | Question | Examples |
|---|---|---|
| **Authentication** | Who are you? | Passwords + MFA, passkeys/FIDO2, certificates, workload identity (OIDC, mTLS) |
| **Authorization** | What may you do? | RBAC, ABAC/ReBAC, ACLs, OAuth scopes, policy engines (OPA, Cedar) |
| **Accounting / Auditing** | What did you do? | Tamper-evident logs, SIEM, cloud audit trails (CloudTrail, Azure Activity Log) |

Identification (claiming an identity) precedes authentication (proving it). See `kb/05-identity-crypto/identity-access.md`.

### Key principles
Least privilege · Defense in depth · Fail secure · Zero trust (never trust, always verify) · Separation of duties · Minimize attack surface · Secure by default · Complete mediation · Keep it simple · Assume breach.

- **Least privilege**: minimum rights, for the minimum time (just-in-time access, short-lived tokens), scoped to the minimum resources.
- **Defense in depth**: independent layers so one failure is not a breach. Example: WAF → parameterized queries → DB account without DDL rights → encrypted columns → query auditing.
- **Fail secure**: on error, deny (an authZ service timeout must not mean "allow").
- **Complete mediation**: check authorization on every request, not just at login or in the UI.
- **Separation of duties**: no single person can request, approve and deploy (e.g., required PR reviewers, two-person rule for prod keys).
- **Zero trust (NIST SP 800-207)**: no implicit trust from network location; every request is authenticated, authorized and encrypted per session using identity, device posture and context. Components: Policy Engine (PE) + Policy Administrator (PA) = Policy Decision Point, enforced at a Policy Enforcement Point (PEP). Assume the network is already hostile.

### Vocabulary
Asset, threat, vulnerability, exploit, risk = likelihood × impact, control (preventive/detective/corrective), residual risk, attack surface, threat actor (nation-state, criminal, hacktivist, insider, script kiddie).

- **Threat** exploits a **vulnerability** in an **asset**; **risk** is the expected harm. **Residual risk** remains after controls and must be formally accepted by an owner.
- **Attack surface**: every entry point (ports, APIs, forms, file uploads, dependencies, CI, admin consoles, people). Shrinking it is often the cheapest control.

### Risk = likelihood × impact (simple 3×3 matrix)
| Likelihood \ Impact | Low | Medium | High |
|---|---|---|---|
| **High** | Medium | High | Critical |
| **Medium** | Low | Medium | High |
| **Low** | Low | Low | Medium |

Treatment options: avoid/eliminate, mitigate, transfer (insurance, contract), accept (documented, time-boxed, with an owner).

### Control types
- By nature: Administrative (policy, training) · Technical (firewall, MFA) · Physical (locks, cameras).
- By function: Preventive · Detective · Corrective · Deterrent · Compensating (plus Recovery, e.g., restore from backup).

## Why it matters
Every control decision is a trade-off between these properties, cost and usability. Teams that skip the fundamentals over-invest in one layer (a perimeter firewall) and leave the rest flat. Clear vocabulary also makes risk discussions with management and auditors concrete.

**Security vs usability**: controls that are too painful get bypassed (shared accounts, passwords on sticky notes, disabled MFA). Prefer controls that are secure *and* low friction: passkeys over complex password rules, SSO, secure defaults, guardrails over gates.

## Attacks
Common failure modes when the concepts are not applied:
- **Single layer**: one perimeter control; once phished, the attacker moves freely on a flat network.
- **Privilege creep**: accounts accumulate rights across role changes; service accounts with domain/cloud admin.
- **Fail open**: errors, timeouts or missing config default to "allow".
- **Implicit trust by location**: "internal = trusted" VPN or VPC designs (the core problem zero trust addresses).
- **Broken mediation**: authorization checked in the UI but not the API (IDOR/BOLA, see `kb/03-application/api-security.md`).
- **No accountability**: shared admin accounts and missing logs make incidents uninvestigable.
- **Availability ignored**: no tested backups; ransomware turns into a business outage.
- **Unmanaged attack surface**: forgotten test servers, exposed admin panels, orphaned DNS records.

## Defenses
- Maintain an **asset inventory** and data classification; you cannot protect what you do not know.
- Enforce **MFA** everywhere (phishing-resistant for admins) and **least privilege** with periodic access reviews (at least quarterly for privileged roles).
- Design for **deny by default** in network rules, IAM policies and application authZ.
- Layer controls across prevent / detect / respond for each critical asset.
- Adopt zero trust incrementally: identity first (SSO + MFA), then device posture, then per-app access (ZTNA), then micro-segmentation. Track with the CISA Zero Trust Maturity Model.
- Keep a **risk register** with owner, rating, treatment and review date.
- Reduce attack surface: remove unused services, ports, dependencies and accounts.

## How to verify
- Can you name your top 5 assets, who can touch them, and how you would know if they were compromised?
- For each top asset: list at least one preventive, one detective and one corrective control.
- Pick one admin action and confirm it requires MFA, is logged centrally, and the log names an individual.
- Kill or time out the authZ dependency in staging; confirm requests are denied (fail secure).
- Review IAM for wildcard permissions (`"Action": "*"`, `"Resource": "*"`) and accounts unused for 90+ days.
- Restore a backup end to end and time it against your recovery time objective.
- Compare external scan results to your inventory; anything unknown is unmanaged attack surface.

## References
- NIST SP 800-207, Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- CISA Zero Trust Maturity Model: https://www.cisa.gov/zero-trust-maturity-model
- NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments) · NIST SP 800-53 Rev. 5 (control catalog)
- Saltzer & Schroeder, "The Protection of Information in Computer Systems" (1975), origin of the design principles
- OWASP Security by Design Principles · CISA Secure by Design: https://www.cisa.gov/securebydesign
- See also `kb/01-foundations/threat-modeling.md`, `kb/09-governance/grc-compliance-privacy.md`, `kb/11-reference/glossary.md`
