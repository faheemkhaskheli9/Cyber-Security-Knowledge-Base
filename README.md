# Cybersecurity Knowledge Base

A practical, Claude-readable knowledge base covering the whole cybersecurity field, plus tooling to audit and harden your own software projects.

## Layout

| Path | Contents |
|------|----------|
| `CLAUDE.md` | Instructions Claude loads automatically in this repo (how to use the KB, how to secure projects) |
| `.claude/skills/secure-project-audit/` | Skill: audit any project against this KB and fix findings |
| `kb/01-foundations` | CIA triad, threat modeling, risk, attacker frameworks (ATT&CK, kill chain), zero trust |
| `kb/02-network` | Network defense, protocols, wireless, DNS, DDoS, email security |
| `kb/03-application` | OWASP Top 10, API security, mobile, browser/client side |
| `kb/04-cloud-infra` | Cloud (incl. AWS/Azure/GCP baselines), containers/Kubernetes, IaC, Linux/Windows hardening |
| `kb/05-identity-crypto` | IAM, authN/authZ, Active Directory, secrets, cryptography, PKI |
| `kb/06-secure-sdlc` | Secure SDLC, supply chain, SAST/DAST, CI/CD security, secure code review |
| `kb/07-offensive` | Pentesting methodology, red team, bug bounty, exploit concepts (authorized testing only) |
| `kb/08-defensive` | SOC, detection engineering, incident response, DFIR, malware analysis, threat intel |
| `kb/09-governance` | GRC, compliance (ISO 27001, SOC 2, NIST, PCI, GDPR), privacy, vulnerability management |
| `kb/10-emerging` | AI/LLM security, IoT/OT, quantum, social engineering, physical |
| `kb/11-reference` | Glossary, tools, learning paths, cheat sheets |
| `templates/` | Drop-in `SECURITY.md`, Dependabot, CodeQL, gitleaks, pre-commit, CLAUDE security snippet |
| `scripts/` | `audit.sh` (quick local project audit), `bootstrap-project.sh` (install templates into a project) |

## KB file index

| Area | Files |
|------|-------|
| 01 Foundations | [core-concepts](kb/01-foundations/core-concepts.md) · [threat-modeling](kb/01-foundations/threat-modeling.md) · [frameworks-attack-models](kb/01-foundations/frameworks-attack-models.md) · [zero-trust-architecture](kb/01-foundations/zero-trust-architecture.md) |
| 02 Network | [network-security](kb/02-network/network-security.md) · [wireless-dns-ddos](kb/02-network/wireless-dns-ddos.md) · [email-security](kb/02-network/email-security.md) |
| 03 Application | [owasp-top10](kb/03-application/owasp-top10.md) · [api-security](kb/03-application/api-security.md) · [browser-client-side](kb/03-application/browser-client-side.md) · [mobile-and-client](kb/03-application/mobile-and-client.md) |
| 04 Cloud & infra | [cloud-security](kb/04-cloud-infra/cloud-security.md) · [containers-kubernetes-iac](kb/04-cloud-infra/containers-kubernetes-iac.md) · [os-hardening](kb/04-cloud-infra/os-hardening.md) · [cloud-provider-baselines](kb/04-cloud-infra/cloud-provider-baselines.md) |
| 05 Identity & crypto | [identity-access](kb/05-identity-crypto/identity-access.md) · [secrets-management](kb/05-identity-crypto/secrets-management.md) · [cryptography](kb/05-identity-crypto/cryptography.md) · [pki-and-tls](kb/05-identity-crypto/pki-and-tls.md) · [active-directory-security](kb/05-identity-crypto/active-directory-security.md) |
| 06 Secure SDLC | [secure-sdlc-and-supply-chain](kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md) · [cicd-security](kb/06-secure-sdlc/cicd-security.md) · [secure-code-review](kb/06-secure-sdlc/secure-code-review.md) |
| 07 Offensive | [pentest-methodology](kb/07-offensive/pentest-methodology.md) · [red-team-and-bug-bounty](kb/07-offensive/red-team-and-bug-bounty.md) |
| 08 Defensive | [soc-detection-ir](kb/08-defensive/soc-detection-ir.md) · [dfir-malware-threat-intel](kb/08-defensive/dfir-malware-threat-intel.md) |
| 09 Governance | [grc-compliance-privacy](kb/09-governance/grc-compliance-privacy.md) · [vulnerability-management](kb/09-governance/vulnerability-management.md) |
| 10 Emerging | [ai-llm-security](kb/10-emerging/ai-llm-security.md) · [iot-ot-social-physical](kb/10-emerging/iot-ot-social-physical.md) · [post-quantum-cryptography](kb/10-emerging/post-quantum-cryptography.md) |
| 11 Reference | [glossary](kb/11-reference/glossary.md) · [tools-and-cheatsheets](kb/11-reference/tools-and-cheatsheets.md) · [learning-paths-and-resources](kb/11-reference/learning-paths-and-resources.md) |

## Using it with Claude

**In this repo:** open Claude Code here; `CLAUDE.md` is loaded automatically.

**Secure another project (recommended):**
```bash
git clone <this-repo-url> ~/cybersec-kb
~/cybersec-kb/scripts/bootstrap-project.sh /path/to/your/project
```
This copies the security templates and adds an `@import` of the KB to the project's `CLAUDE.md`, so Claude follows your security rules in that project. Then ask Claude: *"Run the secure-project-audit skill on this project."*

**Install the skill globally:**
```bash
mkdir -p ~/.claude/skills && cp -r ~/cybersec-kb/.claude/skills/secure-project-audit ~/.claude/skills/
```

## Scope and ethics
Offensive content is for **authorized** testing, defense, CTFs and education. Never test systems you don't own or lack written permission to test. Never commit real secrets, client data or live exploit weaponization to this repo.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). One topic per file, keep it actionable (what / why / how to defend / how to verify), link authoritative sources (OWASP, NIST, MITRE, CIS, vendor docs).

## Web app (view and edit)

```bash
python3 webapp/server.py --open     # http://localhost:8771 , stdlib only, no install
```

Browse the file tree, read rendered Markdown (links and `[[wiki-links]]` work), full-text search, edit raw
text (Ctrl+S saves) and create new files. Edits write straight to the files here; review and commit with git.
It listens on 127.0.0.1 only, rejects foreign Host/Origin headers, needs a per-run token for writes, only touches
text files inside the repo, and refuses to overwrite a file that changed on disk since you opened it.
