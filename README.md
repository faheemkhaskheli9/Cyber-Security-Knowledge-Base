# Cybersecurity Knowledge Base

A practical, Claude-readable knowledge base covering the whole cybersecurity field, plus tooling to audit and harden your own software projects.

## Layout

| Path | Contents |
|------|----------|
| `CLAUDE.md` | Instructions Claude loads automatically in this repo (how to use the KB, how to secure projects) |
| `.claude/skills/secure-project-audit/` | Skill: audit any project against this KB and fix findings |
| `kb/01-foundations` | CIA triad, threat modeling, risk, attacker frameworks (ATT&CK, kill chain) |
| `kb/02-network` | Network defense, protocols, wireless, DNS, DDoS |
| `kb/03-application` | OWASP Top 10, API security, mobile, browser/client side |
| `kb/04-cloud-infra` | Cloud, containers/Kubernetes, IaC, Linux/Windows hardening |
| `kb/05-identity-crypto` | IAM, authN/authZ, secrets, cryptography, PKI |
| `kb/06-secure-sdlc` | Secure SDLC, supply chain, SAST/DAST, CI/CD security |
| `kb/07-offensive` | Pentesting methodology, red team, bug bounty, exploit concepts (authorized testing only) |
| `kb/08-defensive` | SOC, detection engineering, incident response, DFIR, malware analysis, threat intel |
| `kb/09-governance` | GRC, compliance (ISO 27001, SOC 2, NIST, PCI, GDPR), privacy, vulnerability management |
| `kb/10-emerging` | AI/LLM security, IoT/OT, quantum, social engineering, physical |
| `kb/11-reference` | Glossary, tools, learning paths, cheat sheets |
| `templates/` | Drop-in `SECURITY.md`, Dependabot, CodeQL, gitleaks, pre-commit, CLAUDE security snippet |
| `scripts/` | `audit.sh` (quick local project audit), `bootstrap-project.sh` (install templates into a project) |

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

## Available in every new session
`scripts/install-global.sh` clones the three KB repos to `~/kb`, imports them from `~/.claude/CLAUDE.md` and installs their skills. Paste it into your cloud environment's **Setup script** (environment menu → Edit) so every new session runs it. The private repo needs GitHub access in that environment; otherwise it is skipped.

## Scope and ethics
Offensive content is for **authorized** testing, defense, CTFs and education. Never test systems you don't own or lack written permission to test. Never commit real secrets, client data or live exploit weaponization to this repo.

## Contributing
One topic per file, keep it actionable (what / why / how to defend / how to verify), link authoritative sources (OWASP, NIST, MITRE, CIS, vendor docs).
