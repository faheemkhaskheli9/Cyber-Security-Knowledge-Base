# Cybersecurity KB – instructions for Claude

This repo is a cybersecurity knowledge base (`kb/`) plus tooling to secure the user's projects.

## How to use the KB
- For any security question, read the relevant file under `kb/` first, then answer; cite the file.
- Index: `README.md`. Glossary: `kb/11-reference/glossary.md`.
- If the KB lacks a topic, say so, answer from general knowledge, and offer to add a KB file.

## Securing the user's projects
When asked to review, harden or build anything:
1. Run the `secure-project-audit` skill (`.claude/skills/secure-project-audit/SKILL.md`) and `scripts/audit.sh <path>`.
2. Prioritize by severity: secrets exposure > RCE/injection > authN/authZ flaws > vulnerable dependencies > misconfiguration > hardening.
3. Fix issues directly when in scope; explain each fix briefly. Never weaken a control to make a test pass.
4. Add missing baseline files from `templates/` (SECURITY.md, Dependabot, CodeQL, secret scanning, pre-commit).

## Hard rules
- Never print, log or commit secrets. If one is found, tell the user to rotate it; removing it from git history is not enough.
- Offensive techniques only for authorized targets (user's own systems, CTFs, written-scope pentests). Refuse mass targeting, DoS, malware for harm, or evading detection for malicious purposes.
- Prefer secure defaults: least privilege, deny by default, parameterized queries, output encoding, TLS everywhere, pinned dependencies, MFA.
- Confirm before destructive or outward-facing actions (history rewrites, key rotation, public disclosure).

## Style
Concise, actionable, evidence-based. Each KB file: What / Why it matters / Attacks / Defenses / How to verify / References.

## Sibling knowledge bases
This repo is one of three: `faheemkhaskheli9/Cyber-Security-Knowledge-Base`, `faheemkhaskheli9/Personal-Knowledge-Base`,
`faheemkhaskheli9/AI-Knowledge-Base`. If a task could use the others and they are not in the session, attach them
with `add_repo` (read access is enough unless you need to push) and clone them next to this one. Each has a
`webapp/` for manual viewing and editing (`python3 webapp/server.py --open`).
