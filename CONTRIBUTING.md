# Contributing

## Adding or editing a KB file
1. Put it in the matching `kb/NN-area/` folder, one topic per file, kebab-case name.
2. Use this structure (required headings):
   ```
   # Title
   ## What
   ## Why it matters
   ## Attacks
   ## Defenses
   ## How to verify
   ## References
   ```
3. Keep it actionable: concrete settings, commands and checks over prose. Link authoritative sources (OWASP, NIST, MITRE, CIS, CISA, vendor docs).
4. Add new terms to `kb/11-reference/glossary.md` and list the file in `README.md`.

## Rules
- **No real secrets, client data, or weaponized exploits.** Use placeholders like `EXAMPLE_KEY`.
- Offensive content must state it is for authorized testing only and pair each technique with its defense and detection.
- Prefer secure defaults in every example (parameterized queries, TLS on, least privilege, pinned versions).

## Checks
CI runs `bash -n` on scripts, `scripts/check-kb.sh` (required headings and internal links) and `scripts/audit.sh .`. Run them locally before pushing.
