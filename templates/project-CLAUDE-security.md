## Security (imported from cybersec-kb)
@~/cybersec-kb/CLAUDE.md
- Follow OWASP ASVS/Top 10; never commit secrets; parameterize queries; validate input, encode output.
- Before finishing any change touching auth, input handling, crypto, deps, or CI: run the `secure-project-audit` skill.
