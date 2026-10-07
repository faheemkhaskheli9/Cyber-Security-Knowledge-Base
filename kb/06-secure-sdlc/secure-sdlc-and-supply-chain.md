# Secure SDLC & Supply Chain

## Phases
Requirements (security reqs, abuse cases) → Design (threat model) → Code (standards, review) → Test (SAST, DAST, SCA, fuzzing, pentest) → Release (signed, reproducible) → Operate (monitoring, patching, IR). Frameworks: **OWASP SAMM**, **BSIMM**, **NIST SSDF (800-218)**, **OWASP ASVS**.

## Tooling
- SAST: Semgrep, CodeQL, Bandit (Python), gosec, ESLint-security, SpotBugs.
- SCA: Dependabot, Renovate, OSV-Scanner, `npm audit`, `pip-audit`, Trivy, Snyk.
- DAST: OWASP ZAP, Nuclei. Fuzzing: AFL++, libFuzzer, Atheris, Jazzer.
- Secrets: gitleaks, trufflehog. IaC: Checkov, KICS.

## Supply chain
Typosquatting, dependency confusion, compromised maintainers, malicious install scripts, poisoned CI actions. Defenses: lockfiles + hash pinning, private registry scoping, pin GitHub Actions to commit SHAs, SBOM (CycloneDX/SPDX), provenance (**SLSA**, Sigstore/cosign), review new deps, minimal deps, `--ignore-scripts` where feasible, OpenSSF Scorecard.

## CI/CD hardening
Least-privilege `GITHUB_TOKEN` (`permissions:` block), no secrets for forked PRs, protected branches + required reviews, signed commits, OIDC instead of static cloud keys, ephemeral runners, avoid `pull_request_target` with untrusted code, review workflow changes (CODEOWNERS).

## Code review checklist
Input validation · output encoding · authZ on each endpoint · no secrets · safe error handling · crypto usage · logging without sensitive data · dependency changes.
