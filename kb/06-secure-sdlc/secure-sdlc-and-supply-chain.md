# Secure SDLC & Supply Chain

## What
Building security into every phase of software delivery and controlling everything the software is built from: your code, third-party dependencies, build tools and the artifacts you ship.

**Phases**: Requirements (security reqs, abuse cases) → Design (threat model) → Code (standards, review) → Test (SAST, DAST, SCA, fuzzing, pentest) → Release (signed, reproducible) → Operate (monitoring, patching, IR).

**Frameworks**:
- **NIST SSDF (SP 800-218)**: outcome-based practices in four groups: PO (Prepare the Organization), PS (Protect the Software), PW (Produce Well-Secured Software), RV (Respond to Vulnerabilities). Used for US federal supplier self-attestation.
- **OWASP SAMM**: maturity model with five business functions (Governance, Design, Implementation, Verification, Operations), each scored 0–3. Use it to baseline and plan a roadmap.
- **BSIMM**: descriptive study of what real firms do; useful for benchmarking against peers.
- **OWASP ASVS**: testable security requirements in three levels (L1 baseline, L2 most apps handling sensitive data, L3 high-assurance). Turn chapters into user-story acceptance criteria.

## Why it matters
- Fixing a flaw in design or code is far cheaper than after release or after a breach.
- Most application code is third-party. One compromised package or build step reaches every downstream user: event-stream (2018), SolarWinds (2020), ua-parser-js (2021), the xz-utils backdoor (CVE-2024-3094), the self-replicating "Shai-Hulud" npm worm (2025).
- Regulation and procurement increasingly demand evidence: SSDF attestation, SBOMs (US EO 14028 lineage), EU Cyber Resilience Act.

## Attacks
| Attack | How it works | Primary defense |
|---|---|---|
| Typosquatting | `reqeusts`, `crossenv` published to look like popular packages | Review new deps, allowlist, Scorecard/Socket-style checks |
| Slopsquatting | Attacker registers package names that AI assistants hallucinate | Verify every suggested package exists and is established |
| Dependency confusion | Public package with your internal name and a higher version wins resolution (Birsan, 2021) | Scope private registry, reserve names, single-registry resolution |
| Compromised maintainer | Stolen token/phished account publishes a malicious version | Lockfiles + hash pinning, minimum release age, provenance checks |
| Malicious install scripts | `preinstall`/`postinstall` or `setup.py` runs code at install time | `--ignore-scripts` where feasible, sandboxed installs |
| Poisoned CI actions | Mutable tag of a third-party Action re-pointed to malicious code | Pin Actions to commit SHAs (see `kb/06-secure-sdlc/cicd-security.md`) |
| Build tampering | Build system modifies output (SolarWinds) | SLSA L3 hardened builds, reproducible builds, signed provenance |
| Protestware / maintainer sabotage | Legit maintainer ships destructive change | Pinning, review diffs on upgrade, delayed adoption |
| Long-con maintainer takeover | Social engineering to gain commit rights (xz-utils) | Scorecard, maintainer health review, minimal deps |

## Defenses
### Security activities per phase
| Phase | Activities | Gate / output |
|---|---|---|
| Requirements | ASVS level chosen, security & privacy reqs, abuse cases, data classification | Reqs in backlog with acceptance criteria |
| Design | Threat model (`kb/01-foundations/threat-modeling.md`), secure design review, crypto/identity choices | Threat model + mitigations tracked |
| Code | Secure coding standard, pre-commit secret scan, IDE SAST, peer review with checklist | Signed commits, CODEOWNERS approval |
| Build | SAST, SCA, secret scan, IaC scan, SBOM generation, provenance | Block on new criticals/secrets |
| Test | DAST, fuzzing, API tests for authZ, pentest for major releases (`kb/07-offensive/pentest-methodology.md`) | No open High+ without exception |
| Release | Sign artifacts, attach SBOM + provenance, verify at deploy | Unsigned = not deployable |
| Operate | Monitoring, patching SLAs (`kb/09-governance/vulnerability-management.md`), IR, VDP | SECURITY.md, `security.txt` |

### Tooling and CI gates
- **SAST**: Semgrep, CodeQL, Bandit (Python), gosec, ESLint-security, SpotBugs. Gate on new High+ findings only (diff-aware) to keep signal high.
- **SCA**: Dependabot, Renovate, OSV-Scanner, `npm audit`, `pip-audit`, Trivy, Snyk. Gate on KEV/critical reachable vulns.
- **DAST**: OWASP ZAP (`zap-baseline.py` in CI, full scan in staging), Nuclei.
- **Fuzzing**: AFL++, libFuzzer, Atheris (Python), Jazzer (JVM); OSS-Fuzz for open-source projects.
- **Secrets**: gitleaks, trufflehog in pre-commit and CI, plus platform push protection. A found secret must be rotated (see `kb/05-identity-crypto/secrets-management.md`).
- **IaC**: Checkov, KICS (see `kb/04-cloud-infra/containers-kubernetes-iac.md`).
- Baseline files: `templates/codeql.yml`, `templates/dependabot.yml`, `templates/gitleaks.yml`, `templates/pre-commit-config.yaml`, `templates/SECURITY.md`.

### Dependency hygiene
- Commit lockfiles; install exactly what's locked: `npm ci`, `pip install --require-hashes -r requirements.txt` (generate with `pip-compile --generate-hashes`), `poetry install --sync`, `go mod verify`.
- Disable install scripts where feasible: `npm ci --ignore-scripts` (allowlist packages that need them).
- Prevent dependency confusion: scope internal packages to a private registry (`.npmrc`: `@myorg:registry=https://npm.internal.example`), avoid pip `--extra-index-url` (use a proxy registry that resolves internal names first), register your internal names publicly as placeholders.
- Minimum release age before adopting new versions (e.g., Renovate `minimumReleaseAge: "3 days"`); malicious versions are usually pulled within hours.
- Review every new dependency: maintainers, age, downloads, Scorecard, install scripts, transitive footprint. Prefer minimal deps and the standard library.
- Pin GitHub Actions to commit SHAs; full CI/CD hardening (least-privilege `GITHUB_TOKEN` via `permissions:`, no secrets for forked PRs, protected branches + required reviews, signed commits, OIDC instead of static cloud keys, ephemeral runners, avoid `pull_request_target` with untrusted code, CODEOWNERS on workflow changes) lives in `kb/06-secure-sdlc/cicd-security.md`.

### SBOM, provenance and signing
- **SBOM** per build in **CycloneDX** or **SPDX**: `syft . -o cyclonedx-json > sbom.cdx.json`; scan it later with `grype sbom:sbom.cdx.json` to answer "are we affected?" for new CVEs. Add VEX to mark non-exploitable findings.
- **SLSA** Build track: L1 provenance exists · L2 hosted build platform, signed provenance · L3 hardened, isolated builds with unforgeable provenance. Target L3 for released artifacts.
- **Sigstore**: `cosign` signs keylessly using OIDC identity, Fulcio issues short-lived certs, Rekor records signatures in a transparency log. Verify identity, not just "signed":
  ```bash
  cosign verify ghcr.io/org/app@sha256:<digest> \
    --certificate-identity-regexp 'https://github.com/org/app/.github/workflows/release.yml@refs/tags/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- Publish with provenance: `npm publish --provenance`, PyPI Trusted Publishing; consumers check with `npm audit signatures`.
- **OpenSSF Scorecard** on your repos and critical deps (Pinned-Dependencies, Token-Permissions, Branch-Protection, Maintained, Signed-Releases).

### Code review checklist
- [ ] Input validation (allowlist, type/length/range) at trust boundaries
- [ ] Output encoding for the context (HTML, JS, SQL via parameterized queries, shell avoided)
- [ ] AuthZ on each endpoint/object (no IDOR); authN not bypassable
- [ ] No secrets in code, config, tests or logs
- [ ] Safe error handling (no stack traces/internal details to users; fail closed)
- [ ] Crypto usage: vetted libraries, no custom crypto, correct modes, CSPRNG (`kb/05-identity-crypto/cryptography.md`)
- [ ] Logging of security events without sensitive data (passwords, tokens, PII)
- [ ] Dependency changes: justified, pinned, lockfile updated, reviewed
- [ ] Deserialization, file upload, SSRF and path handling reviewed (`kb/03-application/owasp-top10.md`)

## How to verify
- SAMM self-assessment score per function, re-run yearly; map controls to SSDF practice IDs (e.g., PW.7 code review, RV.1 vuln identification).
- CI evidence: every merged PR shows SAST/SCA/secret-scan checks passing; branch rules make them required.
- `osv-scanner scan source -r .` and `pip-audit` / `npm audit --omit=dev` return no unaccepted High+.
- `gitleaks git .` over full history returns nothing new.
- `npm ci` / `pip install --require-hashes` succeeds (proves lockfile/hash integrity); grep for `--extra-index-url` and unscoped internal package names.
- Released artifacts: `cosign verify` and `gh attestation verify oci://ghcr.io/org/app@sha256:<digest> --owner org` pass; SBOM attached to each release.
- `scorecard --repo=github.com/org/repo` score trending up; no critical checks at 0.

## References
- NIST SP 800-218 SSDF: https://csrc.nist.gov/pubs/sp/800/218/final
- OWASP SAMM: https://owaspsamm.org · BSIMM
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- SLSA: https://slsa.dev · Sigstore: https://sigstore.dev
- CycloneDX: https://cyclonedx.org · SPDX: https://spdx.dev
- OpenSSF Scorecard: https://github.com/ossf/scorecard · OSV: https://osv.dev
- CISA Secure by Design: https://www.cisa.gov/securebydesign
- See also `kb/06-secure-sdlc/cicd-security.md`, `kb/09-governance/vulnerability-management.md`, `templates/`
