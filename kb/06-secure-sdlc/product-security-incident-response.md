# Product Security Incident Response (PSIRT) and Coordinated Vulnerability Disclosure

## What
A **PSIRT** (Product Security Incident Response Team) is the function that receives, triages, fixes and discloses vulnerabilities in the software, devices or services an organization ships. It differs from a CSIRT/SOC, which responds to attacks on the organization's own systems (`kb/08-defensive/soc-detection-ir.md`). The core process is **coordinated vulnerability disclosure (CVD)**: the reporter and vendor keep details private while a fix is prepared, then publish together.

Main standards and building blocks:
- **ISO/IEC 29147** (vulnerability disclosure: receiving reports, publishing advisories) and **ISO/IEC 30111** (internal vulnerability handling process).
- **FIRST PSIRT Services Framework**: the service areas a PSIRT operates (stakeholder ecosystem, intake, analysis, remediation, disclosure, training).
- **CVE**: identifiers assigned by CVE Numbering Authorities (CNAs); a vendor can become a CNA for its own products, or use one such as GitHub for repository advisories.
- **CVSS** (v4.0 current) for technical severity, plus exploitation data (EPSS, CISA KEV) for priority (`kb/09-governance/vulnerability-management.md`).
- **CSAF 2.0** (OASIS): machine-readable security advisories, including the VEX profile.
- **VEX** (Vulnerability Exploitability eXchange): per-product statements of `not_affected`, `affected`, `fixed` or `under_investigation` for a given vulnerability, published as CSAF, OpenVEX or CycloneDX.

The intake side for outsiders (VDP, `security.txt`, bug bounty) is in `kb/07-offensive/red-team-and-bug-bounty.md`; this file covers what happens after a report arrives.

## Why it matters
- Customers cannot patch what the vendor has not disclosed. Slow or silent handling leaves every customer exposed, and researchers who get no answer may publish without a fix.
- When a widely used component has a critical flaw (Log4Shell, December 2021), every customer asks "are we affected?" at once. Without an SBOM and VEX process, answers take days of manual work.
- Regulation now requires it. The EU Cyber Resilience Act (Regulation (EU) 2024/2847) requires manufacturers of products with digital elements to handle vulnerabilities and have a CVD policy, and from 11 September 2026 to report actively exploited vulnerabilities and severe incidents through ENISA's single reporting platform: an early warning within 24 hours, a notification within 72 hours and a final report later. Check the regulation text for exact scope and deadlines.
- Published patches are reverse-engineered quickly. Exploits for "n-day" vulnerabilities often appear soon after a fix ships, so the advisory, patch and guidance must be ready at the same moment.

## Attacks
*Failure modes and adversary behavior around disclosure. Each lists its main defense.*

| Failure or attack | What happens | Defense |
|---|---|---|
| No intake channel | Researchers cannot find a contact, report via social media or public issues, or give up and publish | `SECURITY.md`, `/.well-known/security.txt` (RFC 9116), private vulnerability reporting on code hosts, a monitored alias with an encrypted option |
| Report ignored or lost | Report sits in a general inbox; reporter sees no response and goes public (full disclosure of a 0-day) | Ticketed intake, acknowledgement target (example: 3 business days, matching `templates/SECURITY.md`), on-call owner, regular status updates to the reporter |
| Fix leaks before release | Fix commits, branch names, public CI logs or test cases in a public repo reveal the bug before users can patch | Develop the fix in a private fork (for example a GitHub temporary private fork attached to a draft advisory); generic commit messages; publish fix, release and advisory together |
| Silent patching | Fix ships with no advisory or CVE; customers do not prioritize the update, while attackers diff the patch | Always publish an advisory and CVE for security fixes; state affected and fixed versions |
| Incomplete advisory | Wrong affected-version range, missing backports or missing workaround; customers think they are safe | Variant analysis across branches and products; test fixed versions; machine-readable advisory (CSAF/OSV) reviewed before publication |
| Embargo breach | A party in a multi-vendor coordination (or an insider) discloses early | Need-to-know distribution list, written embargo terms, short realistic embargoes, a plan to publish immediately if details leak |
| Fake or extortion reports | Low-quality automated reports, "beg bounty" demands, or threats to publish unless paid | Triage criteria, reproducible PoC required, published policy on rewards and safe harbor; route extortion to legal |
| Researcher handling customer data | A report includes real customer data or the researcher accessed more than needed | Policy limits testing to own accounts and minimal proof; treat any accessed data as a potential incident and run IR (`kb/08-defensive/soc-detection-ir.md`) |
| Exploited before disclosure | Vulnerability is already being exploited in the wild when reported | Escalation path to the incident process, faster fix and advisory track, customer notification with indicators, regulatory reporting where required (CRA, sector rules) |

## Defenses

### 1. Policy and intake
- Publish a disclosure policy: scope, how to report, what reporters can expect (acknowledgement, updates, credit), safe-harbor language (disclose.io templates), and the default disclosure deadline. Common reference points: CERT/CC defaults to 45 days; Google Project Zero uses 90 days plus 30 days after a fix before publishing details.
- Intake through `SECURITY.md`, `security.txt` with a current `Expires`, and private reporting on the code host; one ticket per report, never in a public tracker.
- Define severity with CVSS v4.0 and adjust priority with exploitation evidence and product exposure; record the vector string.

### 2. Handling (ISO/IEC 30111)
1. **Acknowledge** and assign an owner.
2. **Reproduce and assess**: affected products, versions, configurations, and components shared with other products (variant analysis).
3. **Fix** in private, with tests that reproduce the bug; backport to every supported version listed in the support policy.
4. **Prepare disclosure**: advisory text, CVE request (own CNA or a CNA such as GitHub), CSAF/OSV record, VEX statements for related products, customer guidance and workarounds, credit for the reporter.
5. **Release** fix, advisory and CVE record together; notify downstream distributors and major customers under embargo first if needed.
6. **Learn**: root-cause analysis, add a SAST rule or test for the bug class (`kb/06-secure-sdlc/secure-code-review.md`), track recurring classes across releases.

### 3. Third-party and open-source components
- Maintain an SBOM per release (`kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`) and match it daily against OSV, NVD and vendor advisories.
- For each relevant upstream CVE publish a VEX statement. CISA's minimum requirements give five justifications for `not_affected`: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`. Only claim `not_affected` with evidence.
- Report bugs you find in upstream projects through their own CVD process.

Example OpenVEX statement (illustrative values):

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2026-0001",
  "author": "Example Corp PSIRT",
  "timestamp": "2026-10-24T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "CVE-2021-44228" },
      "products": [ { "@id": "pkg:generic/example-app@4.2.0" } ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "JNDI lookup class removed from the bundled log4j-core at build time."
    }
  ]
}
```

### 4. Publication
- Advisory contents: identifier and CVE, title, affected and fixed versions, severity with vector, description without a weaponized exploit, workarounds, detection guidance where useful, credit, revision history.
- Machine-readable feeds: CSAF 2.0 providers publish `/.well-known/csaf/provider-metadata.json`; open-source projects publish to OSV through GitHub Security Advisories or their ecosystem database.
- Keep advisories updated (new affected versions, exploitation status) and version them.

### 5. Organization
- Named PSIRT owner, on-call rota, documented escalation to legal, communications, customer support and the incident process.
- Supported-versions and end-of-life policy published, so customers know which releases get fixes.
- Metrics: time to acknowledge, time to fix by severity, share of fixes released with an advisory, reporter satisfaction, recurring bug classes.

Check a published `security.txt` (standard library; `Contact` and `Expires` are required by RFC 9116, which recommends `Expires` less than a year ahead):

```python
from datetime import datetime, timedelta, timezone

def check_security_txt(text: str, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(timezone.utc)
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith("#"):
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    problems = []
    if not fields.get("contact"):
        problems.append("missing Contact")
    expires = fields.get("expires", [])
    if len(expires) != 1:
        problems.append("Expires must appear exactly once")
    else:
        exp = datetime.fromisoformat(expires[0].replace("Z", "+00:00"))
        if exp <= now:
            problems.append("Expires is in the past")
        elif exp - now > timedelta(days=366):
            problems.append("Expires is more than a year ahead")
    return problems

sample = "Contact: mailto:security@example.com\nExpires: 2027-06-30T00:00:00Z\nPolicy: https://example.com/security-policy\n"
assert check_security_txt(sample, datetime(2026, 10, 24, tzinfo=timezone.utc)) == []
assert "Expires is in the past" in check_security_txt(sample, datetime(2027, 7, 1, tzinfo=timezone.utc))
```

## How to verify
- Send a test report through each published channel (email, form, private reporting); confirm it creates a ticket and is acknowledged within the stated target.
- `curl -s https://<domain>/.well-known/security.txt` returns a file with a working `Contact` and a future `Expires`; `SECURITY.md` exists in every public repository (`templates/SECURITY.md`).
- Tabletop: a critical bug in a shared library across several products, one already exploited. Walk through triage, fix, embargoed partner notification, advisory, CVE, VEX and any regulatory report, and time each step.
- Sample recent advisories: each has a CVE, correct affected and fixed versions, a CVSS vector, and a matching CSAF/OSV record; no security fix in the changelog lacks an advisory.
- For the last few high-profile upstream CVEs, check that customers could get a VEX or advisory answer for every product.

## References
- ISO/IEC 29147:2018, Vulnerability disclosure; ISO/IEC 30111:2019, Vulnerability handling processes
- FIRST PSIRT Services Framework: https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1
- FIRST, Guidelines and Practices for Multi-Party Vulnerability Coordination and Disclosure (Vulnerability Coordination SIG)
- CERT/CC, The CERT Guide to Coordinated Vulnerability Disclosure: https://certcc.github.io/CERT-Guide-to-CVD/
- CVE Program (CNA rules and partner list): https://www.cve.org
- CVSS v4.0 specification: https://www.first.org/cvss/v4-0/
- OASIS CSAF 2.0: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
- CISA, Minimum Requirements for VEX and VEX Status Justifications: https://www.cisa.gov/sbom
- OpenVEX specification: https://github.com/openvex/spec
- RFC 9116, security.txt: https://www.rfc-editor.org/rfc/rfc9116
- Regulation (EU) 2024/2847, Cyber Resilience Act: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- GitHub Docs, repository security advisories and private vulnerability reporting: https://docs.github.com/en/code-security/security-advisories
- Google Project Zero, Vulnerability Disclosure Policy (Project Zero blog); CERT/CC Vulnerability Disclosure Policy
- disclose.io: https://disclose.io · OSV: https://osv.dev
- See also `kb/07-offensive/red-team-and-bug-bounty.md`, `kb/09-governance/vulnerability-management.md`, `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/09-governance/grc-compliance-privacy.md`, `templates/SECURITY.md`
