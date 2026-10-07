# Tools and Cheat Sheets

Open-source first. Offensive tools are for **authorized** targets only.

## Tools by task

| Task | Tools |
|---|---|
| Secrets scanning | gitleaks, trufflehog, detect-secrets, GitHub push protection |
| SAST | Semgrep, CodeQL, Bandit (Python), gosec (Go), Brakeman (Rails), SpotBugs+FindSecBugs (Java) |
| SCA / dependencies | OSV-Scanner, Trivy, Grype, Dependabot, Renovate, `npm audit`, `pip-audit`, `cargo audit` |
| SBOM | Syft, CycloneDX tools, `docker sbom` |
| Containers / IaC | Trivy, Checkov, tfsec/Trivy config, kube-bench, kube-linter, Hadolint, Dockle |
| CI/CD | zizmor, actionlint, OpenSSF Scorecard, harden-runner |
| Signing / provenance | Sigstore cosign, gh attestation, in-toto |
| Cloud posture | Prowler, ScoutSuite, Steampipe, CloudSploit |
| DAST / web testing | OWASP ZAP, Burp Suite, nuclei, ffuf, sqlmap |
| Network | nmap, masscan, Wireshark, tcpdump, Zeek, Suricata |
| TLS / DNS | testssl.sh, sslyze, dnsviz, dig, subfinder |
| AD / identity | BloodHound, PingCastle, Certipy |
| Detection / SIEM | Wazuh, Elastic Security, Sigma (sigma-cli), YARA, Velociraptor, osquery |
| Forensics | Volatility 3, Autopsy/Sleuth Kit, KAPE, Plaso, CyberChef |
| Malware analysis | Ghidra, x64dbg, FLARE-VM, REMnux, CAPE sandbox |
| Threat intel | MISP, OpenCTI, VirusTotal, abuse.ch feeds |
| Red team / emulation | Atomic Red Team, Caldera, Sliver, Mythic |
| Hardening audit | Lynis, CIS-CAT, OpenSCAP, HardeningKitty (Windows) |

## Quick commands

**Secrets and dependencies**
```bash
gitleaks detect --source . --redact -v           # scan repo + history
trufflehog git file://. --only-verified
osv-scanner scan -r .                            # all lockfiles
trivy fs --scanners vuln,secret,misconfig .
```

**SAST**
```bash
semgrep scan --config auto --error
bandit -r src/ -ll
```

**Containers and IaC**
```bash
trivy image --severity HIGH,CRITICAL myimage:tag
hadolint Dockerfile
checkov -d .                                     # Terraform, K8s, CloudFormation, Dockerfile
kube-bench run                                   # CIS K8s benchmark (on node)
```

**CI/CD**
```bash
zizmor .github/workflows/
actionlint
scorecard --repo=github.com/OWNER/REPO
```

**TLS / headers / DNS**
```bash
testssl.sh example.com
curl -sI https://example.com | grep -iE 'strict-transport|content-security|x-content-type|referrer|permissions'
dig +short TXT _dmarc.example.com; dig CAA example.com
```

**Network (authorized scope only)**
```bash
nmap -sV -sC -p- -T4 -oA scan target             # full TCP with service detection
nmap -sU --top-ports 100 target
```

**Linux triage**
```bash
ss -tulpn; ps auxf; last -a; journalctl -u ssh --since "24h ago"
find / -perm -4000 -type f 2>/dev/null           # SUID binaries
crontab -l; ls -la /etc/cron.* ~/.ssh/authorized_keys
```

**Windows triage (PowerShell)**
```powershell
Get-NetTCPConnection -State Listen
Get-ScheduledTask | ? State -ne 'Disabled'
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50
Get-CimInstance Win32_StartupCommand
```

**Crypto helpers**
```bash
openssl rand -base64 32                          # random secret
openssl s_client -connect host:443 -servername host </dev/null | openssl x509 -noout -dates -subject -issuer
```

## Cheat sheet sources
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org
- GTFOBins (Linux) / LOLBAS (Windows): defenders use them to know which binaries to monitor
- HackTricks: offensive reference for authorized testing
- SANS posters (DFIR, Windows forensics, Hunt Evil)
- MITRE ATT&CK Navigator · D3FEND
