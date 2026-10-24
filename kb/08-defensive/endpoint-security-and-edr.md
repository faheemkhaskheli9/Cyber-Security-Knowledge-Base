# Endpoint Security and EDR

## What
Endpoint security protects laptops, desktops, servers and virtual machines, the hosts where users open email, browse, run code and hold credentials. It combines several layers:
- **EPP** (endpoint protection platform): prevention, such as signature and behavioral anti-malware, exploit protection and firewall.
- **EDR** (endpoint detection and response): continuous telemetry (processes, command lines, file, registry, network, module loads), detection rules, and response actions (isolate host, kill process, quarantine file, collect artifacts). **XDR** correlates EDR with identity, email, cloud and network telemetry; **MDR** is a managed service that runs it for you.
- **Endpoint management** (MDM/UEM such as Microsoft Intune, Jamf, or configuration management for servers): enforces configuration, patching, disk encryption and compliance state, and feeds device posture to conditional access (`kb/01-foundations/zero-trust-architecture.md`).
- **Application control**: only approved code runs (App Control for Business/WDAC or AppLocker on Windows, Gatekeeper and notarization or Santa on macOS, fapolicyd on Linux).

OS configuration baselines are in `kb/04-cloud-infra/os-hardening.md`; this file covers the protection, detection and response stack on top of them and how attackers try to blind it.

## Why it matters
- Most intrusions pass through an endpoint: phishing payloads, malicious downloads and browser extensions, stolen session cookies, and hands-on-keyboard ransomware operators all run on user or server hosts (`kb/08-defensive/ransomware-resilience.md`).
- EDR telemetry is the main evidence source for detection and incident response (`kb/08-defensive/soc-detection-ir.md`, `kb/08-defensive/dfir-malware-threat-intel.md`). A host without an agent, or with a disabled one, is a blind spot.
- Ransomware operators routinely try to disable security tools before encrypting (MITRE ATT&CK T1562.001, Impair Defenses: Disable or Modify Tools), and increasingly target systems where EDR does not run, such as hypervisors, appliances and unmanaged hosts.
- The agent is privileged software in its own right. On 19 July 2024 a faulty CrowdStrike Falcon content update crashed Windows hosts worldwide; Microsoft estimated about 8.5 million devices were affected. Rollout control and recovery planning for the agent itself are part of endpoint security.

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Coverage gaps | Attacker lands on, or pivots to, hosts with no agent: unmanaged laptops, new VMs from images without the agent, Linux servers, ESXi hosts, appliances | Reconcile EDR inventory against CMDB, cloud APIs, AD and DHCP; bake the agent into golden images; NAC or conditional access blocks unmanaged devices; compensating controls (network monitoring, hypervisor hardening) where no agent exists |
| Disabling or uninstalling the agent | Local admin stops services, uninstalls, changes Defender settings or adds exclusions (T1562.001) | Tamper protection on and managed centrally; uninstall token/password; remove local admin rights; alert on sensor going offline or health changes |
| Bring your own vulnerable driver (BYOVD) | Attacker loads a legitimately signed but vulnerable kernel driver to get kernel access and kill EDR processes ("EDR killers") | Microsoft vulnerable driver blocklist and HVCI/Memory integrity; the ASR rule "Block abuse of exploited vulnerable signed drivers"; alert on new driver loads and service creation (Sysmon event 6, Windows 7045); track the LOLDrivers list |
| Safe-mode reboot | Attacker sets the host to boot into safe mode, where many security agents do not start, then encrypts (T1562.009) | Alert on `bcdedit` safe-boot changes; agents that run in safe mode where supported; restrict admin rights |
| Telemetry blocking | Local firewall or Windows Filtering Platform rules stop the agent from reaching its cloud console, so detections never arrive | Alert on hosts that go silent while still seen elsewhere (DHCP, AD logons, network); agent self-protection; restrict who can change firewall policy |
| Exclusion abuse | Attacker reads or adds antivirus exclusions (paths, processes, extensions) and stages tools there | Minimal, specific exclusions reviewed on a schedule; hide exclusions from local admins where the product supports it; alert on exclusion changes |
| Living off the land | Built-in, signed binaries (`powershell`, `rundll32`, `mshta`, `certutil`, `wmic`) execute payloads so there is no malicious file to scan | Behavioral detections on parent/child and command-line patterns; PowerShell script block logging (4104) and Constrained Language Mode; application control; ASR rules (`kb/08-defensive/soc-detection-ir.md`) |
| Credential theft from memory | Dumping LSASS (T1003.001) or browser cookie stores to reuse credentials and sessions | Credential Guard, LSA protection (RunAsPPL), ASR rule "Block credential stealing from the Windows local security authority subsystem"; phishing-resistant MFA and token binding (`kb/05-identity-crypto/identity-access.md`) |
| Initial payloads | Macro documents, ISO/LNK/HTML smuggling attachments, malicious installers and search-ad downloads | Block macros from the internet, ASR rules for Office and email child processes, SmartScreen/Gatekeeper, application control, email filtering (`kb/02-network/email-security.md`) |
| Abuse of remote management tools | Legitimate RMM or remote-access software (installed by the attacker or already present) used for persistence and control | Allowlist approved RMM tools and block others via application control; alert on new RMM installs |
| Malicious or faulty agent update | Compromised vendor update channel, or a defective content update, runs with kernel or SYSTEM privilege on every host | Staged rollouts (pilot ring first) for agent versions and, where the vendor allows, content; vendor due diligence (`kb/09-governance/third-party-risk-management.md`); tested recovery procedure (including BitLocker recovery key access) |

## Defenses

### 1. Coverage and inventory
- Agent on every endpoint and server, including Linux and macOS; include cloud VMs through images or provisioning automation.
- Daily reconciliation: hosts in AD, Intune/Jamf, cloud inventory and DHCP that have no healthy agent are tickets with owners (`kb/09-governance/attack-surface-management.md`).
- Feed device compliance (agent healthy, disk encrypted, patched, managed) into conditional access so a non-compliant device cannot reach sensitive apps.

### 2. Prevention baseline (Windows examples; map to your platforms)
- EDR in **block mode**, cloud-delivered protection and tamper protection on, managed from the console, not by local policy.
- **ASR rules**: start in audit mode, review hits, then block. High-value rules include blocking Office applications from creating child processes, executable content from email and webmail, credential stealing from LSASS, and abuse of exploited vulnerable signed drivers.
- **Application control**: App Control for Business (WDAC) or AppLocker for servers and high-risk users first, starting from Microsoft's recommended block rules; on macOS keep Gatekeeper on and consider Santa; on Linux fapolicyd or equivalent.
- **Credential protection**: Credential Guard and LSA protection where supported; Windows LAPS for local admin passwords (`kb/05-identity-crypto/active-directory-security.md`).
- **Privileges**: users are not local administrators; elevation through a managed, logged mechanism.
- Full-disk encryption (BitLocker, FileVault, LUKS) with recovery keys escrowed centrally.
- Patching of OS, browsers and common third-party apps through management tooling with tracked compliance (`kb/09-governance/vulnerability-management.md`).
- Host firewall on; block inbound SMB/RDP between workstations.

### 3. Detection and response
- Stream EDR alerts and telemetry to the SIEM; correlate with identity and email events (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- High-priority alerts: sensor offline or tampered, protection disabled, exclusion added, new kernel driver, safe-boot configuration change, LSASS access, shadow copy deletion, mass file renames.
- Pre-approve response actions in the IR plan: who may isolate a host, kill processes, or collect memory, and when (`kb/08-defensive/soc-detection-ir.md`). Isolation keeps the host powered on so memory evidence survives.
- Supplement or replace where no commercial agent runs: Sysmon with a maintained configuration on Windows, auditd or eBPF-based sensors (Falco, Tetragon) on Linux, osquery for fleet-wide queries.

### 4. Operating the agent safely
- Deploy agent versions in rings (pilot, then broad), and use vendor options for staged content updates where available.
- Keep an offline recovery runbook: safe-mode or WinPE steps, access to BitLocker recovery keys during an outage, and a way to reach systems when the console is down.
- Restrict console access: SSO with phishing-resistant MFA, least-privilege roles, logging of response actions. The EDR console can run commands on every host; treat it as tier-0.
- Review exclusions quarterly; each has an owner, a reason and an expiry.

### 5. Mobile and BYOD
- Enroll corporate mobile devices in MDM; for BYOD use app protection policies (managed apps, no copy to unmanaged apps) instead of full device control.
- Require a current OS, a screen lock and no jailbreak/root for access to corporate data (NIST SP 800-124 Rev. 2; `kb/03-application/mobile-and-client.md`).

## How to verify
- Coverage report: count of managed hosts versus hosts with a healthy, current agent, by platform and business unit; every gap has an owner.
- Windows Defender state on a sample host (PowerShell):
  ```powershell
  Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, IsTamperProtected
  Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
  ```
  With tamper protection on, `Set-MpPreference -DisableRealtimeMonitoring $true` run as a local admin must not turn protection off.
- Credential Guard and VBS status: `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard`.
- Drop the EICAR test file on a test host; expect detection, quarantine and an alert in the SIEM within your target time.
- Run Atomic Red Team tests for T1003.001, T1059.001, T1562.001 and T1490 in a lab or pilot group with change approval; confirm each is blocked or alerted and that an analyst receives it.
- Simulate a sensor going offline on a test host; confirm the "agent silent" alert fires.
- Exercise an isolation and release on a test host, and a restore of an agent-crashed host using the offline runbook.

## References
- NIST SP 800-83 Rev. 1, Guide to Malware Incident Prevention and Handling for Desktops and Laptops: https://csrc.nist.gov/pubs/sp/800/83/r1/final
- NIST SP 800-124 Rev. 2, Guidelines for Managing the Security of Mobile Devices in the Enterprise: https://csrc.nist.gov/pubs/sp/800/124/r2/final
- MITRE ATT&CK T1562.001, Impair Defenses: Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1562.009, Impair Defenses: Safe Mode Boot: https://attack.mitre.org/techniques/T1562/009/
- Microsoft Defender for Endpoint, attack surface reduction rules reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- Microsoft Defender for Endpoint, tamper protection: https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
- Microsoft Learn, App Control for Business and Microsoft recommended driver block rules (Windows security documentation)
- LOLDrivers, vulnerable and malicious driver list: https://www.loldrivers.io/
- LOLBAS project: https://lolbas-project.github.io/
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon · osquery: https://osquery.io
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team · EICAR test file: https://www.eicar.org
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- CrowdStrike, Channel File 291 incident root cause analysis (August 2024); Microsoft, "Helping our customers through the CrowdStrike outage" (July 2024)
- See also `kb/04-cloud-infra/os-hardening.md`, `kb/08-defensive/soc-detection-ir.md`, `kb/08-defensive/ransomware-resilience.md`, `kb/01-foundations/zero-trust-architecture.md`, `kb/04-cloud-infra/firmware-and-boot-security.md`, `kb/03-application/browser-extension-security.md`
