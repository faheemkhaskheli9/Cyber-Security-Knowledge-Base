# Virtualization and Hypervisor Security

## What
A **hypervisor** runs virtual machines and controls their CPU, memory, disks and networks. **Type 1** hypervisors run on bare metal (VMware ESXi, Microsoft Hyper-V, Xen, KVM in a Linux host such as Proxmox VE); **Type 2** run as an application on a desktop OS (VMware Workstation, VirtualBox). A **management plane** sits on top: vCenter Server, System Center VMM or Windows Admin Center, the Proxmox web UI, plus host shells, APIs and out-of-band controllers (BMC/iLO/iDRAC; `kb/04-cloud-infra/firmware-and-boot-security.md`).

This file covers self-managed virtualization in data centers and private clouds. In public IaaS the provider secures the hypervisor and you secure the guest and its configuration (`kb/04-cloud-infra/cloud-security.md`); containers share a kernel instead of a hypervisor (`kb/04-cloud-infra/containers-kubernetes-iac.md`).

## Why it matters
- **One host, many servers**: whoever controls the hypervisor or vCenter controls every VM on it, including domain controllers, databases and backup servers. It is tier-0 in the same sense as Active Directory (`kb/05-identity-crypto/active-directory-security.md`).
- **Ransomware targets it directly**: many ransomware families ship ESXi/Linux encryptors that stop VMs and encrypt their disk files from the host, taking down every guest at once, beneath the guests' EDR (`kb/08-defensive/ransomware-resilience.md`). The ESXiArgs campaign in February 2023 mass-exploited internet-exposed ESXi hosts through the OpenSLP service (CVE-2021-21974 was the suspected vector).
- **Few defensive tools run there**: ESXi does not run standard EDR agents, so hypervisors are a common blind spot (`kb/08-defensive/endpoint-security-and-edr.md`).
- **Espionage actors persist there**: Mandiant reported in 2022 that UNC3886 installed malicious vSphere Installation Bundles (VIBs) as backdoors on ESXi hosts, and later exploited a vCenter vulnerability (CVE-2023-34048) and a VMware Tools authentication bypass (CVE-2023-20867).
- **Identity integration can backfire**: CVE-2024-37085 let members of an Active Directory group named "ESX Admins" get full admin on domain-joined ESXi hosts; Microsoft reported ransomware operators exploiting it in 2024.

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Exposed management interfaces | ESXi host client, vCenter, Proxmox UI, SLP (427), SSH or BMC reachable from user networks or the internet, then exploited or brute-forced | Dedicated management network reachable only from privileged access workstations or a jump host; SLP disabled; no management interface on the internet (`kb/09-governance/attack-surface-management.md`) |
| vCenter / management server exploitation | Pre-auth RCE in the management appliance (for example CVE-2021-21972, CVE-2021-21985, CVE-2023-34048) gives control of every host | Patch management appliances on KEV timelines; restrict network access to them; disable unused plugins; treat their compromise as full-environment compromise |
| AD-integrated admin abuse | Attacker with domain rights creates or joins an admin group mapped to hypervisor admin (CVE-2024-37085), or reuses a domain admin who is also vCenter admin | Do not domain-join hypervisors, or apply vendor fixes and change default admin group settings; separate, non-domain admin identities for virtualization with phishing-resistant MFA; no shared accounts |
| Mass VM encryption from the host | Shell or SSH on ESXi, then `esxcli`/`vim-cmd` to stop VMs and encrypt `.vmdk`/`.vmx` files (ATT&CK T1486) | SSH and ESXi Shell disabled by default and alerted on when enabled; lockdown mode; `execInstalledOnly` so dropped binaries cannot run; immutable, isolated backups |
| Malicious VIBs / host persistence | Installing a backdoor package at a low acceptance level (CommunitySupported) or forcing install | Acceptance level `PartnerSupported` or stricter; UEFI Secure Boot and TPM so the host refuses unsigned VIBs; review installed VIBs against a baseline |
| Disk and snapshot theft | vCenter or datastore access lets an attacker copy a domain controller's virtual disk or snapshot and extract `NTDS.dit` offline | Restrict datastore browse and download rights; encrypt sensitive VMs (vSphere VM Encryption, Hyper-V shielded VMs); alert on datastore downloads and snapshots of tier-0 VMs |
| Guest-to-host escape | A bug in a virtual device or guest tools lets code in a VM run on the host (for example VENOM, CVE-2015-3456, in the QEMU floppy controller) | Patch hypervisors and guest tools promptly; remove unused virtual devices (floppy, serial, USB, CD); keep untrusted workloads on separate hosts or clusters |
| Backup infrastructure deletion | Attacker uses virtualization or backup console access to delete snapshots, backup jobs and repositories before encrypting | Backup system in a separate identity domain with MFA; immutable or offline copies; deletion requires a second approver where the product supports it |
| Network traffic interception | Promiscuous mode, forged transmits or MAC changes on a virtual switch let one VM sniff or spoof others; vMotion and storage traffic on shared networks | Reject promiscuous mode, MAC address changes and forged transmits on port groups; separate VLANs for management, vMotion and storage; encrypted vMotion for sensitive VMs |

## Defenses

### 1. Isolate and minimize the management plane
- Management, vMotion, storage and BMC interfaces on dedicated VLANs, firewall-restricted to admin jump hosts (`kb/02-network/network-security.md`).
- Disable services you do not use: SSH and ESXi Shell (enable briefly, with a ticket, and alert), SLP/CIM, the Managed Object Browser, and unused web plugins.
- Turn on **lockdown mode** (normal or strict) so hosts are managed only through vCenter; keep a documented exception user list.

### 2. Identity and privilege
- Admins for virtualization use separate accounts with phishing-resistant MFA (identity federation for vCenter, or per-host strong local passwords managed in a vault) (`kb/05-identity-crypto/identity-access.md`).
- Prefer not to join ESXi hosts to Active Directory; a domain compromise then does not automatically become a hypervisor compromise. If you must, apply the vendor's guidance for CVE-2024-37085 and audit the mapped admin group.
- Least-privilege vCenter roles: operators cannot browse or download datastores, change host settings or manage backups unless needed.
- Account lockout on host logins (`Security.AccountLockFailures`) and session timeouts for shells.

### 3. Host integrity
- UEFI Secure Boot with TPM 2.0 on hosts; on ESXi 7.0 U2 and later, enforce it and `execInstalledOnly` through the host encryption settings so only signed, installed binaries execute:
  ```bash
  esxcli system settings encryption set --require-secure-boot=T --require-exec-installed-only=T
  esxcli system settings encryption get
  ```
  Back up the host's recovery key before enforcing.
- Acceptance level `PartnerSupported` or stricter (`esxcli software acceptance set --level=PartnerSupported`); never force-install VIBs.
- Patch hypervisors, management appliances, guest tools and host firmware on a defined schedule; hypervisor and vCenter entries in CISA KEV are emergencies (`kb/09-governance/vulnerability-management.md`). Replace versions that are out of vendor support.
- Hyper-V and KVM: harden the host OS like any tier-0 server (`kb/04-cloud-infra/os-hardening.md`): minimal role install (Server Core for Hyper-V), Credential Guard and VBS where supported; for KVM/QEMU keep sVirt (SELinux or AppArmor confinement of each VM process) and seccomp enabled.

### 4. Protect the VMs that matter most
- Run tier-0 VMs (domain controllers, PKI, IdP, backup servers) on a separate cluster or hosts with a smaller admin group.
- Encrypt tier-0 VMs (vSphere VM Encryption with a key provider, Hyper-V shielded VMs with Host Guardian Service, or confidential VMs such as AMD SEV-SNP or Intel TDX where available) so disk copies are useless.
- Remove unused virtual hardware and disable guest-host features you do not need (shared folders, clipboard copy/paste, drag and drop).

### 5. Backups and recovery
- Back up VMs to a system with its own identity domain, MFA, and immutable or offline copies; the hypervisor admin must not be able to delete them (`kb/08-defensive/ransomware-resilience.md`).
- Keep a rebuild runbook: install media, host configuration as code or exported host profiles, and a tested restore of vCenter and a domain controller.

### 6. Logging and detection
- Forward host and vCenter logs (syslog) to the SIEM; local logs on an encrypted host are lost (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on: SSH or shell enabled, lockdown mode disabled, new local accounts or permissions, acceptance level changes, VIB installs, mass VM power-off, datastore file downloads, snapshot deletion, logins from outside the jump hosts, and changes to the AD group mapped to admin.
- Where no agent runs on the host, use network monitoring of the management VLAN and vendor-supported logging as compensating controls.

## How to verify
- From a user workstation and from the internet (authorized scope), confirm ESXi/vCenter/Proxmox UI ports, 427 (SLP), 22 and BMC ports are unreachable: `nmap -p 22,80,443,427,902,5480,8006 <mgmt-range>`.
- On each ESXi host:
  ```bash
  esxcli system settings encryption get           # Require Secure Boot / Require Executables Only From Installed VIBs: true
  esxcli software acceptance get                  # PartnerSupported or stricter
  esxcli software vib list                        # compare with the approved baseline
  esxcli network firewall ruleset list -r CIMSLP  # Enabled: false
  ```
- PowerCLI inventory of lockdown and SSH state:
  ```powershell
  Get-VMHost | Select-Object Name, @{N='Lockdown';E={$_.ExtensionData.Config.LockdownMode}}
  Get-VMHost | Get-VMHostService | Where-Object Key -eq 'TSM-SSH' | Select-Object VMHost, Running, Policy
  ```
- Confirm a domain admin account (in a test) cannot log in to vCenter or a host, and that the vCenter admin cannot delete immutable backups.
- Enable SSH on a test host and confirm the SIEM alert fires.
- Run a restore exercise: rebuild a host from install media and restore vCenter and a domain controller from backup within your target time.

## References
- NIST SP 800-125, Guide to Security for Full Virtualization Technologies: https://csrc.nist.gov/pubs/sp/800/125/final
- NIST SP 800-125A Rev. 1, Security Recommendations for Server-based Hypervisor Platforms: https://csrc.nist.gov/pubs/sp/800/125/a/r1/final
- CIS Benchmarks (VMware ESXi and others): https://www.cisecurity.org/cis-benchmarks
- Broadcom/VMware, vSphere Security Configuration and Hardening Guide, and vSphere Security documentation
- NVD, CVE-2024-37085: https://nvd.nist.gov/vuln/detail/CVE-2024-37085
- Microsoft Security Blog, "Ransomware operators exploit ESXi hypervisor vulnerability for mass encryption" (July 2024)
- Mandiant, "Bad VIB(E)s Part One: Investigating Novel Malware Persistence Within ESXi Hypervisors" (2022)
- CISA, ESXiArgs-Recover script and ESXiArgs advisory (February 2023): https://github.com/cisagov/ESXiArgs-Recover
- MITRE ATT&CK T1486, Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- CISA Known Exploited Vulnerabilities catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- See also `kb/08-defensive/ransomware-resilience.md`, `kb/05-identity-crypto/active-directory-security.md`, `kb/04-cloud-infra/firmware-and-boot-security.md`, `kb/04-cloud-infra/os-hardening.md`, `kb/08-defensive/endpoint-security-and-edr.md`
