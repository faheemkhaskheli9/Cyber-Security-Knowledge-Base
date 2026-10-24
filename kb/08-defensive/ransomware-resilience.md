# Ransomware Resilience – Prevent, Contain, Recover

## What
Ransomware is extortion: an intruder gains access, escalates, moves laterally, steals data, then encrypts systems and demands payment for a decryptor and for not leaking the data ("double extortion"). Most operations run as Ransomware-as-a-Service: affiliates buy access from initial-access brokers and rent the encryptor. Resilience means making each stage harder, detecting the intrusion before encryption, and being able to restore without paying.

## Why it matters
- Encryption is the last step. Intruders usually spend days inside first (discovery, credential theft, backup deletion), which is the window detection has to use.
- Backups are a primary target: operators look for backup consoles, hypervisor admin and cloud snapshots and delete them before encrypting. A backup the attacker's domain admin can delete is not a recovery plan.
- Paying does not guarantee a working decryptor or deletion of stolen data, can breach sanctions rules (check OFAC/local guidance), and many jurisdictions require breach notification regardless.

## Attacks
*Described so defenders can recognise each stage; mapped to MITRE ATT&CK.*
- **Initial access**: exposed RDP/VPN with weak or reused passwords and no MFA, exploitation of edge devices (VPN appliances, file-transfer servers; see CISA KEV), phishing with loaders, stolen credentials bought from infostealer logs.
- **Escalation and lateral movement**: credential dumping (LSASS), Kerberoasting, abuse of AD CS and delegation (see `kb/05-identity-crypto/active-directory-security.md`), remote management tools and PsExec/WMI, LOLBins.
- **Defense impairment** (T1562, T1490): disabling EDR, deleting Volume Shadow Copies (`vssadmin delete shadows`), stopping backup agents, wiping backup catalogs, encrypting hypervisors (ESXi) to hit every VM at once.
- **Exfiltration** (T1567): rclone, cloud storage uploads, or archive-and-transfer before encryption.
- **Impact** (T1486): mass file encryption, often pushed via GPO or management tools; ransom note; leak-site pressure.

## Defenses

### Prevent initial access
- No RDP/SMB exposed to the internet; VPN and remote access behind phishing-resistant MFA (FIDO2) and patched on a KEV-driven timeline (see `kb/09-governance/vulnerability-management.md`).
- Email and browser controls (`kb/02-network/email-security.md`), application allowlisting on servers, macros blocked from the internet.

### Limit blast radius
- Tiered admin model, LAPS, no domain admin on workstations, separate admin accounts with MFA; remove standing privilege where possible (`kb/05-identity-crypto/identity-access.md`).
- Network segmentation: workstations cannot reach server management ports or each other over SMB/RDP; backup and hypervisor management on an isolated network (`kb/01-foundations/zero-trust-architecture.md`).
- EDR on every endpoint and server, with tamper protection on, and alerts on shadow-copy deletion, mass file renames and new remote-admin tools.

### Backups that survive the attacker
- **3-2-1-1-0**: 3 copies, 2 media types, 1 offsite, 1 immutable or offline, 0 errors on restore verification.
- Immutability enforced by the storage, not by the backup software alone: object lock in compliance mode (S3 Object Lock, Azure immutable blob), WORM, or offline/air-gapped media.
- Backup system identity separate from the production domain (own accounts, MFA, no AD trust); deletion or retention changes require a second person or a delay.
- Back up the things you need to rebuild: identity (AD system state, IdP configuration), infrastructure-as-code, secrets/KMS recovery material, and the backup catalog itself.

### Plan the recovery
- Written playbook (`kb/08-defensive/soc-detection-ir.md`): who decides on isolation, how to contact legal, insurer, regulators and law enforcement, out-of-band communication if email and chat are down.
- Restore order defined by business impact (identity first, then core apps), with RTO/RPO agreed per system.
- Rebuild from known-good images and IaC rather than cleaning encrypted hosts; rotate all credentials (especially `krbtgt` twice, service accounts, cloud keys) before reconnecting.

## How to verify
- Restore test at least quarterly: pick a critical system at random, restore it into an isolated network, and time it against the RTO. Record the result.
- Try to delete or shorten retention on an immutable backup with a production admin account: it must fail.
- From a workstation, scan for reachable RDP/SMB/WinRM on servers and for backup and hypervisor management interfaces: they should be unreachable.
- Run Atomic Red Team tests for T1490 (inhibit system recovery) and T1486 in a lab and confirm EDR blocks or alerts.
- External attack-surface scan for exposed RDP, VPN version banners and KEV-listed products.
- Tabletop a ransomware scenario with leadership once a year, including the pay/no-pay decision and notification duties.

## References
- CISA #StopRansomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
- NIST IR 8374, Ransomware Risk Management (CSF profile): https://csrc.nist.gov/pubs/ir/8374/final
- MITRE ATT&CK T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/ · T1490 Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- CISA Known Exploited Vulnerabilities catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- No More Ransom (free decryptors): https://www.nomoreransom.org
- See also `kb/08-defensive/dfir-malware-threat-intel.md`, `kb/05-identity-crypto/active-directory-security.md`, `kb/04-cloud-infra/database-security.md`, `kb/08-defensive/endpoint-security-and-edr.md`, `kb/08-defensive/cloud-incident-response.md`, `kb/04-cloud-infra/virtualization-and-hypervisor-security.md`, `kb/02-network/edge-device-security.md`
