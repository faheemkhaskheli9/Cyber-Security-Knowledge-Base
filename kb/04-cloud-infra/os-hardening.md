# OS Hardening

## What
Reducing the attack surface of Linux, Windows and macOS hosts: patch, remove what is not needed, restrict privilege, enforce mandatory controls and log what happens. Baselines: CIS Benchmarks, DISA STIGs, Microsoft Security Baselines.

## Why it matters
- Most intrusions end on a host: unpatched services, weak SSH/RDP, local admin reuse and missing logging turn one foothold into domain or fleet compromise.
- Active Directory remains the core of most enterprise breaches and ransomware.
- Hardened defaults block or make noisy whole classes of attack (credential dumping, lateral movement, macro malware).

## Attacks
For authorized testing only; each is paired with its defense.
- **Brute force / password spraying on SSH and RDP** → key-only SSH, no exposed RDP (use VPN/bastion), `fail2ban`/lockout, MFA.
- **Local privilege escalation** (SUID binaries, writable cron/service files, kernel CVEs, misconfigured `sudo`) → patching, minimal packages, `sudo` least privilege, file permission audits.
- **Credential dumping** (LSASS, SAM) → Credential Guard, LSA protection (RunAsPPL), ASR rule blocking LSASS credential theft, no local admin for users.
- **Pass-the-Hash / Pass-the-Ticket** → LAPS (unique local admin passwords), tiered admin, Protected Users, restrict NTLM.
- **Kerberoasting / AS-REP roasting** → gMSAs or 25+ character service account passwords, AES-only, Kerberos pre-auth required; detect event 4769 with RC4 tickets.
- **DCSync** → restrict replication rights to DCs; alert on 4662 replication GUIDs from non-DC hosts.
- **Golden Ticket** → protect DCs as Tier 0, rotate `krbtgt` twice after compromise.
- **Unconstrained delegation** → remove it; mark sensitive accounts "cannot be delegated".
- **AD CS misconfigs (ESC1–8 and later)** → see `kb/05-identity-crypto/pki-and-tls.md`.
- **LLMNR/NBT-NS poisoning and SMB relay** → disable LLMNR/NetBIOS, require SMB signing, disable SMBv1.
- **Living-off-the-land** (PowerShell, `mshta`, `rundll32`) → PowerShell logging + Constrained Language Mode, AppLocker/WDAC, ASR rules.
Audit tools: PingCastle, BloodHound (authorized use).

## Defenses

### Linux
- **Patch automatically**: `unattended-upgrades` (Debian/Ubuntu) or `dnf-automatic` (RHEL/Fedora); schedule reboots for kernel updates or use livepatch.
- **Minimal packages**: remove compilers, unused daemons; `systemctl list-unit-files --state=enabled` and disable what is not needed.
- **SSH** (`/etc/ssh/sshd_config.d/10-hardening.conf`), disable root SSH + password auth (keys only):
```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowGroups ssh-users
ClientAliveInterval 300
```
  Validate with `sshd -t` before restart; add `fail2ban`/rate limits.
- **sudo least privilege**: specific commands per group, no `NOPASSWD: ALL`, `Defaults use_pty,logfile=/var/log/sudo.log`; edit with `visudo`.
- **Firewall** (`nftables`/`ufw`) default-deny: `ufw default deny incoming && ufw allow from 10.0.0.0/8 to any port 22 proto tcp && ufw enable`.
- **SELinux/AppArmor enforcing**: `getenforce` → `Enforcing`; `aa-status`. Fix policies rather than disabling.
- **auditd**: watch identity files, sudoers, and privileged execs, e.g. `-w /etc/passwd -p wa -k identity`, `-w /etc/sudoers -p wa -k scope`; forward to SIEM.
- **File integrity (AIDE)**: `aide --init`, schedule `aide --check`.
- **File permissions**: `/etc/shadow` 0640 or stricter, no world-writable files outside `/tmp`, review SUID/SGID (`find / -xdev -perm -4000`).
- **Separate partitions** with `noexec,nosuid,nodev` where possible (`/tmp`, `/var/tmp`, `/dev/shm`, `/home` with `nosuid,nodev`).
- **Kernel sysctl hardening** (`/etc/sysctl.d/99-hardening.conf`):
```
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
```

### Windows / Active Directory
- **Patch** monthly (WSUS/Intune/Autopatch); remove unsupported OS versions.
- **LAPS** (Windows LAPS) for unique, rotated local admin passwords; restrict who can read them.
- **Credential Guard** and LSA protection (RunAsPPL) to protect LSASS.
- **Defender ASR rules** in block mode (e.g., block credential stealing from LSASS, Office child processes, executable content from email); start in audit mode.
- **PowerShell logging + constrained language**: script block logging, module logging, transcription; Constrained Language Mode enforced via WDAC; remove PowerShell v2.
- **SMB**: disable SMBv1, require SMB signing on clients and servers; disable NTLM where possible (audit first, then restrict).
- **Disable LLMNR** (GPO: "Turn off multicast name resolution") and **NetBIOS over TCP/IP**.
- **BitLocker** with TPM (+PIN for laptops), recovery keys escrowed to AD/Entra ID.
- **AppLocker/WDAC** application allowlisting; start with Microsoft recommended block rules.
- **Tiered admin model** (Tier 0 = DCs, AD CS, identity systems), PAWs for admins, Protected Users group, restrict local admin, no domain admin logons to workstations.
- **AD hygiene**: gMSAs, remove unconstrained delegation, clean ACLs, monitor privileged group changes (4728/4732/4756).

### macOS
FileVault, Gatekeeper, SIP, MDM, firewall on, auto-update; enforce via MDM configuration profiles; standard (non-admin) daily accounts.

## How to verify
- Linux: `lynis audit system` (track hardening index), OpenSCAP `oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis --report report.html <ssg-datastream.xml>`.
- `sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'` · `sysctl -a | grep kptr_restrict` · `auditctl -l` · `nft list ruleset`.
- Windows: HardeningKitty (audit mode against CIS/Microsoft lists), Microsoft Security Compliance Toolkit (Policy Analyzer).
- `Get-MpPreference | Select AttackSurfaceReductionRules_*` · `Get-SmbServerConfiguration | Select RequireSecuritySignature,EnableSMB1Protocol` · `manage-bde -status` · `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`.
- AD: PingCastle health check, BloodHound attack paths (authorized use), Purple Knight.
- Remote: `nmap -sV` to confirm only expected ports are exposed.

## References
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- DISA STIGs: https://public.cyber.mil/stigs/
- Microsoft Security Baselines and Security Compliance Toolkit (Microsoft Learn)
- Microsoft "Securing privileged access" (enterprise access model) docs
- NIST SP 800-123 (General Server Security) · NIST SP 800-53 (CM, AC, AU families)
- Lynis: https://cisofy.com/lynis/ · OpenSCAP: https://www.open-scap.org · HardeningKitty (GitHub: scipag/HardeningKitty)
- MITRE ATT&CK: https://attack.mitre.org
- See also `kb/05-identity-crypto/identity-access.md`, `kb/05-identity-crypto/pki-and-tls.md`, `kb/08-defensive/soc-detection-ir.md`, `kb/04-cloud-infra/containers-kubernetes-iac.md`
