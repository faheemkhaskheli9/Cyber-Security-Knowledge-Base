# OS Hardening

## Linux
Patch automatically, disable root SSH + password auth (keys only), `fail2ban`/rate limits, firewall (`nftables`/`ufw`) default-deny, minimal packages, SELinux/AppArmor enforcing, `sudo` least privilege, auditd, file integrity (AIDE), separate partitions with `noexec,nosuid` where possible, kernel sysctl hardening, CIS Benchmark / Lynis.

## Windows / Active Directory
Patch, LAPS, Credential Guard, disable SMBv1/NTLM where possible, tiered admin model, Protected Users, restrict local admin, AppLocker/WDAC, PowerShell logging + constrained language, BitLocker, Defender ASR rules. AD attacks to defend: Kerberoasting, AS-REP roasting, Pass-the-Hash/Ticket, DCSync, Golden Ticket, unconstrained delegation, AD CS misconfigs (ESC1–8). Tools to audit: PingCastle, BloodHound (authorized use).

## macOS
FileVault, Gatekeeper, SIP, MDM, firewall on, auto-update.
