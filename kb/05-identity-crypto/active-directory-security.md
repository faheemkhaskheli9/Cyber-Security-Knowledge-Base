# Active Directory and Entra ID Hybrid Security

## What
Active Directory Domain Services (AD DS) is the on-premises directory that authenticates users and computers with Kerberos and NTLM. Group Policy configures them, and AD Certificate Services (AD CS) issues their certificates. Most enterprises run it **hybrid** with Microsoft Entra ID: Entra Connect (Sync or Cloud Sync) copies identities to the cloud, and sign-in uses password hash sync (PHS), pass-through authentication (PTA) or federation (AD FS). This file takes the defender's view: how AD gets compromised, how to stop it, and how to detect it. General IAM is in `kb/05-identity-crypto/identity-access.md`, and host hardening is in `kb/04-cloud-infra/os-hardening.md`.

**Tier 0** is everything that can control the identity plane: domain controllers (DCs), AD CS, Entra Connect servers, AD FS, PTA agents, the PAWs of Tier 0 admins, and any account or group with control over those systems.

## Why it matters
- Ransomware operators routinely go from one phished workstation to Domain Admin, then deploy ransomware through GPO or remote execution. AD is the usual path to "everything encrypted".
- One mistake can expose the whole domain: a single misconfigured certificate template, a weak service account password, or one ACL can lead straight to Tier 0.
- Hybrid links the two planes. A compromise of on-prem Tier 0 (Entra Connect, AD FS signing keys, Seamless SSO keys) can spread into Entra ID and M365, and over-privileged synced accounts expose the cloud side to on-prem attackers.
- Recovering from a full compromise is very expensive: you rotate krbtgt twice, rotate every privileged and service credential, rebuild Tier 0, and often run a forest recovery.

## Attacks
Each attack is described at concept level only and paired with its defense and detection. Test only in environments you are authorized to test (see `kb/07-offensive/pentest-methodology.md`).

| Attack | How it works (concept) | Defense | Detection |
|---|---|---|---|
| **Kerberoasting** (T1558.003) | Any domain user can request a service ticket for an account that has an SPN. Part of the ticket is encrypted with the service account's key, so the attacker can crack a weak password offline. | gMSAs; 25+ character random passwords on any remaining service accounts; AES only (`msDS-SupportedEncryptionTypes`); no SPNs on privileged accounts | 4769 with `TicketEncryptionType 0x17` (RC4), or one account requesting many SPNs; honeypot SPN account |
| **AS-REP roasting** (T1558.004) | Accounts with "Do not require Kerberos preauthentication" return an AS-REP that can be cracked offline, without needing any credentials. | Require preauth on every account; strong passwords | 4768 with `PreAuthType 0`; alert on the UAC flag being set (4738) |
| **Password spraying** (T1110.003) | The attacker tries a few common passwords against many accounts, staying under lockout thresholds. | Entra Password Protection banned lists (on-prem agent on DCs too), MFA, smart lockout, block legacy auth | 4625/4771 failures across many users from one source; 4776 bursts; Entra sign-in risk |
| **NTLM relay** (T1557.001) | The attacker gets an NTLM authentication through LLMNR/NBT-NS poisoning or by coercing a server (spooler, EFSRPC). They relay it to SMB, LDAP or HTTP (AD CS) and act as the victim. | SMB signing required; LDAP signing plus channel binding; EPA and HTTPS on AD CS web enrollment; disable LLMNR/NBT-NS/WPAD; Print Spooler off on DCs; restrict NTLM | NTLM operational events 8001–8004; 4624 type 3 with `NTLM` from unexpected hosts; DC authenticating to non-DCs |
| **DCSync** (T1003.006) | A principal holding the `Replicating Directory Changes (All)` rights asks a DC to replicate password hashes, krbtgt included. | Only DCs (and, where it is used, the Entra Connect account) hold replication rights; review the domain root ACL | 4662 on the domain object with GUIDs `1131f6aa-…` / `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` from a non-DC account; replication traffic (DRSUAPI) from a non-DC IP |
| **Golden Ticket** (T1558.001) | With the krbtgt key, the attacker forges TGTs for any user with any group memberships. | Protect Tier 0; rotate krbtgt twice after a suspected compromise and regularly in normal times; AES only | TGS requests (4769) with no matching TGT issued (4768); odd ticket lifetimes; MDI forged-PAC alerts |
| **Silver Ticket** (T1558.002) | With a service or computer account key, the attacker forges service tickets. The DC is never contacted. | gMSAs; keep machine account password rotation on (30 days by default); PAC validation; Credential Guard | Hard to see on the DC. Look for host-side 4624 logons with no matching DC 4769 |
| **Delegation abuse** | *Unconstrained* hosts cache the TGTs of anyone who connects, and coercion can make a DC connect. *Constrained with protocol transition* can impersonate any user to the listed services. *RBCD* (`msDS-AllowedToActOnBehalfOfOtherIdentity`) can be written by anyone with write rights on the computer object. | Remove unconstrained delegation outside DCs; mark admins "sensitive and cannot be delegated" or add them to Protected Users; set `ms-DS-MachineAccountQuota` to 0; review write ACLs on computers | 4742 (computer changed, delegation flags); 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity` / `msDS-AllowedToDelegateTo`; 4741 new computer accounts |
| **AD CS misconfig** (ESC1–ESC8, T1649) | ESC1: a template lets the enrollee supply the subject, has a client-auth EKU, and low-privileged users can enroll. ESC2/3: Any Purpose or enrollment-agent templates. ESC4/5/7: weak ACLs on templates, PKI objects or the CA. ESC6: the `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag. ESC8: NTLM relay to HTTP enrollment. The result is a certificate that authenticates as a Domain Admin and survives password resets. | Treat CAs as Tier 0; remove enrollee-supplied SAN or require manager approval; restrict enroll rights; clear the ESC6 flag; EPA and HTTPS (or remove web enrollment); strong certificate mapping enforcement (KB5014754) | 4886/4887 (requested and issued) where the SAN differs from the requester; 4899/4900 template changes; 4768 with certificate (PKINIT) logons for admins |
| **GPP passwords** (T1552.006) | Old Group Policy Preferences XML files in SYSVOL hold a `cpassword` encrypted with a key Microsoft published, so anyone can decrypt it. | Delete those XMLs; rotate the exposed passwords; use Windows LAPS instead (MS14-025 removed the feature) | Defensive scan of SYSVOL for `cpassword` (see How to verify) |
| **ACL abuse / attack paths** | Paths like `GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword` and `AddMember` chain from an ordinary user to Domain Admin. BloodHound draws these as graph paths. | Run attack-path analysis yourself (BloodHound CE, PingCastle, Purple Knight); remove non-default ACEs on Tier 0 objects; review AdminSDHolder | 5136 on Tier 0 objects; 4728/4732/4756 (privileged group adds); 4670 (permissions changed) |
| **Entra Connect / PTA compromise** | The Entra Connect server stores credentials for an AD account with replication rights and for a cloud sync identity. A PTA agent host sees cleartext passwords during validation. Seamless SSO uses the `AZUREADSSOACC` computer key. | Treat Entra Connect, PTA and AD FS hosts as Tier 0; restrict local admins; patch fast; rotate the `AZUREADSSOACC` Kerberos key regularly; cloud-only admin accounts (no synced Entra privileged roles) | New PTA agent registrations in Entra audit logs; sign-ins from the sync account outside the server; changes to federation settings or domains |

## Defenses

### Tier model, Enterprise Access Model and PAWs
- **Enterprise Access Model** (Microsoft, successor to the legacy Tier 0/1/2 model): control plane (Tier 0), management plane and data/workload plane. Credentials never flow down: a Tier 0 account never logs on to a lower-tier host.
- Separate admin accounts per tier. Enforce this with GPO "Deny log on locally/through RDS/as a batch job/as a service" for Tier 0 groups on Tier 1/2 hosts, or with Authentication Policies and Silos.
- **PAWs**: dedicated hardened devices for Tier 0 work, with no email or web browsing, and managed only from Tier 0.
- Empty standing membership of Domain/Enterprise/Schema Admins. Use JIT (PIM, or time-bound group membership with Privileged Access Management in AD 2016+ forests) and break-glass accounts kept in a vault.

### Account hardening
- **Protected Users** group for human admins. Its members get no NTLM, no DES/RC4 in Kerberos preauth, no delegation, no cached credentials, and a 4-hour TGT. Do not add service or computer accounts, and test before rollout.
- **"Account is sensitive and cannot be delegated"** on every privileged account.
- **gMSA** for services: a 240-byte random password that AD rotates automatically (30 days by default), so it cannot be Kerberoasted in practice. `New-ADServiceAccount -Name svcApp -DNSHostName svcApp.corp.example -PrincipalsAllowedToRetrieveManagedPassword "APP-Servers"`.
- **Windows LAPS**: a unique, rotated local admin password per machine, backed up to AD (encrypted) or Entra ID. Restrict who can read it, and audit that with `Find-LapsADExtendedRights`.
- Set `ms-DS-MachineAccountQuota` to 0. Require preauth everywhere. Remove `adminCount=1` leftovers from accounts that are no longer privileged.

### Protocol hardening

| Control | Setting |
|---|---|
| NTLMv1/LM off | `Network security: LAN Manager authentication level` = *Send NTLMv2 response only. Refuse LM & NTLM* (LmCompatibilityLevel 5) |
| Restrict NTLM | Audit first (`Network security: Restrict NTLM: Audit NTLM authentication in this domain`), then deny by server or host exception lists |
| SMB signing | `Microsoft network server/client: Digitally sign communications (always)` = Enabled; SMBv1 removed |
| LDAP signing | `Domain controller: LDAP server signing requirements` = Require signing (find unsigned binds first with DC event 2889) |
| LDAP channel binding | `Domain controller: LDAP server channel binding token requirements` = Always; LDAPS for apps |
| AD CS web enrollment | HTTPS only, EPA required, NTLM disabled on the IIS site, or remove the role if unused |
| Kerberos | AES only: remove RC4 from `msDS-SupportedEncryptionTypes` and from the "Configure encryption types allowed for Kerberos" GPO once inventoried |
| Name resolution | Disable LLMNR (GPO) and NBT-NS (DHCP or NIC); block WPAD auto-discovery; Print Spooler disabled on DCs |

### Secrets and keys
- **krbtgt rotation**: reset it twice, waiting at least the maximum ticket lifetime (10 h by default) plus replication time between resets. Do this after any suspected Tier 0 compromise, and routinely (e.g., every 180 days). Microsoft's `New-KrbtgtKeys.ps1` script automates and checks the process.
- **Credential Guard** (VBS-isolated LSA) on workstations and member servers. It is on by default on eligible Windows 11 22H2+ Enterprise devices. It does not protect the AD database on DCs.
- **AdminSDHolder**: review the ACL on `CN=AdminSDHolder,CN=System,<domain>`. SDProp copies it to protected objects every 60 minutes, so a rogue ACE there is a persistence mechanism.
- **AD CS**: run Locksmith or PSPKIAudit on a schedule; template changes need a change ticket; keep CA keys in an HSM where possible (see `kb/05-identity-crypto/pki-and-tls.md`).

### Hybrid (Entra)
- Tier 0 for the Entra Connect, Cloud Sync agent, PTA and AD FS servers.
- Entra privileged roles go to cloud-only accounts that use phishing-resistant MFA, never to synced accounts.
- Prefer PHS, which keeps cloud sign-in working when on-prem is down and enables leaked-credential detection, over AD FS where possible.
- Conditional Access blocks legacy authentication.
- Monitor the Entra audit logs for: new federated domains, changes to federation settings, PTA agent registrations, and role assignments.

### Monitoring (Windows event IDs)
Enable "Advanced Audit Policy" (Kerberos, Account Logon/Management, DS Access with SACLs) on DCs and forward the events to the SIEM (see `kb/08-defensive/soc-detection-ir.md`). Microsoft Defender for Identity covers many of these out of the box.

| Event | Watch for |
|---|---|
| 4768 | TGT requests; `PreAuthType 0` (AS-REP roast); certificate (PKINIT) logons for admins |
| 4769 | Service tickets with RC4 (`0x17`); one user requesting many SPNs |
| 4771 / 4776 | Kerberos preauth failures / NTLM validation; spray bursts |
| 4624 / 4625 | Logon type 3/10 with NTLM to servers; Tier 0 accounts on non-Tier-0 hosts; failures across many accounts |
| 4662 | Replication GUIDs from non-DC accounts (DCSync) |
| 4738 / 4742 / 4741 | User or computer changed (UAC, delegation, SPN); new computer accounts |
| 5136 | Directory object modified: ACLs, RBCD, GPOs, AdminSDHolder |
| 4728 / 4732 / 4756 | Members added to security groups (privileged groups) |
| 4886 / 4887 / 4899 / 4900 | AD CS request, issuance, template changes |
| 4794 / 4765 / 4766 | DSRM password set; SID History added / failed |
| 7045 / 4697 | Service installed (lateral movement, often on DCs) |
| 2889 (Directory Service) | Unsigned or cleartext LDAP binds |

## How to verify
Run these as an authorized administrator with the RSAT `ActiveDirectory` module. All of them are read-only.

```powershell
# Kerberoastable privileged accounts (should be none) and their encryption types
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,AdminCount,PasswordLastSet,msDS-SupportedEncryptionTypes |
  Where-Object AdminCount -eq 1
# Accounts without Kerberos preauth (should be none)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
# Unconstrained delegation outside DCs (should be none)
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516}
Get-ADUser -Filter {TrustedForDelegation -eq $true}
# Constrained delegation / protocol transition / RBCD inventory
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*" -or TrustedToAuthForDelegation -eq $true} -Properties msDS-AllowedToDelegateTo
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }
# Privileged accounts that can still be delegated
Get-ADUser -Filter {AdminCount -eq 1 -and AccountNotDelegated -eq $false}
# krbtgt password age and MachineAccountQuota
Get-ADUser krbtgt -Properties PasswordLastSet
Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota
# Who holds replication (DCSync) rights on the domain root
(Get-Acl "AD:$((Get-ADDomain).DistinguishedName)").Access |
  Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
  Select-Object IdentityReference, ObjectType
# GPP passwords left in SYSVOL (should return nothing)
Get-ChildItem "\\$((Get-ADDomain).DNSRoot)\SYSVOL" -Recurse -Include *.xml -ErrorAction SilentlyContinue |
  Select-String -Pattern 'cpassword' -List | Select-Object Path
```

- **PingCastle** (`PingCastle.exe --healthcheck`): domain risk score and its rule list. Track the score over time.
- **Purple Knight** (Semperis): indicators of exposure and compromise for AD and Entra ID.
- **Locksmith** (`Invoke-Locksmith`): finds ESC1–ESC8-class AD CS misconfigurations. Review its fixes before applying them.
- **BloodHound CE** (authorized collection only): count the shortest paths from Domain Users and Authenticated Users to Tier 0. The goal is zero.
- Spot checks: `Get-ADGroupMember "Protected Users"` contains every human admin; the Tier 0 admin groups are empty except for break-glass accounts; NTLM audit logs (8004 on DCs) show the list of NTLM dependencies shrinking.
- Detection tests: in a lab or with purple-team approval, run a Kerberoast and a DCSync simulation and confirm the 4769 RC4 and 4662 alerts fire (see `kb/07-offensive/red-team-and-bug-bounty.md`).

## References
- Microsoft Learn: Enterprise access model and privileged access workstations (Securing privileged access): https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
- Microsoft: "Best Practices for Securing Active Directory"; Protected Users security group; Windows LAPS; Group Managed Service Accounts; KB5014754 (certificate-based authentication changes on DCs)
- ASD's ACSC, CISA, NSA et al. joint guidance "Detecting and Mitigating Active Directory Compromises" (2024)
- SpecterOps, Will Schroeder and Lee Christensen, "Certified Pre-Owned: Abusing Active Directory Certificate Services" (2021), the origin of the ESC numbering
- ANSSI Active Directory security checkpoints (CERT-FR)
- MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets), T1003.006 (DCSync), T1557.001, T1110.003, T1552.006, T1649: https://attack.mitre.org
- PingCastle: https://www.pingcastle.com; Purple Knight (Semperis); Locksmith (Jake Hildreth / Trimarc); BloodHound CE (SpecterOps)
- See also `kb/05-identity-crypto/identity-access.md`, `kb/04-cloud-infra/os-hardening.md`, `kb/05-identity-crypto/pki-and-tls.md`, `kb/08-defensive/soc-detection-ir.md`
