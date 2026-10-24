# Firmware and Boot Security (UEFI, Secure Boot, TPM, BMC)

## What
Protecting the code that runs before and beneath the operating system: system firmware (UEFI/BIOS), option ROMs, boot loaders, the Trusted Platform Module (TPM), and out-of-band management controllers (BMC: iDRAC, iLO, XClarity and other IPMI/Redfish controllers). Key mechanisms:
- **UEFI Secure Boot**: firmware verifies each boot component's signature against the allowed database (`db`) and the revocation list (`dbx`). The Platform Key (`PK`) controls the Key Exchange Keys (`KEK`), and a KEK signs updates to `db` and `dbx`.
- **Measured boot**: each stage hashes the next into TPM Platform Configuration Registers (PCRs), so a remote verifier or disk-encryption policy can tell whether the boot chain changed (attestation).
- **Firmware resiliency** (NIST SP 800-193): protect firmware from unauthorized change, detect corruption, and recover to a known-good state.
OS-level hardening is in `kb/04-cloud-infra/os-hardening.md`; embedded and IoT firmware is in `kb/10-emerging/iot-ot-social-physical.md`.

## Why it matters
- Code below the OS survives OS reinstalls and disk replacement and is invisible to most EDR tools. Known in-the-wild examples: LoJax (ESET, 2018, first public UEFI rootkit seen in the wild), CosmicStrand and MoonBounce (2022), and the BlackLotus bootkit (ESET, 2023), which bypassed Secure Boot on fully patched Windows 11 systems of that time by exploiting CVE-2022-21894.
- Secure Boot is only as good as its keys and revocations. PKfail (CVE-2024-8105, 2024) showed many vendors shipping firmware with untrusted test Platform Keys; anyone with the leaked private key can sign boot code those devices accept.
- Microsoft's 2011 Secure Boot certificates expire in 2026 (Microsoft Corporation KEK CA 2011 and Microsoft UEFI CA 2011 in June 2026, Windows Production PCA 2011 in October 2026). Devices that do not receive the 2023 replacement certificates keep booting but can no longer receive new boot manager, `db` and `dbx` updates.
- A BMC has full control of its server (power, console, virtual media, firmware flashing) over the network. Exposed or default-credential BMCs give an attacker persistence below the host OS.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | Example | Defense |
|---|---|---|
| Bootkit with Secure Boot bypass | Vulnerable but still-trusted signed boot manager loaded to disable Secure Boot (BlackLotus, CVE-2022-21894; follow-up CVE-2023-24932) | Apply OS boot manager updates **and** the `dbx` / revocation steps; protect the EFI System Partition; monitor boot configuration changes |
| SPI flash implant | Malicious DXE driver written to firmware from the OS (LoJax) | Firmware write protection (BIOS lock, SMM protections, Intel Boot Guard / AMD Platform Secure Boot), signed firmware updates only, firmware integrity scanning |
| Untrusted platform keys | Production firmware ships a test `PK` (PKfail) | Vendor firmware update with a unique `PK`; inventory and check `PK` certificates |
| Firmware parser bugs | Malicious boot logo image exploits firmware image parsers (LogoFAIL, 2023) | Vendor firmware updates; disable logo customization where offered |
| Disabling or downgrading protections | Secure Boot turned off, firmware rolled back to a vulnerable version | Firmware admin password, anti-rollback, alert on Secure Boot state changes, attestation-gated access |
| DMA and evil-maid attacks | Malicious Thunderbolt/PCIe device reads memory; boot media swapped on an unattended laptop | Kernel DMA Protection / IOMMU enabled, full-disk encryption sealed to TPM PCRs plus a pre-boot PIN, Secure Boot |
| BMC compromise | Internet-exposed iDRAC/iLO, default credentials, unpatched BMC firmware, IPMI cipher zero | BMC on an isolated management network, unique credentials, current firmware, IPMI over LAN disabled where Redfish suffices |
| Supply-chain tampering | Modified firmware on hardware before delivery | Buy through trusted channels, platform certificates / attestation where offered, verify firmware hashes on receipt |

## Defenses

### 1. Inventory and updates
- Inventory firmware versions for laptops, servers, BMCs, NICs and storage controllers alongside OS assets; track vendor end-of-support dates (`kb/09-governance/vulnerability-management.md`).
- Patch firmware through vendor tooling or OS channels (Windows Update / vendor update tools; `fwupd` with the Linux Vendor Firmware Service on Linux). Treat BMC firmware updates as part of normal patch cycles.

### 2. Secure Boot and key management
- Enable UEFI Secure Boot in User Mode on every system that supports it; disable legacy BIOS / CSM boot.
- Keep `db` / `dbx` current. For Windows, follow Microsoft's CVE-2023-24932 guidance (KB5025885) and the Secure Boot certificate update guidance to move devices to the 2023 CAs before the 2011 CAs expire. Test on representative hardware first: revocations can make older boot media unbootable.
- On Linux, use the distribution's signed `shim` and kernel; keep Machine Owner Key (MOK) enrollment under change control; enable kernel lockdown where available.
- Replace test or shared Platform Keys with vendor-supplied unique keys; organizations with strict needs can enroll their own keys (NSA *UEFI Secure Boot Customization*).

### 3. Firmware protection
- Set a firmware (BIOS/UEFI) administrator password; disable boot from external media by default; enable vendor hardware root-of-trust features (Intel Boot Guard, AMD Platform Secure Boot, HP Sure Start, Dell SafeBIOS and similar) and firmware rollback protection.
- Turn on platform protections the OS can use: TPM 2.0, IOMMU / Kernel DMA Protection, virtualization-based security and memory integrity (HVCI) on Windows, System Guard / DRTM where supported.

### 4. Measured boot and attestation
- Seal disk-encryption keys to TPM PCRs (BitLocker, systemd-cryptenroll / Clevis) and require a pre-boot PIN on laptops at risk of theft.
- Use device health attestation in conditional access (Intune / Microsoft Entra device compliance, platform attestation services) so a device whose boot chain changed loses access (`kb/01-foundations/zero-trust-architecture.md`).
- In cloud, use VMs with virtual TPM and Secure Boot: Google Cloud Shielded VMs, Azure Trusted Launch, Amazon EC2 UEFI Secure Boot with NitroTPM.

### 5. BMC and out-of-band management
- Put BMCs on a dedicated management VLAN reachable only from admin jump hosts; never expose them to the internet.
- Change default credentials, integrate with directory authentication where supported, enable TLS for web and Redfish interfaces, disable IPMI over LAN and unused services.
- Update BMC firmware regularly and send BMC logs to the SIEM (NSA/CISA *Harden Baseboard Management Controllers*).

### 6. Detection
- Alert on: Secure Boot disabled, firmware version changes outside maintenance windows, new MOK or `db` entries, modifications to the EFI System Partition, TPM attestation failures, BMC logins from non-admin networks.
- Periodically check firmware integrity with vendor tools or open-source frameworks (CHIPSEC) on a sample of systems, and investigate any mismatch as a possible incident (`kb/08-defensive/dfir-malware-threat-intel.md`).

## How to verify
- Secure Boot state: Windows `Confirm-SecureBootUEFI` (returns `True`) or `msinfo32` (Secure Boot State: On); Linux `mokutil --sb-state` (SecureBoot enabled).
- TPM present and ready: Windows `Get-Tpm`; Linux `tpm2_pcrread sha256:0,2,4,7` returns values, and BitLocker / LUKS keys are TPM-protected (`manage-bde -status`, `systemd-cryptenroll <device>`).
- Firmware updates available: `fwupdmgr get-updates` on Linux, vendor update tool reports on Windows fleets; no device runs firmware past its vendor support date.
- Revocations applied (Windows): Microsoft KB5025885 lists the checks for whether the CVE-2023-24932 mitigations are applied; track the share of devices with the 2023 Secure Boot certificates.
- Platform key not a test key: on Linux, `mokutil --pk` (or `efi-readvar -v PK`) output must not show a certificate subject containing "DO NOT TRUST" or "DO NOT SHIP".
- Firmware protections (authorized lab or sample systems): `chipsec_main -m common.bios_wp` and related CHIPSEC modules report write protection enabled.
- BMC exposure: from outside the management network, BMC web, Redfish and IPMI (UDP 623) ports are unreachable; an external attack-surface scan shows no BMC login pages.

## References
- NIST SP 800-193, Platform Firmware Resiliency Guidelines: https://csrc.nist.gov/pubs/sp/800/193/final
- NIST SP 800-147, BIOS Protection Guidelines: https://csrc.nist.gov/pubs/sp/800/147/final · NIST SP 800-147B (servers) · NIST SP 800-155 (draft, BIOS Integrity Measurement Guidelines)
- UEFI Specifications (Secure Boot, authenticated variables): https://uefi.org/specifications
- Microsoft, Windows Secure Boot certificate expiration and CA updates: https://support.microsoft.com/help/5062710
- Microsoft Security Response Center, CVE-2023-24932 Secure Boot Security Feature Bypass: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932 (management steps in KB5025885)
- CERT/CC VU#455367, PKfail (CVE-2024-8105): https://kb.cert.org/vuls/id/455367
- NSA, *UEFI Secure Boot Customization* (2020) and *BlackLotus Mitigation Guide* (2023)
- CISA and NSA, *Harden Baseboard Management Controllers* (June 2023): https://www.cisa.gov/news-events/alerts/2023/06/14/cisa-and-nsa-release-joint-guidance-hardening-baseboard-management-controllers-bmcs
- fwupd / Linux Vendor Firmware Service: https://fwupd.org · CHIPSEC: https://github.com/chipsec/chipsec
- MITRE ATT&CK T1542 (Pre-OS Boot): T1542.001 (System Firmware), T1542.003 (Bootkit); T1495 (Firmware Corruption)
- See also `kb/04-cloud-infra/os-hardening.md`, `kb/01-foundations/zero-trust-architecture.md`, `kb/10-emerging/iot-ot-social-physical.md`, `kb/08-defensive/dfir-malware-threat-intel.md`, `kb/04-cloud-infra/virtualization-and-hypervisor-security.md`
