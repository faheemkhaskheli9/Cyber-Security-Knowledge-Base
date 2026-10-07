# Network Security

## What
Protecting the confidentiality, integrity and availability of traffic and network infrastructure: segmentation, filtering, monitoring, secure protocols and access control for devices and users. Wireless, DNS and DDoS have their own deep dive in `kb/02-network/wireless-dns-ddos.md`.

### Fundamentals
OSI/TCP-IP, TCP handshake, UDP, ARP, ICMP, DNS, DHCP, HTTP/TLS, routing, NAT, VLANs.

## Why it matters
Most intrusions start with a single foothold (phished laptop, exposed service). What happens next depends on the network: on a flat network the attacker reaches domain controllers, databases and backups in hours. Segmentation, egress control and network visibility turn one compromised host into a contained, detectable incident. Exposed management interfaces and legacy cleartext protocols remain top initial-access vectors in CISA advisories.

## Attacks
> Offensive techniques here are for **authorized testing only** (your own systems, CTFs, written-scope pentests). Each is paired with its defense/detection.

### Common attacks
ARP spoofing/MITM, DNS poisoning/hijack/tunneling, port scanning, SYN flood, DDoS (volumetric, protocol, L7), rogue DHCP, VLAN hopping, BGP hijack, SSL strip, sniffing on open networks.

| Attack | ATT&CK | How it works | Defense / detection |
|---|---|---|---|
| ARP spoofing / MITM | T1557.002 | Forged ARP replies map the gateway IP to the attacker's MAC | Dynamic ARP Inspection + DHCP snooping; TLS/SSH everywhere; alert on ARP flip-flops (Zeek, arpwatch) |
| LLMNR/NBT-NS poisoning (e.g., Responder) | T1557.001 | Attacker answers broadcast name lookups, captures NTLM hashes or relays them | Disable LLMNR (GPO "Turn off multicast name resolution") and NetBIOS over TCP/IP; require SMB signing; disable NTLMv1; detect with LLMNR honeytoken queries |
| Port scanning / service discovery | T1046 | Enumerate open ports and versions to find targets | Minimize exposed services; IDS scan detection; internal honeypots/canaries; alert on one host touching many ports/hosts |
| Lateral movement | T1021, T1550.002 | Reuse credentials over SMB, RDP, WinRM, SSH to pivot | Host firewalls blocking workstation-to-workstation SMB/RDP; tiered admin model; LAPS; PAWs; detect unusual east-west auth |
| Rogue DHCP | — | Attacker hands out its own gateway/DNS | DHCP snooping (trusted ports only) |
| VLAN hopping | — | Switch spoofing via DTP or double tagging | Disable DTP (`switchport nonegotiate`), access ports set to `switchport mode access`, unused native VLAN, prune trunks |
| SSL strip / downgrade | T1557 | Force HTTP or weak TLS | HSTS (preload), TLS 1.2+ only, disable legacy ciphers |
| DNS tunneling / C2 over allowed protocols | T1071.004, T1572 | Data or C2 hidden in DNS queries or HTTPS | Force DNS via internal resolvers, block outbound 53/853 elsewhere, monitor long/high-entropy queries |
| Sniffing on open networks | T1040 | Cleartext credentials captured | Encrypted protocols only; VPN/ZTNA on untrusted Wi-Fi |

## Defenses
### Segmentation and filtering
- Segmentation (VLANs, subnets, micro-segmentation), default-deny firewall rules, egress filtering.
  - Zones: internet edge/DMZ, users, servers, management, OT/IoT, guest, backups. Backups and identity (domain controllers, IdP) get the tightest zones.
  - **Micro-segmentation**: per-workload policy (cloud security groups, Kubernetes NetworkPolicy, host firewalls, identity-based segmentation tools).
  - **Default deny** both ways; every allow rule has an owner, ticket and review date. Log denies.
  - **Egress filtering**: servers reach only required destinations (proxy or allowlist); block direct outbound SMB (445), RDP, and DNS except from resolvers. Apply BCP 38 anti-spoofing at the edge.
- Disable unused services; patch network devices; change defaults; secure management plane (out-of-band, MFA).

### Monitoring
- IDS/IPS (Suricata, Snort, Zeek), NDR, NetFlow monitoring.
  - **Suricata**: signature IDS/IPS (ET Open rules), EVE JSON to SIEM. Start in IDS mode, tune, then block.
  - **Zeek**: protocol logs (`conn.log`, `dns.log`, `ssl.log`, `http.log`) for hunting and long-term retention.
  - Collect firewall deny logs and NetFlow/VPC Flow Logs; baseline east-west traffic. See `kb/08-defensive/soc-detection-ir.md`.

### Secure protocols vs legacy
- Encrypted transport everywhere (TLS 1.2+/1.3, SSH keys, IPsec/WireGuard VPN).

| Legacy (remove) | Use instead |
|---|---|
| Telnet, rsh/rlogin | SSH (keys, `PasswordAuthentication no`, `PermitRootLogin no`) |
| FTP, TFTP | SFTP/SCP, HTTPS |
| HTTP, TLS 1.0/1.1, SSLv3 | HTTPS with TLS 1.2+/1.3, HSTS |
| SNMPv1/v2c (community strings) | SNMPv3 `authPriv` (SHA-2 auth + AES privacy) |
| SMBv1, NTLMv1, LLMNR/NBT-NS | SMBv3 with signing/encryption, Kerberos, DNS |
| Unsigned LDAP binds | LDAPS / LDAP signing + channel binding |

- DNSSEC, DoH/DoT, DNS filtering, DMARC/SPF/DKIM for email.
- DDoS: CDN/scrubbing, rate limiting, anycast, autoscaling.

### Remote access and NAC
- Zero Trust Network Access (ZTNA) over flat VPNs: per-app access based on identity + device posture (NIST SP 800-207, `kb/01-foundations/core-concepts.md`). If a VPN remains, require MFA, patch the concentrator urgently (frequent KEV entries), and route users only to needed subnets.
- **NAC / 802.1X**: port-based authentication (EAP-TLS with device certificates preferred) via RADIUS; unknown devices land in a quarantine/guest VLAN. MAB (MAC bypass) only for devices that cannot do 802.1X, in restricted VLANs.
- Switch hardening: DHCP snooping, Dynamic ARP Inspection, IP Source Guard, port security, BPDU guard.

### Wireless
Use WPA3 (or WPA2-AES with strong passphrase), disable WPS, isolate guest/IoT, 802.1X for enterprise, detect rogue APs. Details in `kb/02-network/wireless-dns-ddos.md`.

## How to verify
Scan only scope you own or are authorized in writing to test.
- `nmap -sV` against your own hosts. Examples:
  ```
  nmap -sS -p- --open -oA tcp_full 10.0.10.0/24      # all TCP ports
  nmap -sU --top-ports 100 -oA udp_top 10.0.10.0/24  # common UDP
  nmap -sV --script ssl-enum-ciphers -p 443 app.example.internal
  ndiff old.xml new.xml                                # drift between scans
  ```
  Compare results with the expected allow list; every unexpected open port is a finding.
- Review firewall rules quarterly: remove `any/any`, unused and shadowed rules; confirm deny logging.
- Test egress: from a server segment, try outbound connections (e.g., `curl`, `nc -vz`) to a host you control on 22, 445, 53, 8080; only approved paths should succeed.
- Check TLS with `testssl.sh`/SSL Labs; check SSH with `ssh-audit`.
- Segmentation test: from the user VLAN, attempt to reach management interfaces, DB ports and backup servers; all should fail.
- Confirm LLMNR/NBT-NS are off (no UDP 5355/137 broadcasts in a packet capture) and SMB signing is required.
- Plug an unknown device into a wall port; it should land in quarantine (802.1X/NAC working).
- Confirm IDS alerts fire for a test scan from an authorized host.

## References
- NIST SP 800-41 Rev. 1 (Firewalls and Firewall Policy) · NIST SP 800-94 (Intrusion Detection and Prevention Systems)
- NIST SP 800-207 Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- CIS Controls v8, Controls 12 (Network Infrastructure Management) and 13 (Network Monitoring and Defense): https://www.cisecurity.org/controls
- MITRE ATT&CK T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/ · T1046: https://attack.mitre.org/techniques/T1046/
- RFC 8446 (TLS 1.3) · RFC 8996 (deprecating TLS 1.0/1.1) · RFC 9325 (BCP 195, TLS recommendations) · RFC 4253 (SSH transport) · RFC 3414 (SNMPv3 USM) · RFC 2827 (BCP 38) · IEEE 802.1X
- Suricata: https://suricata.io · Zeek: https://zeek.org · Nmap reference guide: https://nmap.org/book/man.html
- See also `kb/02-network/wireless-dns-ddos.md`, `kb/05-identity-crypto/pki-and-tls.md`, `kb/04-cloud-infra/os-hardening.md`, `kb/07-offensive/pentest-methodology.md`
