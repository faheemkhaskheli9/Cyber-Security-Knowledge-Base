# Network Security

## Fundamentals
OSI/TCP-IP, TCP handshake, UDP, ARP, ICMP, DNS, DHCP, HTTP/TLS, routing, NAT, VLANs.

## Common attacks
ARP spoofing/MITM, DNS poisoning/hijack/tunneling, port scanning, SYN flood, DDoS (volumetric, protocol, L7), rogue DHCP, VLAN hopping, BGP hijack, SSL strip, sniffing on open networks.

## Defenses
- Segmentation (VLANs, subnets, micro-segmentation), default-deny firewall rules, egress filtering.
- IDS/IPS (Suricata, Snort, Zeek), NDR, NetFlow monitoring.
- Encrypted transport everywhere (TLS 1.2+/1.3, SSH keys, IPsec/WireGuard VPN).
- DNSSEC, DoH/DoT, DNS filtering, DMARC/SPF/DKIM for email.
- Disable unused services; patch network devices; change defaults; secure management plane (out-of-band, MFA).
- DDoS: CDN/scrubbing, rate limiting, anycast, autoscaling.
- Zero Trust Network Access (ZTNA) over flat VPNs.

## Wireless
Use WPA3 (or WPA2-AES with strong passphrase), disable WPS, isolate guest/IoT, 802.1X for enterprise, detect rogue APs.

## Verify
`nmap -sV` against your own hosts, review firewall rules quarterly, test egress, check TLS with `testssl.sh`/SSL Labs.
