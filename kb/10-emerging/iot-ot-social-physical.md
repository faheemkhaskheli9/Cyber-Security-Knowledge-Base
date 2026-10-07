# IoT, OT/ICS, Social Engineering, Physical & Quantum

## IoT
Unique credentials, signed firmware + secure boot, OTA updates, disable unused services/ports (UART/JTAG), network isolation, MQTT/CoAP over TLS. Standard: OWASP IoT Top 10, ETSI EN 303 645.

## OT / ICS / SCADA
Purdue model segmentation, DMZ between IT/OT, passive monitoring (Claroty, Nozomi, Zeek), legacy protocols (Modbus, DNP3, OPC) lack auth → isolate, safety first (availability > confidentiality), IEC 62443, NIST 800-82.

## Social engineering
Phishing, spear-phishing, vishing, smishing, pretexting, BEC, QR phishing, deepfake voice/video. Defenses: phishing-resistant MFA, DMARC enforcement, out-of-band verification for payments/credentials, reporting button, training.

## Physical
Badges, tailgating prevention, locks, cameras, clean desk, device encryption, USB controls, visitor logs, secure disposal.

## Quantum
"Harvest now, decrypt later" risk. Inventory crypto, adopt crypto-agility, plan hybrid PQ (ML-KEM, ML-DSA) migration.
