# SOC, Detection Engineering & Incident Response

## SOC
Tiers L1 triage → L2 investigation → L3 hunting/engineering. Tools: SIEM (Splunk, Elastic, Sentinel, Wazuh), EDR/XDR, SOAR, NDR, ticketing. Metrics: MTTD, MTTR, false-positive rate, ATT&CK coverage.

## Detection engineering
Write detections as code (Sigma → SIEM query, YARA for files, Suricata for network). Lifecycle: hypothesis → data source check → rule → test (Atomic Red Team) → tune → document → review. Log sources that matter: auth logs, EDR, DNS, proxy, cloud audit, Windows 4624/4625/4688/4768/4769, Sysmon, PowerShell 4104.

## Threat hunting
Hypothesis-driven (ATT&CK technique, intel report, anomaly). Look for: rare parent-child processes, beaconing, new persistence (Run keys, cron, services), unusual auth, LOLBins misuse.

## Incident response (NIST 800-61)
**Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-incident review.**
- Contain first (isolate host, disable account, block IOCs), preserve evidence (memory, disk image, logs) before wiping.
- Keep a timeline; chain of custody; communicate via out-of-band channel; legal/PR/regulators (GDPR 72h notification).
- Playbooks: phishing, ransomware, compromised credentials, web shell, insider, data breach, cloud key leak.
- Ransomware readiness: offline/immutable backups, tested restores, segmentation, EDR, MFA, patching, no RDP exposure.

## Post-incident
Blameless review, root cause, detection gaps, action items with owners.
