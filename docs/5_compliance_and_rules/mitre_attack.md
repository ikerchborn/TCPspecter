# 🎯 MITRE ATT&CK® Coverage Matrix

This document maps every detection category in TCPspecter's `zombie_detector.py` (and Scapy engine) to its corresponding MITRE ATT&CK technique, including the NIST CSF and ISO/IEC 27001 compliance controls that are automatically tagged on each alert.

---

## Detection Coverage Table

The following mappings are hard-coded in `core/zombie_detector.py` in the `MITRE_MAP`, `NIST_MAP`, and `ISO_MAP` dictionaries.

| Detection Category | MITRE ID | Technique Name | Tactic | NIST CSF | ISO 27001 |
|-------------------|----------|---------------|--------|----------|-----------|
| Deleted Binary | T1070.004 | File Deletion | Defense Evasion | DE.CM-1 | A.12.4.1 |
| Suspicious Path | T1059 | Command and Scripting Interpreter | Execution | DE.CM-1 | A.12.4.1 |
| SUID with Network Activity | T1548.001 | Setuid and Setgid | Privilege Escalation | PR.AC-4 | A.9.2.3 |
| Shell Signature | T1059.004 | Unix Shell | Execution | DE.AE-2 | A.12.4.1 |
| Shell with Connection | T1059.004 | Unix Shell | Execution | DE.AE-2 | A.12.4.1 |
| Process Masquerading | T1036.005 | Match Legitimate Name or Location | Defense Evasion | DE.CM-1 | A.12.4.1 |
| Orphaned C2 Agent | T1543 | Create or Modify System Process | Persistence | DE.CM-1 | A.12.4.1 |
| Atypical SSL Traffic | T1071.001 | Web Protocols (C2 over HTTPS) | Command and Control | DE.AE-2 | A.13.1.1 |
| C2/Suspicious Port | T1071 | Application Layer Protocol | Command and Control | DE.AE-2 | A.13.1.1 |
| Open Listener | T1049 | System Network Connections Discovery | Discovery | DE.CM-1 | A.12.4.1 |
| Mass Connections | T1046 | Network Service Discovery | Discovery | DE.AE-2 | A.13.1.1 |
| C2 Beaconing | T1071.001 | Web Protocols (Beaconing) | Command and Control | DE.AE-2 | A.13.1.1 |
| System Persistence | T1053 | Scheduled Task/Job | Persistence | DE.CM-1 | A.12.4.1 |
| Regular C2 Connection | T1571 | Non-Standard Port | Command and Control | DE.AE-2 | A.13.1.1 |
| IDS/Sniffer | T1040 | Network Sniffing | Discovery | — | — |
| Fileless Memory | T1055 | Process Injection | Defense Evasion | DE.CM-7 | A.12.6.1 |
| DNS Tunneling (Scapy) | T1048.003 | Exfiltration Over Alternative Protocol | Exfiltration | — | A.13.1.1 |

---

## C2 Port Watchlist

The following ports are hard-coded in `zombie_detector.py` as high-risk indicators. Any established outbound connection to these ports from a non-whitelisted process contributes to the risk score.

| Ports | Associated Threat |
|-------|------------------|
| 6667, 6668, 6669, 7000 | IRC Botnets |
| 9001, 9050, 9051 | Tor Proxy / Onion Routing |
| 4444, 4445, 5555, 8888 | Metasploit, Netcat, Reverse Shells |
| 3333, 14444, 18080 | Cryptominer Stratum Protocol |
| 5900, 5938 | VNC Remote Access / RATs |

---

## Tactics Distribution

```
Execution           ████████░░░░░░░  (T1059, T1059.004)
Defense Evasion     ████████████░░░  (T1070.004, T1036.005, T1055)
Persistence         █████░░░░░░░░░░  (T1543, T1053)
Privilege Escalation████░░░░░░░░░░░  (T1548.001)
Command and Control ████████████████ (T1071, T1071.001, T1571)
Discovery           ████████░░░░░░░  (T1049, T1046, T1040)
Exfiltration        ████░░░░░░░░░░░  (T1048.003)
```

---

## NIST CSF Control Reference

| Control ID | Control Name | TCPspecter Coverage |
|-----------|-------------|---------------------|
| DE.CM-1 | Network communications monitored to detect adverse events | Zombie detector, process forensics |
| DE.CM-7 | Monitoring for unauthorized personnel, connections, devices | Fileless memory detection |
| DE.AE-2 | Detected events analyzed to understand targets and methods | C2 beaconing, DNS tunneling, SSL anomalies |
| PR.AC-4 | Access permissions managed incorporating least privilege | SUID binary with network access detection |

---

## ISO/IEC 27001 Control Reference

| Control | Name | TCPspecter Coverage |
|---------|------|---------------------|
| A.12.4.1 | Event Logging | Alert Bus persistence to `security_events.log` and `security_alerts.json` |
| A.12.6.1 | Management of Technical Vulnerabilities | Fileless memory scanner, deleted binary detection |
| A.13.1.1 | Network Controls | Firewall Manager, C2 traffic detection |
| A.9.2.3 | Management of Privileged Access Rights | SUID binary with active network socket detection |
