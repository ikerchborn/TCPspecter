# 🛡️ Incident Response Playbook: C2 Beaconing

**Classification:** Blue Team — Defensive Use Only  
**Applies to:** TCPspecter `zombie_detector.py` — Beaconing Analysis Module  
**MITRE ATT&CK:** T1071.001 — Application Layer Protocol (Beaconing)

---

## 1. Threat Overview

**C2 Beaconing** occurs when malware installed on a compromised system periodically contacts an attacker-controlled server to receive instructions or confirm continued access. The malware typically uses a standard protocol (HTTP/HTTPS) to blend in with legitimate traffic.

**What makes beaconing distinctive:**
- **Regularity.** Unlike human-driven browser traffic, automated beacons contact the same IP at statistically consistent intervals (e.g., every 30, 60, or 300 seconds). This produces a very low **coefficient of variation** in inter-connection timing.
- **Process anomalies.** The beaconing process often runs from a suspicious path (`/tmp`, `/dev/shm`) or has had its on-disk binary deleted to avoid detection.
- **Known bad ports.** Many C2 frameworks default to non-standard ports: `4444` (Metasploit), `8888` (generic), `4445` (Cobalt Strike alternate), or Tor-based routing on `9050`.

**How TCPspecter detects it:**
`zombie_detector.py` tracks per-PID outbound connection timestamps over a sliding time window. It computes the **coefficient of variation** (standard deviation / mean) of the interval between connections. A coefficient below a threshold (near-perfect regularity) triggers a C2 Beaconing alert.

---

## 2. Reading the Alert in TCPspecter

### Web Dashboard
1. Open the Dashboard at `http://localhost:8050/`.
2. In the **Network Security Analysis** card, look for a elevated Risk Score and a finding labeled **"C2 Beaconing"** or **"Conexión Regular C2"** in the active alerts list.
3. Click the connection row in the **Active Connections Table** to open the **Explanation Engine (XAI) modal**. The modal will describe the risk, the suspicious path or port, and the remote IP.

### Alert in `security_alerts.json` (ECS format)

```json
{
  "@timestamp": "2026-06-21T16:15:00Z",
  "ecs": {"version": "1.12.0"},
  "event": {
    "kind": "alert",
    "category": ["intrusion_detection"],
    "type": ["indicator"],
    "action": "detected",
    "severity": 90,
    "risk_score": 95,
    "provider": "TCPspecter",
    "dataset": "tcpspecter.security",
    "module": "C2 Beaconing"
  },
  "host": {"name": "prod-server-01", "os": {"family": "linux"}},
  "message": "C2 Beaconing: Regular outbound connections with low coefficient of variation detected.",
  "process": {
    "pid": 4512,
    "name": "updater_svc"
  },
  "destination": {"ip": "198.51.100.45"},
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {"id": "T1071.001", "name": "Web Protocols (Beaconing)"},
    "tactic": {"name": "Command and Control"}
  },
  "tcpspecter": {
    "engine": "zombie_detector",
    "status": "DETECTED",
    "severity": "CRITICAL"
  }
}
```

**Key fields for your investigation:**
- `process.pid` and `process.name` — the beaconing process to investigate
- `destination.ip` — the C2 server address to block
- `event.severity` = 90 / `event.risk_score` = 95 → this is a CRITICAL finding

---

## 3. Confirming the Alert

Before blocking, confirm the process is genuinely anomalous. In the **Active Connections Table**:

1. **Filter by PID**: Press `/` in the TUI and type the PID from the alert. Or use the search bar on the Dashboard.
2. **Check the executable path**: A legitimate `updater_svc` should not be running from `/tmp` or with `(deleted)` next to its binary path. If it is — that is a critical Indicator of Compromise (IoC).
3. **Press `a` (TUI)** to run local analysis on the selected process — this shows file hashes, permissions, and whether the binary is SUID.
4. **Press `v` (TUI)** if a VirusTotal API key is configured to check the binary hash reputation online.

---

## 4. Containment (Rule Builder)

### Via Web Dashboard

1. Navigate to **Firewall & IDS** at `http://localhost:8050/firewall`.
2. In the **Quick Block** section:
   - Enter the `destination.ip` from the ECS alert (e.g., `198.51.100.45`).
   - Click **Drop (Quick)**.
3. The firewall rule is immediately applied (`iptables -I INPUT 1 -s 198.51.100.45 -j DROP`).
4. Confirm the IP appears in the **Active Firewall Rules** table.

### For Severe Cases: Host Quarantine

If the alert indicates a process running from a deleted binary on a critical server, a single IP block may be insufficient — the malware may have multiple C2 fallback IPs.

To fully isolate the host while preserving analyst access:
- Ensure your analyst workstation's IP is in `MANAGEMENT_IP_WHITELIST` in `config.json`.
- The quarantine creates custom `iptables` chains (`TCPSPECTER-Q-IN`, `TCPSPECTER-Q-OUT`) that drop all traffic except to/from the whitelist.

See [`automated_mitigation.md`](../4_active_response_soar/automated_mitigation.md) for full quarantine details.

---

## 5. Post-Containment Forensics

1. **Kill the process**: In the TUI, navigate to the beaconing PID and press `x` to terminate it (with confirmation).
2. **Search for persistence**: Press `z` to run a Zombie Scan looking for related persistent mechanisms (cron jobs, systemd services, scripts in `/etc/init.d`).
3. **Check for sibling processes**: Filter the connections table by username (`/` search) or parent PID to find related processes that may also need to be terminated.
4. **Preserve evidence**: Before killing the process, note its full path, start time, and open file descriptors. Export the report with `e` in the TUI (CSV/JSON format) to preserve a snapshot for your incident report.
