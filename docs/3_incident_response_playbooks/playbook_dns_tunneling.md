# 🛡️ Incident Response Playbook: DNS Tunneling & Data Exfiltration

**Classification:** Blue Team — Defensive Use Only  
**Applies to:** TCPspecter `scapy_engine.py` — DNS Heuristics Module  
**MITRE ATT&CK:** T1048.003 — Exfiltration Over Alternative Protocol

---

## 1. Threat Overview

**DNS Tunneling** is a data exfiltration technique in which an adversary encodes stolen data or C2 commands inside DNS queries and responses. Because most corporate firewalls allow outbound DNS traffic (UDP port 53), this channel is rarely blocked.

**Why it works:**
- DNS is a fundamental protocol — blocking it entirely breaks almost all network services.
- Attackers encode payloads in Base64 or Hex and embed them as long subdomains (e.g., `dGhpcyBpcyBhIHRlc3Q.attacker.com`).
- Standard firewalls and IDS systems without DPI do not inspect query content.

**What TCPspecter detects:**
- DNS queries with **unusually long subdomain strings** (Algorithmically Generated Domains / DGA behavior).
- Anomalously high **Shannon Entropy** in DNS query names. Legitimate domain names have low entropy; Base64-encoded payloads have entropy typically above **4.5 bits/byte**.
- Abnormally **high frequency** of DNS queries to a single external resolver.

---

## 2. Reading the Alert in TCPspecter

### Web Dashboard
1. Open the Dashboard at `http://localhost:8050/`.
2. Look at the **DNS Tunneling & Traffic Heuristics** card.
3. The **Payload Entropy** indicator shows the rolling Shannon entropy average for captured packets. A sustained value above **4.5** is the primary indicator.
4. In the **Alerts (Traffic / DNS / DLP)** list below the card, a DNS tunneling alert will appear with the format:

```
[Scapy] DNS Tunneling: high entropy domain detected — <domain> (entropy: 4.87)
```

### Alert in `security_alerts.json` (ECS format)

The Alert Bus automatically writes a structured ECS document. Locate it in `security_alerts.json` in the project root:

```json
{
  "@timestamp": "2026-06-21T15:00:00Z",
  "ecs": {"version": "1.12.0"},
  "event": {
    "kind": "alert",
    "category": ["intrusion_detection"],
    "type": ["indicator"],
    "action": "detected",
    "severity": 70,
    "risk_score": 73,
    "provider": "TCPspecter",
    "dataset": "tcpspecter.security",
    "module": "DNS Tunneling"
  },
  "host": {"name": "sensor-01", "os": {"family": "linux"}},
  "message": "DNS Tunneling: Alta entropía y frecuencia anómala detectada hacia servidor externo.",
  "source": {"ip": "10.0.0.15"},
  "destination": {"ip": "8.8.8.8"},
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {"id": "T1048.003", "name": "Exfiltration Over Alternative Protocol"},
    "tactic": {"name": "Exfiltration"}
  },
  "tcpspecter": {
    "engine": "dns",
    "status": "DETECTED",
    "severity": "HIGH"
  }
}
```

**Key fields to note for your investigation:**
- `destination.ip` — the DNS resolver used for tunneling (this is what you will block)
- `source.ip` — the internal host sending anomalous queries (investigate this machine)
- `message` — description of the anomaly from the Scapy engine

---

## 3. Containment Steps (Firewall Rule Builder)

Once you have confirmed the alert is genuine, the goal is to stop the exfiltration channel without disrupting all DNS on the network.

**Targeted block strategy:** Block traffic from the affected internal host to the specific external DNS resolver used for tunneling — not all DNS.

### Via Web Dashboard (Recommended)

1. Navigate to **Firewall & IDS** at `http://localhost:8050/firewall`.
2. In the **Enterprise Rule Builder** panel, use the **Advanced Rule** form:
   - **Action:** `DROP`
   - **Protocol:** `UDP`
   - **Source IP:** The internal IP from `source.ip` in the alert (e.g., `10.0.0.15`)
   - **Destination IP:** The external resolver from `destination.ip` (e.g., `8.8.8.8`)
   - **Port:** `53`
3. Click **Apply Rule**.
4. Verify the rule appears in the **Active Firewall Rules** table below.

The resulting `iptables` command executed by TCPspecter:
```bash
iptables -A INPUT -p udp -s 10.0.0.15 -d 8.8.8.8 --dport 53 -j DROP
```

### Via TUI (Quick Block)

If you are logged into the TUI and can see the suspicious connection:
1. Navigate to the connection row for the affected process using `↑`/`↓`.
2. Press `b` to block the external IP.

> **Note:** TUI quick block uses `block_ip()` which blocks all traffic from that IP globally. Use the web Rule Builder for more surgical blocking of specific protocol/port combinations.

---

## 4. Post-Containment Actions

After blocking the channel:

1. **Verify entropy drops.** Return to the Dashboard and monitor the Payload Entropy indicator. It should return to a baseline below 3.5 within a few minutes once the tunnel is severed.
2. **Investigate the source host.** The internal IP that was generating the anomalous DNS traffic (`source.ip`) requires forensic analysis. Use the Active Connections table to inspect all processes on that host currently communicating externally.
3. **Check for persistence.** Press `z` in the TUI to run a full Zombie Scan on the host to detect any malicious processes that may have survived even after the DNS channel was blocked.
4. **Preserve logs.** The `security_alerts.json` file contains the full ECS timeline. Copy it before it rotates (max 5,000 entries) for inclusion in your incident report.
