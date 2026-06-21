# 🏗️ System Architecture

TCPspecter is built on a **Zero-Coupling, Kernel-Assisted** architecture. No module in the detection layer ever imports from the UI or web server layer. This prevents circular dependencies and ensures each subsystem can be tested, replaced, or scaled independently.

---

## Detection Engines

### 1. Process Forensics Engine — `core/zombie_detector.py`

This is the heart of TCPspecter's heuristic detection. It operates entirely in **user space** by reading the Linux `/proc` filesystem — no kernel modules or eBPF programs are required. This means it runs on any standard Linux kernel.

**What it analyzes:**
- `/proc/<pid>/maps` — Memory maps of each running process, looking for anonymous executable segments (`rwxp` permissions with no file backing), which are the signature of shellcode injection or process hollowing (MITRE T1055).
- `/proc/<pid>/exe` — Checks if the underlying binary exists on disk. A running process whose executable has been deleted is a critical Indicator of Compromise (T1070.004).
- `/proc/<pid>/net/tcp` — Corroborates network activity per process.

**Detection categories and MITRE mappings (hardcoded in `zombie_detector.py`):**

| Detection | MITRE ID | Tactic |
|-----------|----------|--------|
| Deleted Binary | T1070.004 | Defense Evasion |
| Suspicious Path (`/tmp`, `/dev/shm`) | T1059 | Execution |
| SUID Binary with Network Activity | T1548.001 | Privilege Escalation |
| Shell with Active Connection | T1059.004 | Execution |
| Process Masquerading | T1036.005 | Defense Evasion |
| Orphaned C2 Agent | T1543 | Persistence |
| Atypical SSL Traffic | T1071.001 | Command and Control |
| C2 Beaconing (Statistical) | T1071.001 | Command and Control |
| Fileless Memory | T1055 | Defense Evasion |
| Mass Connections | T1046 | Discovery |

**Known ports flagged as C2 (hard-coded set):**
```
6667-6669, 7000  (IRC Botnets)
9001, 9050-9051  (Tor / Proxy)
4444, 4445, 5555, 8888  (Metasploit / Netcat / Reverse Shells)
3333, 14444, 18080  (Cryptominers / Stratum)
5900, 5938  (VNC / RATs)
```

**Risk scoring formula:**
```
Risk Score = sum of all active finding scores, capped at 100
  CRITICAL finding: +40
  HIGH finding:     +25
  MEDIUM finding:   +10
  LOW finding:      +5
```

---

### 2. Deep Packet Inspection Engine — `core/scapy_engine.py`

Performs real-time Layer 3/4 packet analysis using Scapy's BPF interface. Requires root to open raw sockets.

**What it analyzes:**
- **DNS queries**: Captures UDP port 53 traffic and measures the Shannon Entropy of query subdomains. Entropy values consistently above **4.5 bits/byte** suggest algorithmically-generated domain names (DGA) or Base64-encoded tunneled data (T1048.003).
- **TCP Payloads**: Extracts HTTP payload bytes and computes Shannon Entropy to detect encrypted or obfuscated C2 channels.

---

### 3. Alert Bus — `core/alerts.py`

The central event-driven communication backbone. Implements an **Observer pattern** using a thread-safe `queue.Queue(maxsize=10_000)`.

**Data flow:**
```
Detection Engine
      │
      ▼
alerts.publish(SecurityAlert)
      │
      ▼
Queue (max 10,000 pending alerts)
      │
      ▼
_dispatcher_worker() thread (background, daemon=True)
      │
      ├── _persist_alert()     → writes to security_events.log (text) + security_alerts.json (ECS)
      ├── _trigger_webhook()   → HTTP POST (async daemon thread, 2s timeout)
      └── notify subscribers() → web_server.py callback, TUI callback
```

**Alert capacity limits:**
- Queue: 10,000 alerts in memory before new ones are dropped
- Text log: auto-rotated at 2 MB
- JSON file: capped at 5,000 most recent alerts

---

### 4. Firewall Manager — `core/firewall_manager.py`

Handles all interactions with the host OS firewall. It **auto-detects** the available backend at call time:

1. Checks if `/usr/sbin/ufw` exists and reports `Status: active` → uses `ufw`
2. Falls back to `iptables` if found at `/sbin/iptables` or `/usr/sbin/iptables`
3. Returns `"none"` if neither is available

**Critical security note:** All IP addresses are validated through a strict regex pattern AND Python's `ipaddress` module before being passed to any subprocess call. Loopback, link-local, and malformed IPs are rejected.

**Quarantine chain names:**
- `TCPSPECTER-Q-IN` — injected at position 1 of the `INPUT` chain
- `TCPSPECTER-Q-OUT` — injected at position 1 of the `OUTPUT` chain

---

### 5. Web Server — `core/web_server.py`

A self-contained `http.server.BaseHTTPRequestHandler` serving a Single Page Application (SPA). All HTML, CSS, and JavaScript is embedded as Python string constants.

**Routes:**
- `GET /` `GET /firewall` `GET /configuration` → serve the SPA (client-side routing handles view switching)
- `GET /logs` → serve the Security Logs page
- `GET /api/data` → returns live system JSON data (connections, security score, blocked IPs, Scapy stats)
- `GET /api/logs` → returns parsed security_events.log
- `POST /api/block_ip` → calls `firewall_manager.block_ip()` (rate-limited, CSRF-protected)
- `POST /api/unblock_ip` → calls `firewall_manager.unblock_ip()`
- `POST /api/add_rule` → calls `firewall_manager.add_custom_rule()`

**Security middleware on all POST endpoints:**
1. Rate limit check (30 req/min/IP via sliding window)
2. CSRF token validation (single-use, 30-minute TTL)
3. IP sanitization before any firewall call
