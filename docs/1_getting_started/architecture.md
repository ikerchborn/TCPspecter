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
| Threat Port Match | T1071 | Command and Control |
| Tor Exit Node | T1090.003 | Command and Control |
| Sinkholed Infrastructure | T1071 | Command and Control |

**Port intelligence** is loaded from `data/feeds/suspicious_ports.csv` via the Threat Intelligence Engine (see section 6). A legacy hard-coded fallback set remains when the engine is disabled.

**Risk scoring formula:**
```
Risk Score = sum of all active finding scores, capped at 100
  CRITICAL finding: +40
  HIGH finding:     +25
  MEDIUM finding:   +10
  LOW finding:      +5
```

---

### 2. Deep Packet Inspection Engine — `core/traffic_analyzer.py`

Performs real-time Layer 3/4 packet analysis using Scapy's BPF interface. Requires root to open raw sockets.

**What it analyzes:**
- **DNS queries**: DGA heuristics, DNS tunneling frequency, TXT query length anomalies, and threat intelligence domain correlation (sinkholes, DynDNS, suspicious TLDs).
- **TCP Payloads**: Shannon entropy analysis, magic-byte DLP detection, and IP feed correlation on destination addresses.
- **Port scans**: SYN scan detection (15+ distinct ports in 10 seconds).

---

### 3. Threat Intelligence Engine — `core/intelligence_engine.py`

Loads local CSV/text feeds from `data/feeds/` and provides fast matchers for ports, IPs, and domains. Integrated into both the process forensics engine and the packet analyzer. Publishes alerts with `engine="intelligence"`.

See [`docs/2_user_manual/threat_intelligence.md`](../2_user_manual/threat_intelligence.md) for feed formats and API details.

---

### 4. Alert Bus — `core/alerts.py`

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

### 5. Firewall Manager — `core/firewall_manager.py`

Handles all interactions with the host OS firewall. It **auto-detects** the available backend at call time:

1. Checks if `/usr/sbin/ufw` exists and reports `Status: active` → uses `ufw`
2. Falls back to `iptables` if found at `/sbin/iptables` or `/usr/sbin/iptables`
3. Returns `"none"` if neither is available

**Critical security note:** All IP addresses are validated through a strict regex pattern AND Python's `ipaddress` module before being passed to any subprocess call. Loopback, link-local, and malformed IPs are rejected.

**Quarantine chain names:**
- `TCPSPECTER-Q-IN` — injected at position 1 of the `INPUT` chain
- `TCPSPECTER-Q-OUT` — injected at position 1 of the `OUTPUT` chain

---

### 6. Web Server — `core/web_server.py`

FastAPI application serving the web dashboard SPA, REST API, and WebSocket live updates.

**Key routes:**
- `GET /` `GET /firewall` `GET /intelligence` `GET /configuration` `GET /logs` → SPA shell
- `GET /api/data` → live dashboard JSON (connections, security score, intelligence stats)
- `GET /api/intelligence` → threat feed status
- `POST /api/intelligence/reload` → hot-reload feeds from disk
- `POST /api/intelligence/toggle` → enable/disable correlation engine

**Security middleware on all POST endpoints:**
1. Rate limit check (30 req/min/IP via sliding window)
2. CSRF token validation (single-use, 30-minute TTL)
3. IP sanitization before any firewall call
