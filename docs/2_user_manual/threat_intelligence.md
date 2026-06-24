# Threat Intelligence Engine

TCPspecter includes a **local Threat Intelligence Engine** that enriches live connection and DNS analysis with operator-controlled feed data. No external API calls are required for correlation — all matching runs in-process against files under `data/feeds/`.

---

## Architecture

```text
[data/feeds/*.csv|txt]
         │
         ▼
core/intelligence_engine.py  ──→  match_port / match_ip / match_domain
         │
         ├── core/zombie_detector.py   (outbound socket correlation)
         ├── core/traffic_analyzer.py  (DNS + packet IP correlation)
         └── core/service_catalog.py   (Explanation Engine port labels)
         │
         ▼
   alerts.publish(SecurityAlert)  ──→  Alert Bus ──→ Web / TUI / ECS / Webhooks
```

The engine is a singleton loaded at startup via `initialize_intelligence()`. It is thread-safe and supports hot reload through the web API.

---

## Detection Categories

| Match Type | Source Feed | Severity | MITRE ATT&CK |
|------------|-------------|----------|--------------|
| Threat Port Match | `suspicious_ports.csv` | Based on confidence | T1071 |
| Tor Exit Node | `tor_exit_nodes.txt` | CRITICAL | T1090.003 |
| Sinkholed Infrastructure | `sinkholed_ips.txt`, `sinkholed_domains.txt` | CRITICAL | T1071 |
| Dynamic DNS Provider | `dyndns_domains.txt` | HIGH | T1568 |
| Suspicious TLD | `suspicious_tlds.txt` | MEDIUM | T1568.002 |
| Custom Blacklist Hit | `custom_blacklist.txt` | CRITICAL | T1071 |

---

## Integration Points

### Process Forensics (`zombie_detector.py`)

Every established outbound connection to a public IP is cross-referenced against port and IP feeds. Matches appear in the **risk score panel** and are published to the Alert Bus when first detected.

### Deep Packet Inspection (`traffic_analyzer.py`)

DNS queries are checked for sinkholed domains, dynamic DNS suffixes, and suspicious TLDs. TCP traffic destination IPs are checked against IP feeds.

### Explanation Engine (`service_catalog.py`)

When a connection row is interpreted in the TUI or web dashboard, threat intelligence port labels override generic IANA descriptions when available.

---

## Web Dashboard

Navigate to **Threat Intelligence** (`/intelligence`) to:

- View loaded feeds and entry counts
- Monitor live intelligence alerts
- Toggle the engine on/off
- Reload feeds after editing local files

The main dashboard also shows a summary card with feed statistics and recent matches.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/intelligence` | Engine status and feed metadata |
| `POST` | `/api/intelligence/reload` | Reload all feeds from disk |
| `POST` | `/api/intelligence/toggle` | Enable/disable correlation |

All mutating endpoints require a valid CSRF token.

---

## Operational Notes

1. **Tor exit list**: The bundled `tor_exit_nodes.txt` contains a snapshot. Replace or extend it periodically for production use.
2. **False positives**: Dynamic DNS and suspicious TLD matches are contextual — browsers resolving CDN or legitimate SaaS domains on unusual TLDs may trigger MEDIUM alerts. Tune feeds as needed.
3. **Performance**: IP matching uses hash sets and CIDR networks. Domain suffix matching is linear in feed size; typical feed sizes (< 10k entries) add negligible overhead.

See also: [Threat Intelligence Feeds](../../data/feeds/README.md)
