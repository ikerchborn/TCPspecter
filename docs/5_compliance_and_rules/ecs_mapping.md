# 📊 Elastic Common Schema (ECS) v1.12 Mapping

All TCPspecter security alerts are serialized to ECS v1.12 format by the `SecurityAlert.to_ecs()` method in `core/alerts.py`. This document maps TCPspecter's internal data model to ECS fields so you can write accurate SIEM queries and dashboards without reverse-engineering the log format.

---

## Output Files

| File | Format | Description |
|------|--------|-------------|
| `security_events.log` | Plain text | Human-readable log line per alert. Rotates at 2 MB. |
| `security_alerts.json` | JSON array | ECS documents. Capped at 5,000 most recent entries. |

**Text log line format (`security_events.log`):**
```
[2026-06-21 18:30:00] [DETECTED] [CRITICAL] [Defense Evasion] (PID 8922: unknown_bin) - Fileless memory injection detected.
```

---

## Field Mapping Reference

### Always-Present Fields

| TCPspecter Field | ECS Field | Type | Example Value |
|-----------------|-----------|------|---------------|
| `timestamp` | `@timestamp` | ISO-8601 string | `"2026-06-21T18:30:00Z"` |
| `description` | `message` | string | `"Fileless memory injection detected."` |
| `engine` | `tcpspecter.engine` | string | `"zombie_detector"` |
| `category` | `tcpspecter.category` | string | `"Defense Evasion"` |
| `severity` | `tcpspecter.severity` | string | `"CRITICAL"` |
| `status` | `tcpspecter.status` | string | `"DETECTED"` or `"RESOLVED"` |
| — | `ecs.version` | string | `"1.12.0"` |
| — | `event.kind` | string | `"alert"` |
| — | `event.provider` | string | `"TCPspecter"` |
| — | `event.dataset` | string | `"tcpspecter.security"` |
| — | `host.name` | string | System hostname |
| — | `host.os.family` | string | `"linux"` |

### Severity Numeric Mapping

| Severity | `event.severity` | `event.risk_score` |
|----------|------------------|--------------------|
| CRITICAL | 90 | 95 |
| HIGH | 70 | 73 |
| MEDIUM | 50 | 47 |
| LOW | 30 | 21 |
| WARNING | 20 | 15 |
| INFO | 10 | 5 |

### Event Type by Alert Status

| `status` | `event.type` | `event.action` |
|---------|--------------|----------------|
| `DETECTED` | `["indicator"]` | `"detected"` |
| `RESOLVED` | `["info"]` | `"resolved"` |

### Conditional Fields (Present Only When Data is Available)

| Condition | ECS Fields |
|-----------|-----------|
| `pid` is not None | `process.pid`, `process.name` |
| `source_ip` is not empty | `source.ip` |
| `dest_ip` is not empty | `destination.ip` |
| `mitre_technique_id` is not None | `threat.framework`, `threat.technique.id`, `threat.technique.name`, `threat.tactic.name` |
| `nist_controls` is not empty | `compliance.nist` (list of strings) |
| `iso_controls` is not empty | `compliance.iso` (list of strings) |
| `compliance_tags` is not empty | `compliance.tags` (list of strings) |

---

## Example ECS Document (Full)

```json
{
  "@timestamp": "2026-06-21T18:30:00Z",
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
    "module": "Defense Evasion"
  },
  "host": {
    "name": "prod-sensor-01",
    "os": {"family": "linux", "platform": "linux"}
  },
  "message": "Fileless memory injection: anonymous executable memory segment detected.",
  "process": {"name": "unknown_bin", "pid": 8922},
  "source": {"ip": "10.0.0.5"},
  "destination": {"ip": "198.51.100.45"},
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {"id": "T1055", "name": "Process Injection"},
    "tactic": {"name": "Defense Evasion"}
  },
  "compliance": {
    "nist": ["DE.CM-7"],
    "iso": ["A.12.6.1"],
    "tags": ["NIST-IR-8011", "ISO-27001-A.12.6.1"]
  },
  "tcpspecter": {
    "engine": "zombie_detector",
    "status": "DETECTED",
    "severity": "CRITICAL",
    "category": "Defense Evasion"
  }
}
```

---

## Ingest with Filebeat (Example)

```yaml
# filebeat.inputs in filebeat.yml
- type: log
  paths:
    - /path/to/tcpspecter/security_alerts.json
  json.keys_under_root: true
  json.add_error_key: true
  json.expand_keys: true
```

No custom Grok patterns or processors are needed. The ECS keys map natively to Elasticsearch and Kibana's built-in index templates.
