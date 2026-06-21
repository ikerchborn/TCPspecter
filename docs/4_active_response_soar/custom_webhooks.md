# 🔗 Custom Webhooks Integration

TCPspecter can forward every security alert to an external endpoint via signed HTTP POST — enabling real-time integration with SIEM platforms, ticketing systems, and SOAR orchestrators.

## Configuration

In `config.json`, set both keys:
```json
{
    "webhook_url": "https://your-siem.corp.local/api/v1/tcpspecter",
    "webhook_secret": "your-shared-secret-for-hmac-verification"
}
```

The `_trigger_webhook()` function in `core/alerts.py` reads these values **at alert dispatch time** (not at startup), meaning you can update them without restarting TCPspecter. A 2-second timeout is enforced per request; failures are logged as warnings but do not block alert processing.

---

## Request Format

Every alert triggers an HTTP POST request containing the full ECS v1.12 JSON document.

**Example request:**
```
POST https://your-siem.corp.local/api/v1/tcpspecter
Content-Type: application/json
User-Agent: TCPspecter-SOAR-Webhook
X-TCPspecter-Signature: 3a7d8f2e1b...  (SHA256 hex, present only when webhook_secret is set)
```

**Example payload (from `SecurityAlert.to_ecs()`):**
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
    "name": "sensor-01",
    "os": {"family": "linux", "platform": "linux"}
  },
  "message": "Fileless memory injection: process running with no on-disk binary.",
  "process": {
    "name": "unknown_bin",
    "pid": 8922
  },
  "source": {"ip": "10.0.0.5"},
  "destination": {"ip": "198.51.100.45"},
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {"id": "T1055", "name": "Process Injection"},
    "tactic": {"name": "Defense Evasion"}
  },
  "compliance": {
    "nist": ["DE.CM-7"],
    "iso": ["A.12.6.1"]
  },
  "tcpspecter": {
    "engine": "zombie_detector",
    "status": "DETECTED",
    "severity": "CRITICAL",
    "category": "Defense Evasion"
  }
}
```

**Severity numeric mapping** (ECS `event.severity` field):

| TCPspecter Severity | ECS `event.severity` | ECS `event.risk_score` |
|--------------------|----------------------|------------------------|
| CRITICAL | 90 | 95 |
| HIGH | 70 | 73 |
| MEDIUM | 50 | 47 |
| LOW | 30 | 21 |
| WARNING | 20 | 15 |
| INFO | 10 | 5 |

---

## Signature Verification

If `webhook_secret` is set, the `X-TCPspecter-Signature` header contains an HMAC-SHA256 hex digest of the raw JSON payload bytes, computed using the secret as the key.

**Verify in Python (receiving side):**
```python
import hmac
import hashlib

def verify_signature(payload_bytes: bytes, secret: str, received_sig: str) -> bool:
    expected = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, received_sig)
```

**Verify in Node.js:**
```javascript
const crypto = require('crypto');

function verifySignature(payloadBuffer, secret, receivedSig) {
    const expected = crypto
        .createHmac('sha256', secret)
        .update(payloadBuffer)
        .digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(receivedSig));
}
```

---

## Platform Integration Examples

### Wazuh Active Response
Configure a Wazuh custom integration that receives the TCPspecter webhook and creates Wazuh alerts from the ECS payload. The `tcpspecter.engine` and `threat.technique.id` fields map directly to Wazuh rule groups and MITRE tagging.

### TheHive
Use TheHive's REST API as the `webhook_url`. The ECS `event.severity` (numeric) can map to TheHive case severity levels. The `message` field becomes the case description.

### Slack / PagerDuty
Forward alerts to a Slack Incoming Webhook or PagerDuty Events API v2 endpoint. Note that these platforms do not verify HMAC signatures natively — in this case, use network-level access control (firewall rules) to restrict who can *send to* the TCPspecter webhook URL instead.

---

## Network Security Considerations

- The webhook is sent from TCPspecter's host. Ensure the receiving endpoint is reachable from the sensor's network.
- The webhook request is dispatched asynchronously in a daemon thread with a **2-second timeout**. If your endpoint is slow or unreachable, alerts are not delayed — they are dropped after the timeout with a warning log.
- For air-gapped environments, disable the webhook (`webhook_url = ""`) and rely on the local `security_alerts.json` file for SIEM ingestion via log forwarders like Filebeat.
