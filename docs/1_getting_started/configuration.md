# ⚙️ Configuration Reference

TCPspecter stores all runtime configuration in `config.json` at the project root. This file is read at startup and also re-read dynamically by specific modules (e.g., the webhook dispatcher reads it at alert time).

## Complete `config.json` Reference

```json
{
  "virustotal_api_key": "",
  "ACTIVE_RESPONSE_ENABLED": false,
  "MANAGEMENT_IP_WHITELIST": [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],
  "SOAR_WEBHOOK_URL": "",
  "TARPIT_PORT": 2222,
  "web_server_port": 8050,
  "webhook_url": "",
  "webhook_secret": "",
  "INTELLIGENCE_ENABLED": true,
  "INTELLIGENCE_FEED_DIR": "data/feeds"
}
```

---

## Parameter Reference

### `INTELLIGENCE_ENABLED`
- **Type:** Boolean
- **Default:** `true`
- **Effect:** When `true`, TCPspecter cross-references live connections and DNS queries against local feeds in `INTELLIGENCE_FEED_DIR`. When `false`, only the legacy hard-coded C2 port set is used for port matching.

### `INTELLIGENCE_FEED_DIR`
- **Type:** String (path)
- **Default:** `data/feeds`
- **Effect:** Directory containing threat intelligence feed files. Can be relative to the project root or an absolute path. See [`data/feeds/README.md`](../../data/feeds/README.md).

---

### `ACTIVE_RESPONSE_ENABLED`
- **Type:** Boolean
- **Default:** `false`
- **Effect:** When `false`, TCPspecter operates in **Audit Mode** — all detections are logged and displayed in the dashboard, but no automated firewall rules are created. Set to `true` only after you have profiled your network baseline to avoid false-positive blocks.

> ⚠️ **Start in Audit Mode (`false`).** Enabling automated blocking on a production system without a traffic baseline will cause legitimate connections to be dropped.

---

### `MANAGEMENT_IP_WHITELIST`
- **Type:** List of CIDR strings
- **Default:** All RFC 1918 private subnets
- **Effect:** A list of trusted IP subnets used by the **Response Engine** (`core/response_engine.py`) to prevent self-isolation. When an alert triggers automated blocking, if the source or destination IP falls within these ranges, no block rule is created.

**Important:** The underlying `firewall_manager.py` functions (`block_ip`, `add_custom_rule`) do **not** check this whitelist on their own. The whitelist is enforced at the response engine orchestration layer.

---

### `webhook_url`
- **Type:** String (URL)
- **Default:** `""` (disabled)
- **Effect:** When set, every `SecurityAlert` published to the Alert Bus will be forwarded as an HTTP POST to this URL. The payload is the full ECS JSON document. Leave empty to disable.

### `webhook_secret`
- **Type:** String
- **Default:** `""` (unsigned)
- **Effect:** If set, the webhook dispatcher computes an HMAC-SHA256 signature of the JSON payload using this secret and sends it in the `X-TCPspecter-Signature` HTTP header. The receiving endpoint should verify this signature to authenticate the request.

**Webhook headers sent:**
```
Content-Type: application/json
User-Agent: TCPspecter-SOAR-Webhook
X-TCPspecter-Signature: <sha256_hex>  (only when webhook_secret is set)
```

---

### `virustotal_api_key`
- **Type:** String
- **Default:** `""` (disabled)
- **Effect:** Enables live VirusTotal reputation lookups from the TUI (`v` key) for the binary of the selected process. Requires a free or paid VirusTotal account.

---

### `TARPIT_PORT`
- **Type:** Integer
- **Default:** `2222`
- **Effect:** The local TCP port where `core/tarpit.py` listens. When `enable_tarpit(attacker_ip)` is called from `firewall_manager.py`, it redirects all TCP SYN packets from the attacker's IP to this port using an `iptables` PREROUTING DNAT rule. The Tarpit server responds at an extremely slow rate to exhaust automated scanners.

---

### `web_server_port`
- **Type:** Integer
- **Default:** `8050`
- **Effect:** The TCP port the built-in web server (`core/web_server.py`) binds to. Access the dashboard at `http://localhost:<port>`.

---

## Applying Configuration Changes

Restart the application after editing `config.json` for most changes to take effect. The webhook URL and secret are re-read from disk at each alert dispatch, so those can be updated without a full restart.
