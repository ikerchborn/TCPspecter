# 🛡️ Automated Mitigation & SOAR Containment

This document describes how TCPspecter's response engine orchestrates automated firewall actions, host quarantine, and deception tarpitting.

> ⚠️ **By default, `ACTIVE_RESPONSE_ENABLED = false`.** All automated blocking is disabled until you explicitly enable it in `config.json`. In its default state, TCPspecter is a pure IDS/auditing tool.

---

## The Fail-Safe Architecture

The most critical requirement of any automated response system is **not blocking yourself**. TCPspecter implements this through the `MANAGEMENT_IP_WHITELIST` in `config.json`.

**How it works in practice:**
When a CRITICAL alert is processed by the Response Engine (`core/response_engine.py`), before calling any `firewall_manager` function, the engine checks whether the alert's source or destination IP falls within the configured management subnets. If it does, the alert is logged and displayed but **no block rule is created**.

```json
"MANAGEMENT_IP_WHITELIST": [
    "127.0.0.0/8",   ← Loopback — never blocked
    "10.0.0.0/8",    ← RFC 1918 class A private
    "172.16.0.0/12", ← RFC 1918 class B private
    "192.168.0.0/16" ← RFC 1918 class C private
]
```

**Add your analyst workstation's IP** to this list if it is not in a private range (e.g., VPN IPs in a custom range) before enabling active response.

---

## Quick IP Blocking (Manual)

The simplest response action. Available from both the **Web Dashboard** (`/firewall`) and the **TUI** (`b` key).

**What happens when you block an IP:**
1. `firewall_manager.detect_backend()` checks for `ufw` first, then `iptables`.
2. The IP is validated (regex + `ipaddress` module — loopback and link-local are rejected).
3. The appropriate command is executed:
   - **ufw:** `ufw insert 1 deny from <IP> to any`
   - **iptables:** `iptables -I INPUT 1 -s <IP> -j DROP`
4. The blocked IP appears in the **Active Firewall Rules** table on the web dashboard.

**To unblock:** Click the **Unblock** button in the Active Firewall Rules table, or press `b` again in the TUI on an already-blocked connection.

---

## Granular Rule Builder (Advanced Blocking)

When a simple IP block is too broad, use the Advanced Rule Builder in the web dashboard (`/firewall`) to create protocol- and port-specific rules.

**Rules are created as:**
```bash
iptables -A INPUT [-p tcp|udp] [-s src_ip] [-d dst_ip] [--dport port] -j DROP|ACCEPT|REJECT
```

> **Note:** Granular custom rules currently require `iptables` as the backend. Systems running UFW-only will see a failure for this action. Use the Quick Block for UFW systems.

---

## Host Quarantine (`quarantine_host`)

For severe incidents where a single IP block is insufficient, TCPspecter can **fully isolate the host**. This is the equivalent of physically unplugging a server from the network, but preserving access for analysts.

**What quarantine does:**
1. Creates two custom `iptables` chains: `TCPSPECTER-Q-IN` and `TCPSPECTER-Q-OUT`
2. Populates them to:
   - `ACCEPT` all loopback (`lo`) traffic
   - `ACCEPT` traffic from/to each IP in `MANAGEMENT_IP_WHITELIST`
   - `DROP` everything else
3. Injects both chains at position 1 of `INPUT` and `OUTPUT` (highest priority)

**The result:** Only your analyst workstations (from the whitelist) can reach the quarantined host. All other inbound and outbound traffic is silently dropped.

**To remove quarantine:**
```python
# Via the response engine or directly:
from core.firewall_manager import remove_quarantine
remove_quarantine()
```

This removes the jump rules and flushes/deletes the custom chains, restoring normal operation.

> ⚠️ **Quarantine requires iptables.** UFW systems cannot use this feature.

---

## Deception Tarpitting

Instead of simply dropping packets from an attacker — which tells them the port is blocked — TCPspecter can **redirect attackers to a Tarpit** that accepts connections but responds at an extremely slow rate. This wastes the attacker's resources and time.

**How the Tarpit works:**
1. `firewall_manager.enable_tarpit(attacker_ip)` injects an `iptables` PREROUTING DNAT rule:
   ```bash
   iptables -t nat -I PREROUTING 1 -s <attacker_ip> -p tcp --syn -j REDIRECT --to-ports <TARPIT_PORT>
   ```
2. All TCP SYN packets from the attacker's IP are redirected to `core/tarpit.py` running on `TARPIT_PORT` (default: `2222`).
3. The Tarpit server responds to each connection by sending **1 byte every 15 seconds**, keeping the attacker's connection open indefinitely while consuming minimal server resources.

**To disable tarpitting for an IP:**
```python
from core.firewall_manager import disable_tarpit
disable_tarpit("198.51.100.45")
```

---

## Automated Response Flow (When `ACTIVE_RESPONSE_ENABLED = true`)

When active response is enabled, the Response Engine subscribes to the Alert Bus and processes CRITICAL alerts automatically:

```
Alert published to bus (severity=CRITICAL)
          │
          ▼
Response Engine receives alert via subscriber callback
          │
          ├── IP in MANAGEMENT_IP_WHITELIST? → YES → Log only, no action
          │
          └── NO →
                ├── Alert category = "C2 Beaconing" or "Memoria Fileless"?
                │         → quarantine_host(MANAGEMENT_IP_WHITELIST)
                │
                └── Alert category = other CRITICAL?
                          → block_ip(source_ip or dest_ip)
```

> **Recommendation:** Run for at least 48–72 hours in audit mode (`ACTIVE_RESPONSE_ENABLED = false`) before enabling automated response. This establishes a baseline and prevents false-positive blocks of legitimate services.
