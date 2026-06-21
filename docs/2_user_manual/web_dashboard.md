# 🌐 Web Dashboard Guide

The TCPspecter Web Dashboard is a self-hosted Single Page Application (SPA) running on `http://localhost:8050` (or your configured `web_server_port`). It requires no external dependencies — all assets are embedded in the Python web server.

## Starting the Dashboard

The web server starts automatically when you run `./run.sh`. You do not need to run it separately.

---

## Navigation

The dashboard uses **client-side routing** — clicking navigation links or using the browser's back/forward buttons switches views without making new server requests (except for API data calls). The backend serves the same HTML for all SPA routes.

### Top Navigation Bar

| Route | Label | Content |
|-------|-------|---------|
| `http://localhost:8050/` | Dashboard | Risk score, protocol charts, alerts, connections table, geo map |
| `http://localhost:8050/firewall` | Firewall & IDS | Rule Builder, active firewall policies, Snort status |
| `http://localhost:8050/logs` | Logs | Parsed security event timeline |
| `http://localhost:8050/configuration` | Configuration | Language settings, tutorial link |

---

## Dashboard View (`/`)

### Risk Score Widget
Displays the current heuristic security score (0–100) computed by `zombie_detector.py`. The score refreshes every **1.5 seconds** via a polling call to `/api/data`.

**Score thresholds:**
- `0–30`: Normal (green)
- `31–60`: Elevated (blue/primary)
- `61–80`: High (amber/warning)
- `81–100`: Critical (red/danger)

### Protocol Distribution Chart
A doughnut chart showing the ratio of TCP : UDP : LISTEN sockets. Useful for quickly spotting unusual protocol spikes (e.g., a sudden surge in UDP may indicate DNS flooding or tunneling).

### CPU Process Chart
Bar chart of the top processes sorted by CPU usage. Correlates with the connections table — a process consuming high CPU with an outbound C2-port connection is a strong Indicator of Compromise.

### DNS Tunneling & Traffic Heuristics
Displays real-time data from `scapy_engine.py`:
- **Sniffed Packets** — total packets processed since startup
- **Payload Entropy** — rolling average Shannon entropy of captured packet payloads (values consistently above 4.5 suggest encrypted/tunneled traffic)
- **Alerts List** — live-scrolling list of DNS/DLP alerts from the Scapy engine

### Alerts Widget (C2 / Zombie)
Feeds from the Alert Bus subscriber registered in `web_server.py`. Displays the most recent `SecurityAlert` objects with severity badges. Each entry shows the engine source, category, and description.

### Global Connections Map
Renders active IP connections as geographic nodes on an Echarts world map. Data comes from `/api/geoip` lookups:
- **Green pulsing nodes** — connection endpoints with resolved geographic coordinates
- **Line trails** — animated paths showing traffic direction

> Note: The map is read-only (roaming and zoom are disabled to prevent accidental distortion). GeoIP lookups require an internet connection.

### Active Connections Table
Sorted, filterable table of all active sockets from `psutil.net_connections()`. Each row shows:
- Process name and PID
- Protocol (TCP/UDP)
- Source IP:Port → Destination IP:Port
- Connection state (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
- Risk evaluation badge

**Click any row** to open the **Explanation Engine (XAI) modal** — TCPspecter automatically interprets the connection in plain language, explaining what the destination IP represents, what the port is used for, and what the connection state means, along with a risk assessment.

---

## Firewall & IDS View (`/firewall`)

### Snort Service Status
Shows whether Snort IDS is installed and running. Controls:
- **Install Snort** button (shown only when not installed) — this button prompts you to install Snort via the TUI, not the web. This is intentional, as package installation requires terminal interaction.
- **Start/Stop Snort** button — toggles the Snort daemon.

### Enterprise Rule Builder
The most powerful feature for active response. Two modes:

**Quick Block:**
Enter an IP in the input field and click **Drop (Quick)** — this calls `POST /api/block_ip` which runs `firewall_manager.block_ip()`. The IP is validated and blocked via `iptables -I INPUT 1 -s <IP> -j DROP` or the `ufw` equivalent.

**Granular Rule (Advanced):**
Build a full iptables-compatible rule by specifying:
- **Action**: `DROP` / `ACCEPT` / `REJECT`
- **Protocol**: `TCP` / `UDP` / `ICMP` / `All`
- **Source IP**: (optional) filter by originating IP
- **Destination IP**: (optional) filter by target IP
- **Port**: (optional) specific destination port

This calls `POST /api/add_rule` → `firewall_manager.add_custom_rule()`. Note: granular rules currently require `iptables` backend (not UFW).

### Active Firewall Rules Table
Lists all active `DROP` rules extracted from `iptables -L INPUT -n` or `ufw status`. Shows the blocked IP, backend used (iptables/ufw), and chain target. Each row has an **Unblock** button that calls `POST /api/unblock_ip`.

---

## Configuration View (`/configuration`)

### Language Toggle
Switch the dashboard's UI language between **English** and **Spanish**. The preference is saved in browser `localStorage` — it persists between page refreshes and browser sessions without any backend involvement (zero server RAM overhead).

**Coverage:** All `data-i18n` tagged elements switch. This includes navigation labels, section titles, badges, and status text.

> Note: Log data, alert descriptions, and ECS fields are always in English regardless of UI language, as they originate from the backend.

### Tutorial Link
Links to `/tutorial` — an embedded interactive guide to the main features.

---

## Security Features of the Web Interface

| Feature | Implementation |
|---------|----------------|
| CSRF Protection | Single-use token per client with 30-minute TTL; invalidated immediately on first use |
| Rate Limiting | 30 mutating requests per minute per client IP (sliding window) |
| IP Validation | All IPs passed to firewall functions validated via `ipaddress` module |
| Security Headers | CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |
| No External CDN | All library assets (Chart.js, ECharts) loaded from CDN only — this requires internet; internal deployments should host locally |
