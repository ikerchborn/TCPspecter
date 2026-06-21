# 🚀 TCPspecter Installation Guide

## System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| OS | Any Linux with kernel 4.4+ | Debian 11+, Ubuntu 22.04+, Parrot OS 5+ |
| Python | 3.8+ | 3.11+ |
| Terminal | 80×24 characters | 120×40 |
| RAM | 256 MB | 512 MB |
| Privileges | Root (`sudo`) required | Dedicated service user with `CAP_NET_RAW` |

> **Root is required** for raw socket access (Scapy DPI), `/proc/<pid>/maps` reading of other users' processes, and `iptables`/`ufw` management.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/tcpspecter.git
cd tcpspecter
```

### 2. Run the Launcher

```bash
chmod +x run.sh
./run.sh
```

`run.sh` handles everything:
1. Creates a Python virtual environment (`.venv/`) in the project directory
2. Installs dependencies from `requirements.txt` into the virtualenv
3. Elevates to root via `sudo` (will prompt for password)
4. Starts the TUI and the web server simultaneously

### 3. Access the Web Dashboard

Once running, open your browser:
```
http://localhost:8050
```

The TUI and the web dashboard share the same data — you can use both at the same time.

---

## Manual Installation (Without run.sh)

If you prefer manual control:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run as root
sudo .venv/bin/python tcpspecter.py
```

---

## Dependencies

All dependencies are listed in `requirements.txt`. Core runtime dependencies:

| Package | Purpose |
|---------|---------|
| `psutil` | Process inspection, CPU/memory stats, network connections |
| `scapy` | Raw packet capture and deep packet inspection |
| `urwid` | Terminal User Interface (TUI) rendering |

> The web server uses only Python's built-in `http.server` module — no Flask, FastAPI, or external web frameworks are required.

---

## First-Time Configuration

Before running in any environment, review `config.json`:

```bash
cp config.json.example config.json   # if an example file exists
nano config.json
```

Key settings to review on first start:
- `ACTIVE_RESPONSE_ENABLED`: Leave as `false` until you have profiled your network.
- `MANAGEMENT_IP_WHITELIST`: Verify it includes your analyst workstation's IP if it's outside RFC 1918 ranges.
- `web_server_port`: Change if `8050` conflicts with another service.

See [`configuration.md`](configuration.md) for the full parameter reference.

---

## Running as a Systemd Service (Production)

For persistent operation across reboots on a dedicated sensor:

```ini
# /etc/systemd/system/tcpspecter.service

[Unit]
Description=TCPspecter Network Detection & Response Sensor
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/tcpspecter
ExecStart=/opt/tcpspecter/.venv/bin/python /opt/tcpspecter/tcpspecter.py
Restart=on-failure
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable tcpspecter
sudo systemctl start tcpspecter
sudo systemctl status tcpspecter
```

The web dashboard will be available on the configured port immediately. Monitor logs with:
```bash
journalctl -u tcpspecter -f
```

---

## Verifying the Installation

After starting, confirm the following in the TUI:
- **Status bar** shows `Root: YES` — required for full functionality.
- **Snort status** shows either `ACTIVE` (if installed) or `NOT INSTALLED` — Snort is optional and can be installed separately.
- The web dashboard loads at `http://localhost:8050/` and the Risk Score widget shows a number (even if 0).

If the web dashboard is unreachable, check whether another process is using the configured port:
```bash
sudo ss -tlnp | grep 8050
```
