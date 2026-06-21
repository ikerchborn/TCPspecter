# 💻 TUI Navigation Guide

The TCPspecter Terminal User Interface (TUI) is designed for security analysts who need low-latency, keyboard-driven access to network forensics without leaving the terminal. It renders inside any standard terminal emulator at a minimum size of **80×24 characters**.

## Launching the TUI

```bash
sudo ./run.sh
```

The TUI starts automatically alongside the web server. Both interfaces share the same underlying data — you can use both simultaneously.

---

## Panel Layout

The TUI is organized into multiple panels. Use `TAB` to move focus between them.

```
┌─────────────────────────────────────────────────────────┐
│  HEADER: Status Bar                                     │
│  Version | Root Status | Fail-Safe Mode | Snort Status  │
├──────────────────────────────┬──────────────────────────┤
│  CONNECTIONS TABLE (main)    │  SECURITY ANALYSIS        │
│  Live socket list with PIDs  │  Risk Score / Alerts      │
│  process names, ports, IPs   │  Recent findings          │
├──────────────────────────────┴──────────────────────────┤
│  STATUS BAR: Scapy packet count | Bandwidth | Filter    │
└─────────────────────────────────────────────────────────┘
```

---

## Complete Keyboard Reference

### Navigation

| Key | Action | Description |
|:----|:-------|:------------|
| `↑` / `k` | Cursor Up | Move row selection up in the active table |
| `↓` / `j` | Cursor Down | Move row selection down in the active table |
| `TAB` | Switch Panel | Toggle keyboard focus between available panels |
| `ESC` | Cancel / Close | Close any open dialog, modal, or search bar |
| `q` | Quit | Gracefully terminate TCPspecter and release all raw sockets |

### Filtering & Sorting

| Key | Action | Description |
|:----|:-------|:------------|
| `/` | Filter | Open a real-time search bar — filters by IP, port, PID, or process name as you type |
| `p` | Protocol Filter | Cycle through protocol views: `ALL` → `TCP` → `UDP` → `LISTEN` |
| `s` | Sort | Change the sort column for the connections table |
| `c` | View Toggle | Switch between *all system connections* and *connections for selected process only* |

### Analysis

| Key | Action | Description |
|:----|:-------|:------------|
| `a` | Local Analysis | Offline binary analysis of the selected process: SUID bits, file hashes, permissions |
| `v` | VirusTotal | Live binary hash lookup via VirusTotal API (requires `virustotal_api_key` in `config.json`) |
| `i` | Interpret | Open the Explanation Engine — translates the selected socket to plain-language risk description |
| `z` | Zombie Scan | Trigger a full heuristic audit: memory maps, deleted binaries, C2 beaconing analysis |

### Actions

| Key | Action | Description |
|:----|:-------|:------------|
| `x` | Kill Process | Terminate the selected PID (shows a confirmation prompt before acting) |
| `b` | Block IP | Block the external IP of the selected connection via `iptables`/`ufw` |
| `e` | Export | Generate a report of current system state in CSV or JSON format |
| `d` | Resolve DNS | Toggle background reverse DNS resolution for all visible IPs |

### View Switching

| Key | Action | Description |
|:----|:-------|:------------|
| `m` | Map (Browser) | Open the geographic connections map in your default browser |
| `g` | Charts (TUI) | Open the embedded performance charts modal inside the terminal |
| `Shift+G` | Charts (Browser) | Open the full web dashboard in your default browser |

### Security Controls

| Key | Action | Description |
|:----|:-------|:------------|
| `S` | Toggle Analytics | Enable/disable advanced heuristic security scanning in real time |
| `f` | Firewall Panel | Open the firewall control panel showing active `iptables`/`ufw` rules |
| `t` | Toggle Snort | Start or stop the passive Snort IDS service |

---

## Understanding the Risk Score

The risk score displayed in the Security Analysis panel is computed by `zombie_detector.py`:

```
Score = Σ(finding weights), capped at 100

  CRITICAL finding:  +40 pts  (e.g., deleted binary with active connection)
  HIGH finding:      +25 pts  (e.g., execution from /tmp)
  MEDIUM finding:    +10 pts  (e.g., suspicious listening port)
  LOW finding:       +5 pts   (informational)
```

A score of 0–30 is **Normal**, 31–60 is **Elevated**, 61–80 is **High**, and 81–100 is **Critical**.

---

## Headless / Daemonized Operation

For server deployments where you don't need the TUI, you can access all functionality through the web dashboard at `http://localhost:8050`. The background detection engines and Alert Bus run independently of which interface is active.
