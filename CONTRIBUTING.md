# Contributing to TCPspecter

Thank you for considering contributing! TCPspecter is an open-source Linux network security monitor and we welcome contributions from the community.

## English-First Policy
All internal codebase elements MUST be written in **English**:
- Variable and function names
- Docstrings and inline code comments
- Internal system log messages
- Commit messages and PR descriptions

UI-facing strings (displayed in the web dashboard) should use the `data-i18n` attribute and be added to the translations dictionary in `web/static/js/app.js` for both English and Spanish.

## Getting Started
```bash
git clone https://github.com/your-org/tcpspecter.git
cd tcpspecter
sudo ./run.sh
```
> Root privileges are required for raw socket access, firewall management, and Snort IDS integration. Always test in a secure VM or container.

## Project Architecture
| Path | Purpose |
|---|---|
| `core/web_server.py` | FastAPI backend — all API routes and WebSocket |
| `core/data_aggregator.py` | Business logic — dashboard data collection |
| `core/zombie_detector.py` | Process threat heuristics (PPID-aware scoring) |
| `core/snort_manager.py` | Snort IDS lifecycle management |
| `core/firewall_manager.py` | iptables/nftables abstraction |
| `web/templates/` | HTML templates served by FastAPI |
| `web/static/` | CSS and JavaScript frontend assets |
| `tests/` | pytest test suite |

## Pull Request Guidelines
1. Fork and create a branch from `main`
2. Follow the English-First Policy above
3. Add tests in `tests/` for new functionality
4. Ensure `pytest tests/` passes before submitting
5. Describe what your PR does and WHY in the PR description

## Adding Security Heuristics
When modifying `core/zombie_detector.py`:
- **Use Process Lineage (PPID):** Never flag a process purely by name. Check its parent process first.
- **Use the Scoring Matrix:** Add to `proc_risk_score` rather than creating binary CRITICAL triggers.
- **Add to MITRE/NIST maps:** Map new detections to their ATT&CK technique.

## Reporting Issues
Please open a GitHub issue with:
- OS and kernel version (`uname -a`)
- Python version (`python3 --version`)
- Steps to reproduce
- Relevant log output from `security_events.log`

Thank you for helping make TCPspecter better!
