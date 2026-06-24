# Threat Intelligence Feeds

TCPspecter loads local threat intelligence feeds from this directory at startup.
All feeds are optional except `suspicious_ports.csv`, which ships with the project.

## Feed Files

| File | Format | Purpose |
|------|--------|---------|
| `suspicious_ports.csv` | CSV | Malicious or high-risk port catalog with confidence scores |
| `tor_exit_nodes.txt` | Plain text (one IP per line) | Tor exit node correlation |
| `sinkholed_ips.txt` | Plain text (IP or CIDR per line) | Sinkholed IP addresses and networks |
| `sinkholed_domains.txt` | Plain text (one domain per line) | Sinkholed domain names |
| `dyndns_domains.txt` | Plain text (suffix per line) | Dynamic DNS providers abused for C2 |
| `suspicious_tlds.txt` | Plain text (TLD per line) | High-abuse top-level domains |
| `custom_blacklist.txt` | Plain text (IP or CIDR per line) | Operator-defined block list |

Lines starting with `#` are ignored.

## suspicious_ports.csv Schema

```csv
port,label,category,confidence,description
4444,Metasploit Handler,C2,high,Default reverse shell listener
```

- **confidence**: `high`, `medium`, `low`, or `info`
- **category**: Used for MITRE ATT&CK mapping (`C2`, `malware`, `RAT`, `miner`, `anonymity`)

## Custom Blacklist

Copy `custom_blacklist.example.txt` to `custom_blacklist.txt` and add your own IPv4/IPv6 addresses or CIDR ranges.

## Reloading Feeds

Feeds can be reloaded without restarting TCPspecter:

- **Web UI**: Threat Intelligence view → **Reload Feeds**
- **API**: `POST /api/intelligence/reload` (requires CSRF token)

## Configuration

In `config.json`:

```json
{
  "INTELLIGENCE_ENABLED": true,
  "INTELLIGENCE_FEED_DIR": "data/feeds"
}
```
