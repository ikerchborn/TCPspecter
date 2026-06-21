import os
import subprocess
import re
import ipaddress

# ─────────────────────────────────────────────────────────────────────────────
# Input Validation & Sanitization
# CRITICAL: Prevents shell injection via malformed IP strings
# ─────────────────────────────────────────────────────────────────────────────

_IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/(?:3[0-2]|[12]?\d))?$'
)

def validate_ip(ip: str) -> str | None:
    """
    Validates that an IP string is a legitimate IPv4 address or CIDR block.
    Returns the normalized IP string, or None if invalid.
    """
    if not ip or not isinstance(ip, str):
        return None
    
    ip = ip.strip()
    
    BLOCKED = {"0.0.0.0", "127.0.0.1", "::1", "255.255.255.255", ""}
    if ip in BLOCKED:
        return None
    
    if not _IP_PATTERN.match(ip):
        return None
    
    try:
        parsed = ipaddress.ip_network(ip, strict=False)
        if parsed.is_loopback or parsed.is_link_local:
            return None
        return str(parsed.network_address) if '/' not in ip else str(parsed)
    except ValueError:
        return None


def detect_backend() -> str:
    """
    Detects which firewall backend is active and available.
    Returns: "ufw", "iptables", or "none"
    """
    try:
        ufw_path = "/usr/sbin/ufw"
        if os.path.exists(ufw_path):
            res = subprocess.run([ufw_path, "status"], capture_output=True, text=True, timeout=2.0)
            if "Status: active" in res.stdout:
                return "ufw"
    except Exception:
        pass

    for ipt_path in ["/sbin/iptables", "/usr/sbin/iptables", "iptables"]:
        try:
            res = subprocess.run([ipt_path, "-V"], capture_output=True, text=True, timeout=2.0)
            if "iptables" in res.stdout:
                return "iptables"
        except Exception:
            pass

    return "none"


def block_ip(ip: str) -> bool:
    safe_ip = validate_ip(ip)
    if not safe_ip:
        return False
        
    backend = detect_backend()
    try:
        if backend == "ufw":
            subprocess.run(
                ["/usr/sbin/ufw", "insert", "1", "deny", "from", safe_ip, "to", "any"],
                check=True, timeout=5.0, capture_output=True
            )
            return True
        elif backend == "iptables":
            if is_ip_blocked_iptables(safe_ip):
                return True
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", safe_ip, "-j", "DROP"],
                check=True, timeout=5.0, capture_output=True
            )
            return True
    except Exception:
        pass
    return False


def unblock_ip(ip: str) -> bool:
    safe_ip = validate_ip(ip)
    if not safe_ip:
        return False
        
    backend = detect_backend()
    try:
        if backend == "ufw":
            subprocess.run(
                ["/usr/sbin/ufw", "delete", "deny", "from", safe_ip],
                check=True, timeout=5.0, capture_output=True
            )
            return True
        elif backend == "iptables":
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", safe_ip, "-j", "DROP"],
                check=True, timeout=5.0, capture_output=True
            )
            return True
    except Exception:
        pass
    return False


def is_ip_blocked_iptables(ip: str) -> bool:
    safe_ip = validate_ip(ip)
    if not safe_ip:
        return False
    try:
        res = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=3.0)
        for line in res.stdout.splitlines():
            if "DROP" in line and safe_ip in line:
                return True
    except Exception:
        pass
    return False


def get_blocked_ips() -> list[dict]:
    blocked_list = []
    backend = detect_backend()

    if backend == "ufw":
        try:
            res = subprocess.run(["/usr/sbin/ufw", "status"], capture_output=True, text=True, timeout=3.0)
            for line in res.stdout.splitlines():
                if "DENY" in line or "Deny" in line:
                    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b', line)
                    if match:
                        candidate = match.group(0)
                        safe = validate_ip(candidate)
                        if safe and safe not in [b["ip"] for b in blocked_list]:
                            blocked_list.append({"ip": safe, "backend": "ufw", "target": "INPUT"})
        except Exception:
            pass

    elif backend == "iptables":
        try:
            res = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=3.0)
            for line in res.stdout.splitlines():
                if line.strip().startswith("DROP"):
                    parts = line.split()
                    if len(parts) >= 4:
                        ip_candidate = parts[3]
                        safe = validate_ip(ip_candidate.split('/')[0])
                        if safe and safe != "0.0.0.0":
                            blocked_list.append({"ip": safe, "backend": "iptables", "target": "INPUT"})
        except Exception:
            pass

    return blocked_list


def get_active_rules() -> list[dict]:
    return get_blocked_ips()


def add_custom_rule(action: str, src_ip: str, dst_ip: str, port: int, protocol: str) -> bool:
    """
    Creates a granular firewall rule mapping inputs safely to iptables.
    """
    action = str(action).upper()
    protocol = str(protocol).lower()
    
    if action not in ("ACCEPT", "DROP", "REJECT", "ALLOW", "DENY"):
        return False
    
    # Map ALLOW/DENY to iptables equivalent ACCEPT/DROP
    if action == "ALLOW": action = "ACCEPT"
    if action == "DENY": action = "DROP"
        
    if protocol not in ("tcp", "udp", "all", "icmp"):
        return False
        
    safe_src = validate_ip(src_ip) if src_ip and src_ip.strip() else None
    safe_dst = validate_ip(dst_ip) if dst_ip and dst_ip.strip() else None
    
    port_num = None
    if port:
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                port_num = None
        except (ValueError, TypeError):
            pass

    backend = detect_backend()
    if backend != "iptables":
        # Can be adapted for UFW if needed
        return False

    cmd = ["iptables", "-A", "INPUT"]
    
    if protocol != "all":
        cmd.extend(["-p", protocol])
        
    if safe_src:
        cmd.extend(["-s", safe_src])
        
    if safe_dst:
        cmd.extend(["-d", safe_dst])
        
    if port_num is not None and protocol in ("tcp", "udp"):
        cmd.extend(["--dport", str(port_num)])
        
    cmd.extend(["-j", action])

    try:
        subprocess.run(cmd, check=True, timeout=5.0, capture_output=True)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Advanced Enterprise SOAR Containment & Deception (Tarpitting)
# ─────────────────────────────────────────────────────────────────────────────

def quarantine_host(admin_ips: list[str]) -> bool:
    """
    Isolates the host using iptables custom chains.
    Only connections to loopback and admin IPs are allowed.
    All other traffic is blocked.
    """
    backend = detect_backend()
    if backend != "iptables":
        return False

    try:
        # 1. Clean existing quarantine rules first if any
        remove_quarantine()

        # 2. Create custom chains
        subprocess.run(["iptables", "-N", "TCPSPECTER-Q-IN"], check=True, capture_output=True)
        subprocess.run(["iptables", "-N", "TCPSPECTER-Q-OUT"], check=True, capture_output=True)

        # 3. Populate Ingress Quarantine Chain
        subprocess.run(["iptables", "-A", "TCPSPECTER-Q-IN", "-i", "lo", "-j", "ACCEPT"], check=True)
        for admin_ip in admin_ips:
            safe = validate_ip(admin_ip)
            if safe:
                subprocess.run(["iptables", "-A", "TCPSPECTER-Q-IN", "-s", safe, "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "TCPSPECTER-Q-IN", "-j", "DROP"], check=True)

        # 4. Populate Egress Quarantine Chain
        subprocess.run(["iptables", "-A", "TCPSPECTER-Q-OUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        for admin_ip in admin_ips:
            safe = validate_ip(admin_ip)
            if safe:
                subprocess.run(["iptables", "-A", "TCPSPECTER-Q-OUT", "-d", safe, "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "TCPSPECTER-Q-OUT", "-j", "DROP"], check=True)

        # 5. Inject jumps at the top of INPUT and OUTPUT chains
        subprocess.run(["iptables", "-I", "INPUT", "1", "-j", "TCPSPECTER-Q-IN"], check=True)
        subprocess.run(["iptables", "-I", "OUTPUT", "1", "-j", "TCPSPECTER-Q-OUT"], check=True)
        return True
    except Exception:
        return False


def remove_quarantine() -> bool:
    """
    Removes active quarantine isolation chains and rules.
    """
    backend = detect_backend()
    if backend != "iptables":
        return False

    try:
        # Remove jump rules
        subprocess.run(["iptables", "-D", "INPUT", "-j", "TCPSPECTER-Q-IN"], capture_output=True)
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "TCPSPECTER-Q-OUT"], capture_output=True)

        # Flush custom chains
        subprocess.run(["iptables", "-F", "TCPSPECTER-Q-IN"], capture_output=True)
        subprocess.run(["iptables", "-F", "TCPSPECTER-Q-OUT"], capture_output=True)

        # Delete custom chains
        subprocess.run(["iptables", "-X", "TCPSPECTER-Q-IN"], capture_output=True)
        subprocess.run(["iptables", "-X", "TCPSPECTER-Q-OUT"], capture_output=True)
        return True
    except Exception:
        return False


def is_quarantined() -> bool:
    """
    Checks if quarantine is active.
    """
    try:
        res = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=2.0)
        return "TCPSPECTER-Q-IN" in res.stdout
    except Exception:
        return False


def enable_tarpit(attacker_ip: str, tarpit_port: int = 8000) -> bool:
    """
    Redirects TCP traffic from an attacking IP to a local Tarpit server.
    """
    safe_ip = validate_ip(attacker_ip)
    if not safe_ip:
        return False

    backend = detect_backend()
    if backend != "iptables":
        return False

    try:
        # Redirect SYN connection attempts to our Tarpit port
        subprocess.run(
            ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", safe_ip, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", str(tarpit_port)],
            check=True, timeout=5.0, capture_output=True
        )
        return True
    except Exception:
        return False


def disable_tarpit(attacker_ip: str, tarpit_port: int = 8000) -> bool:
    """
    Removes redirection rules for the Tarpit.
    """
    safe_ip = validate_ip(attacker_ip)
    if not safe_ip:
        return False

    backend = detect_backend()
    if backend != "iptables":
        return False

    try:
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-s", safe_ip, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", str(tarpit_port)],
            check=True, timeout=5.0, capture_output=True
        )
        return True
    except Exception:
        return False
