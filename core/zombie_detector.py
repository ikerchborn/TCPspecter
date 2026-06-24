import os
import stat
import psutil
import socket
import re
import time
import threading
import math
from collections import defaultdict, deque

# Global setting to toggle advanced security heuristics
ADVANCED_SECURITY_ENABLED = True

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Technique Mapping
# Reference: https://attack.mitre.org/
# ─────────────────────────────────────────────────────────────────────────────
MITRE_MAP = {
    "Deleted Binary":         {"id": "T1070.004", "name": "File Deletion",                     "tactic": "Defense Evasion"},
    "Suspicious Path":        {"id": "T1059",     "name": "Command and Scripting Interpreter",  "tactic": "Execution"},
    "SUID with Network":      {"id": "T1548.001", "name": "Setuid and Setgid",                  "tactic": "Privilege Escalation"},
    "Shell Signature":        {"id": "T1059.004", "name": "Unix Shell",                         "tactic": "Execution"},
    "Shell with Connection":  {"id": "T1059.004", "name": "Unix Shell",                         "tactic": "Execution"},
    "Process Masquerading":   {"id": "T1036.005", "name": "Match Legitimate Name or Location",  "tactic": "Defense Evasion"},
    "Orphan C2 Agent":        {"id": "T1543",     "name": "Create or Modify System Process",    "tactic": "Persistence"},
    "Atypical SSL Traffic":   {"id": "T1071.001", "name": "Web Protocols (C2 over HTTPS)",      "tactic": "Command and Control"},
    "Suspicious C2 Port":     {"id": "T1071",     "name": "Application Layer Protocol",         "tactic": "Command and Control"},
    "Open Listener":          {"id": "T1049",     "name": "System Network Connections Discovery","tactic": "Discovery"},
    "Mass Connections":       {"id": "T1046",     "name": "Network Service Discovery",          "tactic": "Discovery"},
    "C2 Beaconing":           {"id": "T1071.001", "name": "Web Protocols (Beaconing)",          "tactic": "Command and Control"},
    "System Persistence":     {"id": "T1053",     "name": "Scheduled Task/Job",                 "tactic": "Persistence"},
    "Regular C2 Connection":  {"id": "T1571",     "name": "Non-Standard Port",                  "tactic": "Command and Control"},
    "IDS/Sniffer":            {"id": "T1040",     "name": "Network Sniffing",                   "tactic": "Discovery"},
    "Fileless Memory":        {"id": "T1055",     "name": "Process Injection",                  "tactic": "Defense Evasion"},
}

NIST_MAP = {
    "Deleted Binary":         ("DE.CM-1",),
    "Suspicious Path":        ("DE.CM-1",),
    "SUID with Network":      ("PR.AC-4",),
    "Shell Signature":        ("DE.AE-2",),
    "Shell with Connection":  ("DE.AE-2",),
    "Process Masquerading":   ("DE.CM-1",),
    "Orphan C2 Agent":        ("DE.CM-1",),
    "Atypical SSL Traffic":   ("DE.AE-2",),
    "Suspicious C2 Port":     ("DE.AE-2",),
    "Open Listener":          ("DE.CM-1",),
    "Mass Connections":       ("DE.AE-2",),
    "C2 Beaconing":           ("DE.AE-2",),
    "System Persistence":     ("DE.CM-1",),
    "Regular C2 Connection":  ("DE.AE-2",),
    "Fileless Memory":        ("DE.CM-7",),
}

ISO_MAP = {
    "Deleted Binary":         ("A.12.4.1",),
    "Suspicious Path":        ("A.12.4.1",),
    "SUID with Network":      ("A.9.2.3",),
    "Shell Signature":        ("A.12.4.1",),
    "Shell with Connection":  ("A.12.4.1",),
    "Process Masquerading":   ("A.12.4.1",),
    "Orphan C2 Agent":        ("A.12.4.1",),
    "Atypical SSL Traffic":   ("A.13.1.1",),
    "Suspicious C2 Port":     ("A.13.1.1",),
    "Open Listener":          ("A.12.4.1",),
    "Mass Connections":       ("A.13.1.1",),
    "C2 Beaconing":           ("A.13.1.1",),
    "System Persistence":     ("A.12.4.1",),
    "Regular C2 Connection":  ("A.13.1.1",),
    "Fileless Memory":        ("A.12.6.1",),
}

# Ports commonly used by known C2 servers, botnets, shells, and miners
C2_PORTS = {
    6667, 6668, 6669, 7000,   # IRC Botnets
    9001, 9050, 9051,         # Tor / Proxy
    4444, 4445, 5555, 8888,   # Metasploit, Netcat, reverse shells
    3333, 14444, 18080,       # Cryptominers (Stratum)
    5900, 5938                # VNC / RATs / AnyDesk
}

WHITELISTED_MASS_CONN_PROCS = {
    "firefox", "firefox-esr", "firefox-bin", "chrome", "google-chrome", "chrome-sandbox", "brave", "brave-browser", 
    "chromium", "chromium-browser", "opera", "safari", "msedge", "microsoft-edge", "vivaldi",
    "slack", "discord", "spotify", "thunderbird", "steam", "dropbox",
    "teams", "zoom", "vscode", "code", "curl", "wget", "git", "npm", 
    "pip", "docker", "rustc", "cargo", "go", "gopls", "rust-analyzer",
    "language_server", "language-server", "pyright", "tsserver", "node", "nodejs",
    "cursor", "electron", "python", "python3", "uvicorn", "gunicorn", "tcpspecter",
}

# Prefix match for process names like "Cursor Helper" or "python3.11"
TRUSTED_NETWORK_PROC_PREFIXES = (
    "cursor", "electron", "firefox", "chrome", "chromium", "microsoft-edge",
    "msedge", "brave", "python", "node", "code", "vscode", "uvicorn",
)

def _is_trusted_network_proc(proc_name: str) -> bool:
    """Return True for browsers, IDEs, and other legitimately multi-connection apps."""
    name = (proc_name or "").lower().strip()
    if not name:
        return False
    if name in WHITELISTED_MASS_CONN_PROCS:
        return True
    return any(name.startswith(prefix) for prefix in TRUSTED_NETWORK_PROC_PREFIXES)

# SUID binaries that are known to be safe or standard network/system tools
TRUSTED_SUID_BINARIES = {
    "/usr/bin/ping", "/usr/bin/sudo", "/usr/bin/ping6", "/sbin/ping",
    "/usr/sbin/traceroute", "/usr/bin/traceroute", "/usr/bin/chfn",
    "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/passwd"
}

SUSPICIOUS_PATHS = [
    "/tmp", "/var/tmp", "/dev/shm", "/run/user"
]

SUSPICIOUS_CMD_PATTERNS = [
    r"\bbash\s+-i",
    r"\bsh\s+-i",
    r"\bnc\s+-[^\s]*e",
    r"\bncat\s+-[^\s]*e",
    r"\bsocat\s+",
    r"python.*import\s+pty",
    r"python.*pty\.spawn",
    r"/dev/tcp/",
    r"/dev/udp/"
]

# ─────────────────────────────────────────────────────────────────────────────
# C2 Beaconing Behavioral Tracker
# Monitors repeated connections from a PID to the same IP to detect beaconing
# ─────────────────────────────────────────────────────────────────────────────
_beacon_tracker = defaultdict(lambda: deque(maxlen=50))  # pid -> deque of (timestamp, ip)
_beacon_lock = threading.Lock()
_BEACON_WINDOW_SECS = 120  # 2-minute rolling window
_BEACON_MIN_COUNT = 6      # Minimum connections required before calling it beaconing
_BEACON_JITTER_THRESHOLD = 0.20  # CoV < 20% = highly regular = suspicious

def _record_beacon_sample(pid: int, ip: str):
    """Records a connection timestamp for a given PID for beaconing detection."""
    now = time.time()
    with _beacon_lock:
        if len(_beacon_tracker) > 500:
            stale_pids = []
            for p, q in _beacon_tracker.items():
                if not q or now - q[-1][0] > 300:  # 5 mins stale
                    if not psutil.pid_exists(p):
                        stale_pids.append(p)
            for p in stale_pids:
                if p != pid:
                    del _beacon_tracker[p]

        _beacon_tracker[pid].append((now, ip))

def _analyze_beaconing(pid: int) -> tuple[bool, float, str]:
    """
    Analyzes if a PID exhibits beaconing behavior by evaluating regularity of
    connections via Coefficient of Variation (CoV) of inter-connection intervals.
    
    Returns: (is_beaconing, regularity_score, primary_target_ip)
    """
    with _beacon_lock:
        samples = list(_beacon_tracker.get(pid, []))

    now = time.time()
    # Filter to rolling window and extract timestamps
    recent = [(ts, ip) for ts, ip in samples if now - ts < _BEACON_WINDOW_SECS]

    if len(recent) < _BEACON_MIN_COUNT:
        return False, 0.0, ""

    # Group by target IP (pick the most frequent)
    ip_counts = defaultdict(int)
    for _, ip in recent:
        ip_counts[ip] += 1
    primary_ip = max(ip_counts, key=ip_counts.get)

    # Get timestamps for the primary IP
    ts_list = sorted(ts for ts, ip in recent if ip == primary_ip)
    if len(ts_list) < _BEACON_MIN_COUNT:
        return False, 0.0, ""

    # Calculate inter-arrival intervals
    intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
    if not intervals:
        return False, 0.0, ""

    mean_interval = sum(intervals) / len(intervals)
    if mean_interval < 0.5:
        return False, 0.0, ""  # Too fast to be beaconing (likely normal burst)

    # Compute CoV (Coefficient of Variation): stdev / mean
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    stdev = math.sqrt(variance)
    cov = stdev / mean_interval if mean_interval > 0 else 1.0

    # Low CoV (regular intervals) = classic beaconing behavior
    is_beaconing = cov < _BEACON_JITTER_THRESHOLD
    regularity_score = round(1.0 - min(cov, 1.0), 2)  # 1.0 = perfectly regular
    return is_beaconing, regularity_score, primary_ip


def is_private_ip(ip: str) -> bool:
    """
    Checks if an IP is a local, private, or loopback address.
    """
    if not ip or ip in ("-", "*", "0.0.0.0", "::"):
        return True
    
    # Loopback
    if ip.startswith("127.") or ip == "::1":
        return True
        
    # Private ranges
    # Class A: 10.0.0.0/8
    if ip.startswith("10."):
        return True
    # Class B: 172.16.0.0/12
    if ip.startswith("172."):
        try:
            parts = ip.split('.')
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return True
        except Exception:
            pass
    # Class C: 192.168.0.0/16
    if ip.startswith("192.168."):
        return True
        
    # Link-local: 169.254.0.0/16
    if ip.startswith("169.254."):
        return True
        
    # Multicast / Broadcast
    if ip.startswith("224.") or ip.startswith("255."):
        return True

    return False


def scan_anonymous_memory(pid: int) -> int:
    """
    Escanea /proc/{pid}/maps buscando regiones de memoria que estén marcadas como ejecutables
    (r-xp o rwxp) pero que no estén respaldadas por un archivo en disco (memoria anónima).
    """
    anon_exec_regions = 0
    maps_path = f"/proc/{pid}/maps"
    if os.path.exists(maps_path):
        try:
            with open(maps_path, "r", errors="replace") as maps_f:
                for line in maps_f:
                    parts = line.strip().split(None, 5)
                    if len(parts) >= 5:
                        perms = parts[1]
                        if 'x' in perms and 'r' in perms:
                            path = parts[5].strip() if len(parts) >= 6 else ""
                            # Path vacío o explícitamente [anon]
                            if not path or "[anon]" in path:
                                anon_exec_regions += 1
        except Exception:
            pass
    return anon_exec_regions


def _enrich_finding(finding: dict) -> dict:
    """
    Enriches a raw finding dict with MITRE ATT&CK tagging and compliance mapping.
    """
    category = finding.get("category", "")
    mitre = MITRE_MAP.get(category)
    if mitre:
        finding["mitre_technique_id"] = mitre["id"]
        finding["mitre_technique_name"] = mitre["name"]
        finding["mitre_tactic"] = mitre["tactic"]
    else:
        finding["mitre_technique_id"] = None
        finding["mitre_technique_name"] = None
        finding["mitre_tactic"] = None

    finding["nist_controls"] = NIST_MAP.get(category, ())
    finding["iso_controls"] = ISO_MAP.get(category, ())
    return finding


_last_report = None
_last_analysis_time = 0.0
_analysis_lock = threading.Lock()

def analyze_zombie_status(force=False) -> dict:
    """
    Scans the system's processes and active connections to detect potential 
    zombie machine / botnet / C2 behaviors.
    
    Returns a dictionary report containing:
      - score: risk score (0 to 100)
      - risk_level: string ("Bajo", "Medio", "Alto", "Crítico")
      - findings: list of enriched finding dicts with MITRE ATT&CK tags
      - scanned_processes: count of successfully scanned processes
      - scanned_connections: count of scanned connections
    """
    global _last_report, _last_analysis_time
    
    if not ADVANCED_SECURITY_ENABLED:
        return {
            "score": 0,
            "risk_level": "DESACTIVADO",
            "findings": [],
            "scanned_processes": 0,
            "scanned_connections": 0
        }
        
    with _analysis_lock:
        now = time.time()
        if not force and _last_report is not None and (now - _last_analysis_time) < 4.0:
            return _last_report

    findings = []
    scanned_procs = 0
    scanned_conns = 0
    
    # Group connections by PID to analyze per-process network footprints
    pid_connections = {}
    try:
        # Get all system-wide connections
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            scanned_conns += 1
            if conn.pid:
                pid_connections.setdefault(conn.pid, []).append(conn)
    except psutil.AccessDenied:
        findings.append(_enrich_finding({
            "category": "Permisos",
            "severity": "WARNING",
            "description": "Sin acceso a todas las conexiones del sistema. Ejecute como root (sudo) para un escaneo completo.",
            "pid": None,
            "proc_name": None
        }))
    except Exception as e:
        findings.append(_enrich_finding({
            "category": "Error",
            "severity": "WARNING",
            "description": f"Error al escanear conexiones de red: {str(e)}",
            "pid": None,
            "proc_name": None
        }))

    # Iterate through all running processes
    for proc in psutil.process_iter():
        try:
            pid = proc.pid
            
            # Skip kernel processes and idle process
            if pid == 0:
                continue
                
            proc_name = proc.name()
            username = proc.username()
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list)
            
            scanned_procs += 1
            conns = pid_connections.get(pid, [])
            
            # --- 1. Check for Deleted Binary ---
            exe_path = ""
            try:
                exe_path = proc.exe()
                if exe_path and "(deleted)" in exe_path:
                    findings.append(_enrich_finding({
                        "category": "Deleted Binary",
                        "severity": "CRITICAL",
                        "description": f"Proceso ejecutándose desde un archivo binario eliminado en disco.",
                        "pid": pid,
                        "proc_name": proc_name
                    }))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # --- 2. Check for Executable in Suspicious Paths ---
            if exe_path:
                for path in SUSPICIOUS_PATHS:
                    if exe_path.startswith(path):
                        findings.append(_enrich_finding({
                            "category": "Suspicious Path",
                            "severity": "HIGH",
                            "description": f"Ejecutable ubicado en directorio temporal/volátil: {exe_path}",
                            "pid": pid,
                            "proc_name": proc_name
                        }))
                        break

            # --- 3. Check SUID/SGID Privilege with Network Connections ---
            if exe_path and conns:
                try:
                    st = os.stat(exe_path)
                    # Check SUID or SGID bits
                    is_suid = bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))
                    if is_suid and exe_path not in TRUSTED_SUID_BINARIES:
                        findings.append(_enrich_finding({
                            "category": "SUID with Network",
                            "severity": "HIGH",
                            "description": f"Binario con bit SUID/SGID activo tiene conexiones de red abiertas ({exe_path})",
                            "pid": pid,
                            "proc_name": proc_name
                        }))
                except Exception:
                    pass
            # --- 3b. Check for Fileless Malware (Anonymous Executable Memory) ---
            try:
                JIT_RUNTIMES = {
                    "python", "python3", "python3.11", "python3.12", "python3.13",
                    "node", "nodejs", "java", "code", "electron", "slack", "teams", "discord", "spotify", "steam",
                    "firefox", "firefox-esr", "firefox-bin", "chrome", "google-chrome", "chrome-sandbox", 
                    "chromium", "chromium-browser", "brave", "brave-browser", "msedge", "microsoft-edge",
                    "opera", "vivaldi"
                }
                if proc_name.lower() not in JIT_RUNTIMES:
                    anon_exec_regions = scan_anonymous_memory(pid)
                    
                    if anon_exec_regions > 0:
                        # Real fileless malware has active connections or runs from temp directories
                        is_suspicious_process = False
                        
                        # Has active external connections
                        if conns:
                            has_external_conn = any(not is_private_ip(conn.raddr.ip) for conn in conns if conn.status == "ESTABLISHED" and conn.raddr)
                            if has_external_conn:
                                is_suspicious_process = True
                                
                        if exe_path:
                            for spath in SUSPICIOUS_PATHS:
                                if exe_path.startswith(spath):
                                    is_suspicious_process = True
                        
                        # Command shells should never run JIT code
                        SHELL_NAMES = {"bash", "sh", "zsh", "dash", "ash"}
                        if proc_name.lower() in SHELL_NAMES:
                            is_suspicious_process = True

                        if is_suspicious_process:
                            findings.append(_enrich_finding({
                                "category": "Fileless Memory",
                                "severity": "HIGH",
                                "description": f"Se detectaron {anon_exec_regions} regiones de memoria ejecutable anónima (sin respaldo en disco). Posible inyección de shellcode / malware fileless con red activa.",
                                "pid": pid,
                                "proc_name": proc_name
                            }))
            except Exception:
                pass

            # --- 4. Process Tree Lineage & Scoring Matrix ---
            # Instead of binary triggers, accumulate a risk score for the process
            proc_risk_score = 0
            proc_findings = []
            
            # Helper to get parent process name safely
            parent_name = "unknown"
            try:
                parent = psutil.Process(proc.info['ppid'])
                parent_name = parent.name().lower()
            except Exception:
                pass

            if cmdline:
                for pattern in SUSPICIOUS_CMD_PATTERNS:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        proc_risk_score += 40
                        proc_findings.append(f"Firma de Shell en comando: {cmdline[:60]}")
                        break

            SHELL_NAMES = {"bash", "sh", "zsh", "dash", "ash", "python", "python3", "perl", "php", "ruby"}
            if proc_name.lower() in SHELL_NAMES and conns:
                has_external_established = any(
                    conn.status == "ESTABLISHED" and conn.raddr and not is_private_ip(conn.raddr.ip)
                    for conn in conns
                )
                if has_external_established:
                    if proc_name.lower() not in {"python", "python3", "node"}:
                        proc_risk_score += 30
                        proc_findings.append(f"Intérprete ({proc_name}) con red ext activa")
                    
                    # Contextual Lineage Validation (The core of Enterprise False Positive Reduction)
                    LEGITIMATE_PARENTS = {"sshd", "gnome-terminal-server", "konsole", "tmux", "screen", "systemd"}
                    SUSPICIOUS_PARENTS = {"apache2", "nginx", "httpd", "php-fpm", "java", "mysql", "postgres"}
                    
                    if parent_name in SUSPICIOUS_PARENTS:
                        proc_risk_score += 60 # Critical indicator of a web shell or RCE
                        proc_findings.append(f"Anomalía de Linaje: Padre web/BD ({parent_name}) lanzó Shell ({proc_name})")
                    elif parent_name in LEGITIMATE_PARENTS:
                        proc_risk_score -= 50 # Strongly benign (e.g., standard SSH session)

            if proc_risk_score >= 60:
                findings.append(_enrich_finding({
                    "category": "Shell with Connection" if "Linaje" in "".join(proc_findings) else "Firma de Shell",
                    "severity": "CRITICAL" if proc_risk_score >= 80 else "HIGH",
                    "description": " | ".join(proc_findings) + f" (Score: {proc_risk_score})",
                    "pid": pid,
                    "proc_name": proc_name
                }))

            # --- 4c. Process Masquerading / Kernel Thread Spoofing ---
            is_spoofing = False
            if (proc_name.startswith("[") and proc_name.endswith("]")) or "kworker" in proc_name or "khelper" in proc_name:
                try:
                    exe = proc.exe()
                    if exe:  # Real executable file exists on disk
                        is_spoofing = True
                except Exception:
                    pass
            if is_spoofing:
                findings.append(_enrich_finding({
                    "category": "Process Masquerading",
                    "severity": "CRITICAL",
                    "description": f"Proceso malicioso camuflado como hilo del kernel: {proc_name} (Ruta: {exe_path})",
                    "pid": pid,
                    "proc_name": proc_name
                }))

            # --- 4d. Orphan Process C2 Agent ---
            try:
                ppid = proc.ppid()
                if ppid == 1 and conns:
                    if exe_path and (exe_path.startswith("/home") or any(p in exe_path for p in SUSPICIOUS_PATHS)):
                        has_outbound = any(
                            conn.status == "ESTABLISHED" and conn.raddr and not is_private_ip(conn.raddr.ip)
                            for conn in conns
                        )
                        if has_outbound:
                            findings.append(_enrich_finding({
                                "category": "Orphan C2 Agent",
                                "severity": "HIGH",
                                "description": f"Proceso huérfano (PPID 1) no-sistema en {exe_path} con tráfico de red público.",
                                "pid": pid,
                                "proc_name": proc_name
                            }))
            except Exception:
                pass

            # --- 4e. Atypical SSL Connection (Port 443 Spoofing) ---
            if conns and not _is_trusted_network_proc(proc_name):
                for conn in conns:
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        rip = conn.raddr.ip
                        rport = conn.raddr.port
                        if rport == 443 and not is_private_ip(rip):
                            findings.append(_enrich_finding({
                                "category": "Atypical SSL Traffic",
                                "severity": "HIGH",
                                "description": f"Proceso desconocido ({proc_name}) usando puerto HTTPS (443) hacia {rip} (posible C2 beaconing).",
                                "pid": pid,
                                "proc_name": proc_name
                            }))
                            break

            # --- 5. Analyze Connections of the Process ---
            outbound_ips = set()
            for conn in conns:
                # Check for C2 Ports
                raddr = conn.raddr
                if raddr:
                    rip = raddr.ip
                    rport = raddr.port
                    
                    # Track external outbound destinations
                    if not is_private_ip(rip) and conn.status == "ESTABLISHED":
                        outbound_ips.add(rip)
                        # Record sample for beaconing analysis
                        _record_beacon_sample(pid, rip)
                    
                    if rport in C2_PORTS and not is_private_ip(rip):
                        findings.append(_enrich_finding({
                            "category": "Suspicious C2 Port",
                            "severity": "CRITICAL",
                            "description": f"Conectado a puerto sospechoso/C2 ({rport}) en IP externa {rip}",
                            "pid": pid,
                            "proc_name": proc_name
                        }))
                
                # Check for suspicious listening on all interfaces
                if conn.status == "LISTEN" and conn.laddr:
                    lip = conn.laddr.ip
                    lport = conn.laddr.port
                    if lip in ("0.0.0.0", "::"):
                        # Exclude standard/well-known local listening services
                        is_trusted = False
                        if lport in (22, 80, 443, 631):
                            is_trusted = True
                        elif proc_name in ("sshd", "nginx", "apache2", "lighttpd", "systemd-resolved"):
                            is_trusted = True
                            
                        if not is_trusted:
                            findings.append(_enrich_finding({
                                "category": "Open Listener",
                                "severity": "MEDIUM",
                                "description": f"Proceso no estándar escuchando en puerto {lport} en todas las interfaces",
                                "pid": pid,
                                "proc_name": proc_name
                            }))

            # --- 6. Check for Mass Scanning or Spamming (Outbound Scaling) ---
            if len(outbound_ips) >= 8 and not _is_trusted_network_proc(proc_name):
                sev = "CRITICAL" if len(outbound_ips) >= 10 else "HIGH"
                findings.append(_enrich_finding({
                    "category": "Mass Connections",
                    "severity": sev,
                    "description": f"Estableció conexiones simultáneas a {len(outbound_ips)} IPs públicas distintas (posible DDoS o escaneo)",
                    "pid": pid,
                    "proc_name": proc_name
                }))

            # --- 7. C2 Beaconing Detection (Behavioral Multi-Signal Analysis) ---
            if not _is_trusted_network_proc(proc_name):
                is_beaconing, regularity, target_ip = _analyze_beaconing(pid)
                if is_beaconing and target_ip:
                    findings.append(_enrich_finding({
                        "category": "C2 Beaconing",
                        "severity": "CRITICAL",
                        "description": (
                            f"Comportamiento de beaconing C2 detectado: {proc_name} conectándose regularmente a "
                            f"{target_ip} (regularidad: {regularity:.0%}, ventana: {_BEACON_WINDOW_SECS}s). "
                            f"Indica posible malware verificando estado con servidor C2."
                        ),
                        "pid": pid,
                        "proc_name": proc_name
                    }))

            # --- 8. System Persistence Check (Cron + Systemd) ---
            # Check if process has a corresponding cron entry or systemd service that was recently created
            if exe_path and (exe_path.startswith("/home") or any(p in exe_path for p in SUSPICIOUS_PATHS)):
                # Persistence indicator: orphan with a user cron entry
                try:
                    cron_out = ""
                    try:
                        import subprocess
                        r = subprocess.run(
                            ["crontab", "-l", "-u", username], 
                            capture_output=True, text=True, timeout=1.5
                        )
                        cron_out = r.stdout
                    except Exception:
                        pass
                    
                    # Check if the process binary appears in cron
                    if exe_path in cron_out or (proc_name and proc_name in cron_out):
                        findings.append(_enrich_finding({
                            "category": "System Persistence",
                            "severity": "HIGH",
                            "description": (
                                f"Proceso sospechoso '{proc_name}' en ruta {exe_path} encontrado en las "
                                f"tareas programadas (crontab) del usuario '{username}'. Indica persistencia."
                            ),
                            "pid": pid,
                            "proc_name": proc_name
                        }))
                except Exception:
                    pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    # Calculate overall risk score
    # CRITICAL finding = 40 points
    # HIGH finding = 25 points
    # MEDIUM finding = 10 points
    # WARNING/LOW = 5 points
    score = 0
    for f in findings:
        sev = f["severity"]
        if sev == "CRITICAL":
            score += 40
        elif sev == "HIGH":
            score += 25
        elif sev == "MEDIUM":
            score += 10
        elif sev == "WARNING":
            score += 5
            
    # Bound score at 100
    score = min(100, score)
    
    # Determine risk level name
    if score >= 60:
        risk_level = "CRÍTICO"
    elif score >= 35:
        risk_level = "ALTO"
    elif score >= 15:
        risk_level = "MEDIO"
    else:
        risk_level = "BAJO"
        
    report = {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "scanned_processes": scanned_procs,
        "scanned_connections": scanned_conns
    }
    with _analysis_lock:
        _last_report = report
        _last_analysis_time = time.time()
        
    return report
