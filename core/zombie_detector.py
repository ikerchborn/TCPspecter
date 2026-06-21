import os
import stat
import psutil
import socket
import re

# Ports commonly used by known C2 servers, botnets, shells, and miners
C2_PORTS = {
    6667, 6668, 6669, 7000,   # IRC Botnets
    9001, 9050, 9051,         # Tor / Proxy
    4444, 4445, 5555, 8888,   # Metasploit, Netcat, reverse shells
    3333, 14444, 18080,       # Cryptominers (Stratum)
    5900, 5938                # VNC / RATs / AnyDesk
}

# Processes that naturally establish many outbound connections and should not trigger mass connection warnings
WHITELISTED_MASS_CONN_PROCS = {
    "firefox", "chrome", "brave", "chromium", "opera", "safari", 
    "slack", "discord", "spotify", "thunderbird", "steam", "dropbox",
    "teams", "zoom", "vscode", "code", "curl", "wget", "git", "npm", 
    "pip", "docker", "rustc", "cargo", "curl", "wget"
}

SUSPICIOUS_PATHS = [
    "/tmp", "/var/tmp", "/dev/shm", "/run/user"
]

SUSPICIOUS_CMD_PATTERNS = [
    r"bash\s+-i",
    r"sh\s+-i",
    r"nc\s+-[^\s]*e",
    r"ncat\s+-[^\s]*e",
    r"socat\s+",
    r"python.*import\s+pty",
    r"python.*pty\.spawn",
    r"/dev/tcp/",
    r"/dev/udp/"
]

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

def analyze_zombie_status() -> dict:
    """
    Scans the system's processes and active connections to detect potential 
    zombie machine / botnet / C2 behaviors.
    
    Returns a dictionary report containing:
      - score: risk score (0 to 100)
      - risk_level: string ("Bajo", "Medio", "Alto", "Crítico")
      - findings: list of finding dicts
      - scanned_processes: count of successfully scanned processes
      - scanned_connections: count of scanned connections
    """
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
        findings.append({
            "category": "Permisos",
            "severity": "WARNING",
            "description": "Sin acceso a todas las conexiones del sistema. Ejecute como root (sudo) para un escaneo completo.",
            "pid": None,
            "proc_name": None
        })
    except Exception as e:
        findings.append({
            "category": "Error",
            "severity": "WARNING",
            "description": f"Error al escanear conexiones de red: {str(e)}",
            "pid": None,
            "proc_name": None
        })

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
                    findings.append({
                        "category": "Binario Eliminado",
                        "severity": "CRITICAL",
                        "description": f"Proceso ejecutándose desde un archivo binario eliminado en disco.",
                        "pid": pid,
                        "proc_name": proc_name
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # --- 2. Check for Executable in Suspicious Paths ---
            if exe_path:
                for path in SUSPICIOUS_PATHS:
                    if exe_path.startswith(path):
                        findings.append({
                            "category": "Ruta Sospechosa",
                            "severity": "HIGH",
                            "description": f"Ejecutable ubicado en directorio temporal/volátil: {exe_path}",
                            "pid": pid,
                            "proc_name": proc_name
                        })
                        break

            # --- 3. Check SUID/SGID Privilege with Network Connections ---
            if exe_path and conns:
                try:
                    st = os.stat(exe_path)
                    # Check SUID or SGID bits
                    is_suid = bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))
                    if is_suid:
                        # Exclude common system utilities if any, but SUID + Network is highly suspicious
                        findings.append({
                            "category": "SUID con Red",
                            "severity": "HIGH",
                            "description": f"Binario con bit SUID/SGID activo tiene conexiones de red abiertas ({exe_path})",
                            "pid": pid,
                            "proc_name": proc_name
                        })
                except Exception:
                    pass

            # --- 4. Check for Reverse Shell Command-line Signatures ---
            if cmdline:
                for pattern in SUSPICIOUS_CMD_PATTERNS:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        findings.append({
                            "category": "Firma de Shell",
                            "severity": "CRITICAL",
                            "description": f"Argumentos de comando sugieren una Reverse Shell o payload: {cmdline[:60]}...",
                            "pid": pid,
                            "proc_name": proc_name
                        })
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
                    
                    if rport in C2_PORTS and not is_private_ip(rip):
                        findings.append({
                            "category": "Puerto C2/Sospechoso",
                            "severity": "CRITICAL",
                            "description": f"Conectado a puerto sospechoso/C2 ({rport}) en IP externa {rip}",
                            "pid": pid,
                            "proc_name": proc_name
                        })
                
                # Check for suspicious listening on all interfaces
                if conn.status == "LISTEN" and conn.laddr:
                    lip = conn.laddr.ip
                    lport = conn.laddr.port
                    if lip in ("0.0.0.0", "::"):
                        # Exclude standard/well-known local listening services
                        is_trusted = False
                        # SSH (22), HTTP (80/443), cups (631), loopbacks/services commonly verified
                        if lport in (22, 80, 443, 631):
                            is_trusted = True
                        elif proc_name in ("sshd", "nginx", "apache2", "lighttpd", "systemd-resolved"):
                            is_trusted = True
                            
                        if not is_trusted:
                            findings.append({
                                "category": "Escucha Abierta",
                                "severity": "MEDIUM",
                                "description": f"Proceso no estándar escuchando en puerto {lport} en todas las interfaces",
                                "pid": pid,
                                "proc_name": proc_name
                            })

            # --- 6. Check for Mass Scanning or Spamming (Outbound Scaling) ---
            if len(outbound_ips) >= 5 and proc_name.lower() not in WHITELISTED_MASS_CONN_PROCS:
                sev = "CRITICAL" if len(outbound_ips) >= 10 else "HIGH"
                findings.append({
                    "category": "Conexiones Masivas",
                    "severity": sev,
                    "description": f"Estableció conexiones simultáneas a {len(outbound_ips)} IPs públicas distintas (posible DDoS o escaneo)",
                    "pid": pid,
                    "proc_name": proc_name
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    # Calculate overall risk score
    # CRITICAL finding = 40 points
    # HIGH finding = 20 points
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
        
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "scanned_processes": scanned_procs,
        "scanned_connections": scanned_conns
    }
