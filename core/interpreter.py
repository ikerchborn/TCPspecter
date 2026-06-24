# -*- coding: utf-8 -*-

PORT_DESCRIPTIONS_ES = {
    21: "FTP (File Transfer Protocol) - Transferencia de archivos antigua y sin cifrar.",
    22: "SSH (Secure Shell) - Acceso y administración remota segura.",
    23: "Telnet - Control remoto antiguo e inseguro (sin cifrar). ¡Peligroso si es externo!",
    25: "SMTP - Envío de correo electrónico.",
    53: "DNS (Domain Name System) - Traducción de nombres de dominio (como google.com) a IPs.",
    80: "HTTP (HyperText Transfer Protocol) - Tráfico web clásico no cifrado.",
    110: "POP3 - Descarga de correos electrónicos.",
    123: "NTP (Network Time Protocol) - Sincronización del reloj de tu computadora.",
    143: "IMAP - Acceso y sincronización de bandeja de correo electrónico.",
    443: "HTTPS - Tráfico web moderno, cifrado y seguro mediante SSL/TLS.",
    445: "SMB (Server Message Block) - Compartición de archivos e impresoras en red local.",
    631: "CUPS - Interfaz común de impresión para sistemas Unix.",
    993: "IMAPS - Sincronización segura de correos electrónicos (cifrada).",
    995: "POP3S - Descarga segura de correos electrónicos (cifrada).",
    1433: "MSSQL - Tráfico de base de datos Microsoft SQL Server.",
    3306: "MySQL - Conexión de base de datos MySQL.",
    5432: "PostgreSQL - Conexión de base de datos PostgreSQL.",
    8080: "HTTP Alt/Proxy - Puerto alternativo para servidores web y pruebas de desarrollo.",
}

PORT_DESCRIPTIONS_EN = {
    21: "FTP (File Transfer Protocol) - Legacy unencrypted file transfer protocol.",
    22: "SSH (Secure Shell) - Secure remote administration and access.",
    23: "Telnet - Legacy unencrypted and insecure remote control. Dangerous if external!",
    25: "SMTP - Email transmission protocol.",
    53: "DNS (Domain Name System) - Maps domain names (like google.com) to IP addresses.",
    80: "HTTP (HyperText Transfer Protocol) - Standard unencrypted web traffic.",
    110: "POP3 - Email retrieval protocol.",
    123: "NTP (Network Time Protocol) - System time synchronization.",
    143: "IMAP - Email retrieval and sync protocol.",
    443: "HTTPS - Secure encrypted web traffic via SSL/TLS.",
    445: "SMB (Server Message Block) - Local network file and printer sharing.",
    631: "CUPS - Common Unix Printing System interface.",
    993: "IMAPS - Secure encrypted IMAP email synchronization.",
    995: "POP3S - Secure encrypted POP3 email retrieval.",
    1433: "MSSQL - Microsoft SQL Server database traffic.",
    3306: "MySQL - MySQL database connection.",
    5432: "PostgreSQL - PostgreSQL database connection.",
    8080: "HTTP Alt/Proxy - Common port for alternative web servers and dev setups.",
}


def interpret_connection(conn: dict, lang: str = "en") -> dict:
    """
    Translates raw socket data into a human-friendly diagnostic explanation in English or Spanish.
    """
    raddr_ip = conn.get("raddr_ip", "-")
    raddr_port = conn.get("raddr_port", "-")
    laddr_port = conn.get("laddr_port", "-")
    proto = conn.get("proto", "TCP")
    status = conn.get("status", "-")
    pid = conn.get("pid", "-")
    name = conn.get("name", "-")

    from core.geoip import is_private_ip

    port_desc_dict = PORT_DESCRIPTIONS_EN if lang == "en" else PORT_DESCRIPTIONS_ES

    # 1. IP Address Scope Interpretation
    is_local = False
    if raddr_ip in ("-", "*", "0.0.0.0", "::"):
        is_local = True
        if status == "LISTEN":
            ip_desc = (
                "Local Server Service: Listening for inbound connections."
                if lang == "en"
                else "Servicio Servidor Local: Escuchando conexiones externas entrantes."
            )
        else:
            ip_desc = "Local system loopback connection." if lang == "en" else "Conexión local del sistema."
    elif raddr_ip == "127.0.0.1" or raddr_ip == "::1":
        is_local = True
        ip_desc = (
            "Internal Loopback: Local traffic that never leaves your computer."
            if lang == "en"
            else "Comunicación Interna (Loopback): Tráfico local que nunca sale de tu computadora."
        )
    elif is_private_ip(raddr_ip):
        is_local = True
        if raddr_ip.startswith("169.254."):
            ip_desc = (
                "Link-Local IP address (Autoconfigured, no internet routing)."
                if lang == "en"
                else "Dirección IP de Enlace Local (Autoconfigurada, sin salida a Internet)."
            )
        else:
            ip_desc = (
                "Local Area Network (LAN): Direct connection to another device within your private network."
                if lang == "en"
                else "Red Local (LAN): Conexión directa a otro dispositivo dentro de tu red interna/privada."
            )
    else:
        ip_desc = (
            f"Public IP (Internet): The process is sending or receiving data from external servers."
            if lang == "en"
            else f"IP Pública (Internet): El proceso está enviando o recibiendo datos desde servidores externos."
        )

    # 2. Port Purpose Interpretation
    port_desc = (
        "Ephemeral or unknown port (normally used temporarily by the system)."
        if lang == "en"
        else "Puerto dinámico o desconocido (normalmente usado por el sistema de forma temporal)."
    )
    
    # Try interpreting remote port first
    try:
        rport_val = int(raddr_port)
        from core.service_catalog import describe_port, lookup_service
        catalog_desc = describe_port(rport_val, proto, lang)
        if catalog_desc:
            port_desc = catalog_desc
        elif rport_val in port_desc_dict:
            port_desc = port_desc_dict[rport_val]
    except ValueError:
        # Fallback to local port if remote is unset
        try:
            lport_val = int(laddr_port)
            from core.service_catalog import describe_port, lookup_service
            catalog_desc = describe_port(lport_val, proto, lang)
            if catalog_desc:
                port_desc = (
                    f"Local: {catalog_desc}" if lang == "en" else f"Local: {catalog_desc}"
                )
            elif lport_val in port_desc_dict:
                port_desc = (
                    f"Local: {port_desc_dict[lport_val]}"
                    if lang == "en"
                    else f"Local: {port_desc_dict[lport_val]}"
                )
        except ValueError:
            pass

    # 3. Connection State Interpretation
    if status == "LISTEN":
        status_desc = (
            "The process is waiting for incoming connections. Acts as a local server."
            if lang == "en"
            else "El proceso está en espera de conexiones entrantes. Funciona como un servidor local."
        )
    elif status == "ESTABLISHED":
        status_desc = (
            "Active connection. Data is being actively transferred between your host and the destination."
            if lang == "en"
            else "Conexión activa. Los datos se están transfiriendo activamente entre tu máquina y el destino."
        )
    elif status == "CLOSE_WAIT":
        status_desc = (
            "The remote server requested to close the socket; your machine is finalizing the local session."
            if lang == "en"
            else "El servidor remoto solicitó cerrar la conexión; tu máquina está finalizando la sesión local."
        )
    elif status == "TIME_WAIT":
        status_desc = (
            "The connection was closed; it is held in wait to capture late packets in the network."
            if lang == "en"
            else "La conexión se ha cerrado; se mantiene en espera para capturar paquetes perdidos en la red."
        )
    elif status == "NONE" or status == "-":
        status_desc = (
            "UDP (connectionless socket) or unnegotiated network state."
            if lang == "en"
            else "UDP (sin conexión persistente) o estado de red no negociado."
        )
    else:
        status_desc = (
            f"State: {status}. Active communication phase."
            if lang == "en"
            else f"Estado: {status}. Fase de comunicación activa."
        )

    # 4. Security Assessment Heuristics
    assessment = "SAFE / STANDARD" if lang == "en" else "SEGURO / ESTÁNDAR"
    reasons = []
    educational = ""
    recommendations = []

    # Check for shells talking outbound
    if not is_local and status == "ESTABLISHED":
        if name.lower() in ("bash", "sh", "dash", "zsh", "nc", "ncat", "socat", "python", "python3"):
            assessment = "CRITICAL (SHELL THREAT)" if lang == "en" else "CRÍTICO (PELIGRO DE SHELL)"
            reasons.append(
                f"The process '{name}' (shell or command utility) has an active session to a public IP. This is standard indicator of a REVERSE SHELL or unauthorized data exfiltration."
                if lang == "en"
                else f"El proceso '{name}' (consola o utilidad) tiene una sesión activa hacia una IP pública. Esto es típico de una REVERSE SHELL o exfiltración de datos."
            )
            recommendations = [
                "Verify if this execution was explicitly authorized by you." if lang == "en" else "Verifica si este proceso fue autorizado por ti.",
                "If not authorized, terminate the process immediately." if lang == "en" else "Si no fue autorizado, termina el proceso de inmediato.",
                "Review system command history to audit what commands were executed." if lang == "en" else "Revisa el historial de comandos para ver qué acciones se ejecutaron."
            ]
            educational = (
                "Reverse Shell: A technique where a target machine initiates an outbound connection to an attacker's listener port. This allows the attacker to bypass local inbound firewall policies."
                if lang == "en"
                else "Reverse Shell: Una técnica donde un atacante fuerza a tu computadora a iniciar una conexión hacia su servidor, dándole control remoto encubierto saltándose firewalls locales."
            )
        else:
            try:
                rport_val = int(raddr_port)
                from core.zombie_detector import C2_PORTS
                if rport_val in C2_PORTS:
                    assessment = "CRITICAL (C2/MINER)" if lang == "en" else "CRÍTICO (C2/MINERÍA)"
                    reasons.append(
                        f"Active connection to port {rport_val}, commonly associated with Trojan Command & Control (C2) servers or Cryptomining nodes."
                        if lang == "en"
                        else f"Conexión activa al puerto {rport_val}, comúnmente usado por troyanos de control (C2) o mineros de criptomonedas."
                    )
                    recommendations = [
                        "Isolate the machine from the network immediately." if lang == "en" else "Aísla la máquina de la red inmediatamente.",
                        "Identify and inspect the binary file associated with this process." if lang == "en" else "Identifica y elimina el binario malicioso de tu sistema."
                    ]
                    educational = (
                        "C2 (Command and Control): Servers used by malware operators to send instructions to compromised hosts (Zombie nodes) in a botnet."
                        if lang == "en"
                        else "C2 (Command and Control): Servidores usados por atacantes para enviar instrucciones a dispositivos infectados (Zombies) en una botnet."
                    )
            except ValueError:
                pass

    if not reasons:
        if status == "LISTEN" and not is_local:
            assessment = "SUSPICIOUS (OPEN TO LAN/WAN)" if lang == "en" else "REVISAR (ABIERTO A LAN/WAN)"
            reasons.append(
                f"The process '{name}' is open to receive incoming connections from any host on your network. Verify if this exposure is intended."
                if lang == "en"
                else f"El proceso '{name}' está abierto a recibir conexiones entrantes desde cualquier parte de tu red. Verifica si confías en esta aplicación."
            )
            recommendations = [
                "Verify if this service is required to be publicly accessible." if lang == "en" else "Asegúrate de que este servicio deba ser público.",
                "Use a firewall (UFW/iptables) to restrict connections to trusted IPs only." if lang == "en" else "Configura un firewall (UFW/iptables) para restringir IPs si es necesario."
            ]
            educational = (
                "Open Ports (LISTEN): Entry points to your system. If a port is exposed to the network without proper authentication, it is vulnerable to scanning, brute-forcing, or exploits."
                if lang == "en"
                else "Puertos Abiertos (LISTEN): Puntos de entrada al sistema. Si un puerto está expuesto a Internet sin autenticación, es susceptible a ataques de fuerza bruta o exploits."
            )
        elif not is_local:
            reasons.append(
                f"Regular outbound internet communication initiated by process '{name}'."
                if lang == "en"
                else f"Comunicación regular con internet iniciada por '{name}'."
            )
            recommendations = [
                "Monitor bandwidth usage if you suspect network bottlenecks or high usage."
                if lang == "en"
                else "Monitorear el consumo de ancho de banda si se sospecha lentitud."
            ]
            educational = (
                "Outbound Traffic (Egress): Network packets sent from your host to external networks. Usually allowed by default on host firewalls."
                if lang == "en"
                else "Tráfico de Salida (Egress): Conexiones iniciadas desde tu máquina hacia afuera. Suelen estar permitidas por defecto en la mayoría de los firewalls."
            )
        else:
            reasons.append(
                f"Safe local traffic generated by process '{name}'."
                if lang == "en"
                else f"Tráfico local seguro originado por '{name}'."
            )
            recommendations = [
                "No action required. Low-risk local communication."
                if lang == "en"
                else "No requiere acción. Tráfico de bajo riesgo."
            ]
            educational = (
                "Local Traffic (Loopback/LAN): Data that stays inside the local host or private subnet, significantly reducing exposure to external interception."
                if lang == "en"
                else "Tráfico Local (Loopback/LAN): Datos que no viajan por Internet, reduciendo drásticamente el riesgo de intercepción externa."
            )

    return {
        "ip_desc": ip_desc,
        "port_desc": port_desc,
        "status_desc": status_desc,
        "assessment": assessment,
        "explanation": " ".join(reasons),
        "recommendations": recommendations,
        "educational": educational,
    }


CATEGORY_TRANSLATIONS = {
    "es": {
        "Binario Eliminado": "Binario Eliminado",
        "Ruta Sospechosa": "Ruta Sospechosa",
        "SUID con Red": "SUID con Red",
        "Firma de Shell": "Firma de Shell",
        "Shell con Conexión": "Shell con Conexión",
        "Mascarada de Proceso": "Mascarada de Proceso",
        "Agente C2 Huérfano": "Agente C2 Huérfano",
        "Tráfico SSL Atípico": "Tráfico SSL Atípico",
        "Puerto C2/Sospechoso": "Puerto C2/Sospechoso",
        "Escucha Abierta": "Escucha Abierta",
        "Conexiones Masivas": "Conexiones Masivas",
        "C2 Beaconing": "C2 Beaconing",
        "Persistencia del Sistema": "Persistencia del Sistema",
        "Conexión Regular C2": "Conexión Regular C2",
        "IDS/Sniffer": "IDS/Sniffer",
        "Memoria Fileless": "Memoria Fileless",
        "Permisos": "Permisos",
        "Error": "Error",
        "Escaneo de Puertos": "Escaneo de Puertos",
        "Threat Port Match": "Puerto de Amenaza",
        "Tor Exit Node": "Nodo Salida Tor",
        "Sinkholed Infrastructure": "Infraestructura Sinkhole",
        "Custom Blacklist Hit": "Lista Negra Personalizada",
        "Dynamic DNS Provider": "Proveedor DNS Dinámico",
        "Suspicious TLD": "TLD Sospechoso",
        "Suspicious C2 Port": "Puerto C2/Sospechoso",
    },
    "en": {
        "Binario Eliminado": "Deleted Binary",
        "Ruta Sospechosa": "Suspicious Path",
        "SUID con Red": "SUID with Network Activity",
        "Firma de Shell": "Shell Signature",
        "Shell con Conexión": "Shell with Active Connection",
        "Mascarada de Proceso": "Process Masquerading",
        "Agente C2 Huérfano": "Orphaned C2 Agent",
        "Tráfico SSL Atípico": "Atypical SSL Traffic",
        "Puerto C2/Sospechoso": "C2/Suspicious Port",
        "Escucha Abierta": "Open Port Listener",
        "Conexiones Masivas": "Mass Outbound Connections",
        "C2 Beaconing": "C2 Beaconing Behavior",
        "Persistencia del Sistema": "System Persistence",
        "Conexión Regular C2": "Regular C2 Connection",
        "IDS/Sniffer": "IDS/Sniffer",
        "Memoria Fileless": "Fileless Memory Injection",
        "Permisos": "Permissions Error",
        "Error": "System Error",
        "Escaneo de Puertos": "Port Scan",
        "Threat Port Match": "Threat Port Match",
        "Tor Exit Node": "Tor Exit Node",
        "Sinkholed Infrastructure": "Sinkholed Infrastructure",
        "Custom Blacklist Hit": "Custom Blacklist Hit",
        "Dynamic DNS Provider": "Dynamic DNS Provider",
        "Suspicious TLD": "Suspicious TLD",
        "Suspicious C2 Port": "Suspicious C2 Port",
    }
}


def translate_description(desc: str, lang: str = "en") -> str:
    if lang == "es":
        return desc
    
    import re
    # 1. Permisos
    if "Sin acceso a todas las conexiones del sistema" in desc:
        return "No access to all system connections. Run as root (sudo) for a full scan."
    
    # 2. Error
    if "Error al escanear conexiones de red:" in desc:
        err_msg = desc.split("Error al escanear conexiones de red:")[1].strip()
        return f"Error scanning network connections: {err_msg}"
        
    # 3. Binario Eliminado
    if "Proceso ejecutándose desde un archivo binario eliminado" in desc:
        return "Process running from a deleted binary file on disk."
        
    # 4. Ruta Sospechosa
    if "Ejecutable ubicado en directorio temporal/volátil:" in desc:
        path = desc.split("Ejecutable ubicado en directorio temporal/volátil:")[1].strip()
        return f"Executable located in a temporary/volatile directory: {path}"
        
    # 5. SUID con Red
    if "Binario con bit SUID/SGID activo tiene conexiones de red abiertas" in desc:
        path = desc.split("tiene conexiones de red abiertas (")[1].replace(")", "").strip()
        return f"Binary with active SUID/SGID bit has open network connections ({path})"
        
    # 6. Memoria Fileless
    if "regiones de memoria ejecutable anónima (sin respaldo en disco)" in desc:
        m = re.search(r"Se detectaron (\d+) regiones", desc)
        count = m.group(1) if m else "some"
        return f"Detected {count} regions of anonymous executable memory (no backing file on disk). Possible active network fileless malware / shellcode injection."
        
    # 7. Firma de Shell
    if "Argumentos de comando sugieren una Reverse Shell o payload:" in desc:
        cmd = desc.split("Argumentos de comando sugieren una Reverse Shell o payload:")[1].strip()
        return f"Command line arguments suggest a Reverse Shell or payload: {cmd}"
        
    # 8. Shell con Conexión
    if "Proceso intérprete de comandos (" in desc and "con conexión TCP activa hacia IP pública" in desc:
        proc = desc.split("Proceso intérprete de comandos (")[1].split(")")[0]
        return f"Command interpreter process ({proc}) with active TCP connection to public IP."
        
    # 9. Mascarada
    if "Proceso malicioso camuflado como hilo del kernel:" in desc:
        parts = desc.split("Proceso malicioso camuflado como hilo del kernel:")[1].strip()
        return f"Malicious process masquerading as a kernel thread: {parts}"
        
    # 10. Huérfano
    if "Proceso huérfano (PPID 1) no-sistema en" in desc:
        path = desc.split("Proceso huérfano (PPID 1) no-sistema en")[1].split("con tráfico")[0].strip()
        return f"Orphan process (PPID 1) non-system binary at {path} with public network traffic."
        
    # 11. HTTPS Spoofing
    if "usando puerto HTTPS (443) hacia" in desc:
        proc = desc.split("Proceso desconocido (")[1].split(")")[0]
        rip = desc.split("hacia")[1].split("(posible")[0].strip()
        return f"Unknown process ({proc}) using HTTPS port (443) to {rip} (possible C2 beaconing)."
        
    # 12. Puerto C2
    if "Conectado a puerto sospechoso/C2" in desc:
        rport = desc.split("sospechoso/C2 (")[1].split(")")[0]
        rip = desc.split("en IP externa")[1].strip()
        return f"Connected to suspicious/C2 port ({rport}) on external IP {rip}"
        
    # 13. Escucha Abierta
    if "Proceso no estándar escuchando en puerto" in desc:
        port = desc.split("escuchando en puerto")[1].split("en todas")[0].strip()
        return f"Non-standard process listening on port {port} on all interfaces"
        
    # 14. Conexiones Masivas
    if "Estableció conexiones simultáneas a" in desc:
        count = desc.split("Estableció conexiones simultáneas a")[1].split("IPs públicas")[0].strip()
        return f"Established simultaneous connections to {count} distinct public IPs (possible DDoS or port scan)"
        
    # 15. C2 Beaconing
    if "Comportamiento de beaconing C2 detectado:" in desc:
        m = re.search(r"detectado:\s+(\S+)\s+conectándose regularmente a\s+(\S+)\s+\(regularidad:\s*([^,]+),\s*ventana:\s*([^\)]+)\)", desc)
        if m:
            proc, target, reg, win = m.groups()
            return f"C2 beaconing behavior detected: {proc} connecting regularly to {target} (regularity: {reg}, window: {win}). Indicates potential malware calling home."
        return f"C2 beaconing behavior detected: {desc}"
        
    # 16. Persistencia
    if "tareas programadas (crontab) del usuario" in desc:
        m = re.search(r"Proceso sospechoso '([^']+)' en ruta (\S+) encontrado en las tareas programadas \(crontab\) del usuario '([^']*)'", desc)
        if m:
            proc, path, user = m.groups()
            return f"Suspicious process '{proc}' at path {path} found in crontab for user '{user}'. Indicates persistence."
        return f"Suspicious process found in crontab: {desc}"

    # 17. Escaneo de Puertos (ndr scan alert)
    if "Escaneo de puertos detectado desde" in desc:
        m = re.search(r"desde (\S+) hacia (\S+) \((\d+) puertos en <10s\)", desc)
        if m:
            src, dst, ports = m.groups()
            return f"Port scan detected from {src} to {dst} ({ports} ports in <10s)"
        return desc
        
    return desc

