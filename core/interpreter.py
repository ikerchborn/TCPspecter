# -*- coding: utf-8 -*-

PORT_DESCRIPTIONS = {
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

def interpret_connection(conn: dict) -> dict:
    """
    Translates raw socket data into a human-friendly diagnostic explanation.
    """
    raddr_ip = conn.get("raddr_ip", "-")
    raddr_port = conn.get("raddr_port", "-")
    laddr_port = conn.get("laddr_port", "-")
    proto = conn.get("proto", "TCP")
    status = conn.get("status", "-")
    pid = conn.get("pid", "-")
    name = conn.get("name", "-")

    # 1. IP Address Scope Interpretation
    is_local = False
    if raddr_ip in ("-", "*", "0.0.0.0", "::"):
        is_local = True
        if status == "LISTEN":
            ip_desc = "Servicio Servidor Local: Escuchando conexiones externas entrantes."
        else:
            ip_desc = "Conexión local del sistema."
    elif raddr_ip == "127.0.0.1" or raddr_ip == "::1":
        is_local = True
        ip_desc = "Comunicación Interna (Loopback): Tráfico local que nunca sale de tu computadora."
    elif raddr_ip.startswith("10.") or raddr_ip.startswith("192.168.") or raddr_ip.startswith("172."):
        is_local = True
        ip_desc = "Red Local (LAN): Conexión directa a otro dispositivo dentro de tu red interna/privada."
    elif raddr_ip.startswith("169.254."):
        is_local = True
        ip_desc = "Dirección IP de Enlace Local (Autoconfigurada, sin salida a Internet)."
    else:
        ip_desc = f"IP Pública (Internet): El proceso está enviando o recibiendo datos desde servidores externos."

    # 2. Port Purpose Interpretation
    port_desc = "Puerto dinámico o desconocido (normalmente usado por el sistema de forma temporal)."
    
    # Try interpreting remote port first
    try:
        rport_val = int(raddr_port)
        if rport_val in PORT_DESCRIPTIONS:
            port_desc = PORT_DESCRIPTIONS[rport_val]
    except ValueError:
        # Fallback to local port if remote is unset
        try:
            lport_val = int(laddr_port)
            if lport_val in PORT_DESCRIPTIONS:
                port_desc = f"Local: {PORT_DESCRIPTIONS[lport_val]}"
        except ValueError:
            pass

    # 3. Connection State Interpretation
    if status == "LISTEN":
        status_desc = "El proceso está en espera de conexiones entrantes. Funciona como un servidor local."
    elif status == "ESTABLISHED":
        status_desc = "Conexión activa. Los datos se están transfiriendo activamente entre tu máquina y el destino."
    elif status == "CLOSE_WAIT":
        status_desc = "El servidor remoto solicitó cerrar la conexión; tu máquina está finalizando la sesión local."
    elif status == "TIME_WAIT":
        status_desc = "La conexión se ha cerrado; se mantiene en espera para capturar paquetes perdidos en la red."
    elif status == "NONE" or status == "-":
        status_desc = "UDP (sin conexión persistente) o estado de red no negociado."
    else:
        status_desc = f"Estado: {status}. Fase de comunicación activa."

    # 4. Security Assessment Heuristics
    assessment = "SEGURO / ESTÁNDAR"
    reasons = []
    educational = ""
    recommendations = []

    # Check for shells talking outbound
    if not is_local and status == "ESTABLISHED":
        if name.lower() in ("bash", "sh", "dash", "zsh", "nc", "ncat", "socat", "python", "python3"):
            assessment = "CRÍTICO (PELIGRO DE SHELL)"
            reasons.append(f"El proceso '{name}' (consola o utilidad) tiene una sesión activa hacia una IP pública. Esto es típico de una REVERSE SHELL o exfiltración de datos.")
            recommendations = [
                "Verifica si este proceso fue autorizado por ti.",
                "Si no fue autorizado, termina el proceso de inmediato.",
                "Revisa el historial de comandos para ver qué acciones se ejecutaron."
            ]
            educational = "Reverse Shell: Una técnica donde un atacante fuerza a tu computadora a iniciar una conexión hacia su servidor, dándole control remoto encubierto saltándose firewalls locales."
        else:
            try:
                rport_val = int(raddr_port)
                if rport_val in (4444, 5555, 3333, 14444):
                    assessment = "CRÍTICO (C2/MINERÍA)"
                    reasons.append(f"Conexión activa al puerto {rport_val}, comúnmente usado por troyanos de control (C2) o mineros de criptomonedas.")
                    recommendations = [
                        "Aísla la máquina de la red inmediatamente.",
                        "Identifica y elimina el binario malicioso de tu sistema."
                    ]
                    educational = "C2 (Command and Control): Servidores usados por atacantes para enviar instrucciones a dispositivos infectados (Zombies) en una botnet."
            except ValueError:
                pass

    if not reasons:
        if status == "LISTEN" and not is_local:
            assessment = "REVISAR (ABIERTO A LAN/WAN)"
            reasons.append(f"El proceso '{name}' está abierto a recibir conexiones entrantes desde cualquier parte de tu red. Verifica si confías en esta aplicación.")
            recommendations = [
                "Asegúrate de que este servicio deba ser público.",
                "Configura un firewall (UFW/iptables) para restringir IPs si es necesario."
            ]
            educational = "Puertos Abiertos (LISTEN): Puntos de entrada al sistema. Si un puerto está expuesto a Internet sin autenticación, es susceptible a ataques de fuerza bruta o exploits."
        elif not is_local:
            reasons.append(f"Comunicación regular con internet iniciada por '{name}'.")
            recommendations = ["Monitorear el consumo de ancho de banda si se sospecha lentitud."]
            educational = "Tráfico de Salida (Egress): Conexiones iniciadas desde tu máquina hacia afuera. Suelen estar permitidas por defecto en la mayoría de los firewalls."
        else:
            reasons.append(f"Tráfico local seguro originado por '{name}'.")
            recommendations = ["No requiere acción. Tráfico de bajo riesgo."]
            educational = "Tráfico Local (Loopback/LAN): Datos que no viajan por Internet, reduciendo drásticamente el riesgo de intercepción externa."

    return {
        "ip_desc": ip_desc,
        "port_desc": port_desc,
        "status_desc": status_desc,
        "assessment": assessment,
        "explanation": " ".join(reasons),
        "recommendations": recommendations,
        "educational": educational
    }
