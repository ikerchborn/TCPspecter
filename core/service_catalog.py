"""
Network service catalog — maps well-known ports to human-readable labels.

Combines built-in IANA-style descriptions with threat intelligence port
labels loaded by the intelligence engine.
"""
from __future__ import annotations

from typing import Final

_BUILTIN_TCP: Final[dict[int, str]] = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    631: "IPP/CUPS",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    27017: "MongoDB",
}

_BUILTIN_UDP: Final[dict[int, str]] = {
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP",
    161: "SNMP",
    514: "Syslog",
    1900: "SSDP",
}


def lookup_service(port: int | str, proto: str = "TCP") -> str | None:
    """
    Return a service label for the given port and protocol.
    Threat intelligence labels take precedence over built-in catalog entries.
    """
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return None

    try:
        from core.intelligence_engine import get_engine
        intel = get_engine().match_port(port_num)
        if intel:
            return intel.label
    except Exception:
        pass

    proto_key = (proto or "TCP").upper()
    if proto_key == "UDP":
        return _BUILTIN_UDP.get(port_num)
    return _BUILTIN_TCP.get(port_num)


def describe_port(port: int | str, proto: str = "TCP", lang: str = "en") -> str | None:
    """Return an extended port description for the Explanation Engine."""
    label = lookup_service(port, proto)
    if not label:
        return None

    try:
        from core.intelligence_engine import get_engine
        intel = get_engine().match_port(int(port))
        if intel and intel.description:
            if lang == "es":
                return f"Puerto {port} ({label}): {intel.description}"
            return f"Port {port} ({label}): {intel.description}"
    except Exception:
        pass

    if lang == "es":
        return f"Puerto {port}: servicio conocido como {label}."
    return f"Port {port}: known service {label}."
