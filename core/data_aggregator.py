# -*- coding: utf-8 -*-
import threading
import json
import time
import urllib.parse
import asyncio
import secrets
import socket
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import os
import re
import datetime
import logging
from collections import defaultdict

import psutil
from core.sysinfo import get_system_stats, get_process_list, get_all_connections
from core.zombie_detector import analyze_zombie_status
from core.interpreter import interpret_connection
from core.geoip import lookup_ip_geoip, lookup_self_geoip
from core.traceroute import get_hops
from core.alerts import SecurityAlert, publish as _publish_alert, subscribe as _subscribe_alert

log = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(_BASE_DIR, "config.json")
SECURITY_LOG_FILE = os.path.join(_BASE_DIR, "security_events.log")

# ─────────────────────────────────────────────────────────────────────────────
# CSRF Token Store (in-memory, 30-minute TTL)
# ─────────────────────────────────────────────────────────────────────────────
_csrf_tokens: dict[str, float] = {}   # token -> expiry timestamp
_csrf_lock = threading.Lock()
_CSRF_TTL_SECS = 1800  # 30 minutes

def generate_csrf_token() -> str:
    """Generates a cryptographically secure CSRF token and registers it."""
    token = secrets.token_hex(32)
    now = time.time()
    with _csrf_lock:
        # Purge expired tokens
        expired = [t for t, exp in _csrf_tokens.items() if now > exp]
        for t in expired:
            del _csrf_tokens[t]
        _csrf_tokens[token] = now + _CSRF_TTL_SECS
    return token

def validate_csrf_token(token: str) -> bool:
    """Validates a CSRF token. Tokens are valid for their entire TTL to support SPA without reloading."""
    if not token:
        return False
    with _csrf_lock:
        expiry = _csrf_tokens.get(token)
        if expiry and time.time() < expiry:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiter — Sliding window per client IP
# ─────────────────────────────────────────────────────────────────────────────
_rate_limit_store: dict[str, list] = defaultdict(list)  # ip -> [timestamps]
_rate_lock = threading.Lock()
_RATE_WINDOW_SECS = 60   # 1-minute window
_RATE_MAX_REQUESTS = 30  # max 30 mutating requests per minute per IP

def check_rate_limit(client_ip: str) -> bool:
    """Returns True if the client is within the rate limit, False if exceeded."""
    now = time.time()
    with _rate_lock:
        timestamps = _rate_limit_store[client_ip]
        # Keep only events in the current window
        valid_ts = [t for t in timestamps if now - t < _RATE_WINDOW_SECS]
        _rate_limit_store[client_ip] = valid_ts
        
        # Evict old IPs from the store to prevent memory leaks if store grows large
        if len(_rate_limit_store) > 1000:
            stale_ips = [ip for ip, ts_list in _rate_limit_store.items() if not ts_list or now - ts_list[-1] > _RATE_WINDOW_SECS]
            for ip in stale_ips:
                if ip != client_ip:
                    del _rate_limit_store[ip]
        
        if len(valid_ts) >= _RATE_MAX_REQUESTS:
            return False
        
        _rate_limit_store[client_ip].append(now)
        return True

def get_configured_port():
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
            return int(cfg.get("web_server_port", 8050))
    except Exception:
        return 8050


_dns_alerts = []
_dlp_alerts = []
_alerts_lock = threading.Lock()

def _alert_callback(alert: SecurityAlert) -> None:
    global _dns_alerts, _dlp_alerts
    with _alerts_lock:
        alert_dict = {
            "timestamp": alert.timestamp,
            "category": alert.category,
            "description": alert.description,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip
        }
        if alert.engine == "dns":
            _dns_alerts.append(alert_dict)
            if len(_dns_alerts) > 100:
                _dns_alerts.pop(0)
        else:
            _dlp_alerts.append(alert_dict)
            if len(_dlp_alerts) > 100:
                _dlp_alerts.pop(0)

_subscribe_alert(_alert_callback)

PORT = get_configured_port()

# Global server controls
_server = None
_thread = None
last_net_io = None
last_net_time = 0.0
_active_findings = set()

def log_security_finding(finding: dict, status: str = "DETECTED") -> None:
    """
    Shim de compatibilidad: convierte el dict de finding legacy al
    nuevo SecurityAlert y lo publica en el Alert Bus.

    El Alert Bus se encarga de la persistencia en disco (text log + ECS JSON).
    Esta función ya NO escribe directamente al disco — elimina la duplicación
    y el riesgo de 'except Exception: pass' silencioso en I/O.
    """
    _publish_alert(SecurityAlert.now(
        engine=finding.get("proc_name", "system") or "system",
        category=finding.get("category", "General"),
        severity=finding.get("severity", "INFO"),  # type: ignore[arg-type]
        description=finding.get("description", ""),
        pid=finding.get("pid") if isinstance(finding.get("pid"), int) else None,
        proc_name=finding.get("proc_name") or "",
        status=status,  # type: ignore[arg-type]
        mitre_technique_id=finding.get("mitre_technique_id"),
        mitre_technique_name=finding.get("mitre_technique_name"),
        mitre_tactic=finding.get("mitre_tactic"),
        nist_controls=tuple(finding.get("nist_controls") or ()),
        iso_controls=tuple(finding.get("iso_controls") or ()),
    ))

def get_parsed_logs(lang: str = "en") -> list[dict]:
    """
    Lee y parsea el archivo de log de texto de eventos de seguridad.
    Retorna los eventos más recientes primero.
    """
    logs = []
    log_path = os.path.join(_BASE_DIR, "security_events.log")
    if not os.path.exists(log_path):
        return logs
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(
                    r"^\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+\(PID (.*?):\s+(.*?)\)\s+-\s+(.*)$",
                    line.strip(),
                )
                if m:
                    cat = m.group(4)
                    desc = m.group(7)
                    from core.interpreter import CATEGORY_TRANSLATIONS, translate_description
                    translated_cat = CATEGORY_TRANSLATIONS.get(lang, {}).get(cat, cat)
                    translated_desc = translate_description(desc, lang)
                    logs.append({
                        "timestamp": m.group(1),
                        "status":    m.group(2),
                        "severity":  m.group(3),
                        "category":  translated_cat,
                        "pid":       m.group(5),
                        "proc_name": m.group(6),
                        "description": translated_desc,
                    })
    except OSError as exc:
        log.error("Error leyendo security_events.log: %s", exc)
    return list(reversed(logs))

_cached_security = {
    "score": 0,
    "risk_level": "CALCULANDO...",
    "findings": [],
    "scanned_processes": 0,
    "scanned_connections": 0
}
_security_lock = threading.Lock()

def _security_worker() -> None:
    """Background thread: refresca el análisis de seguridad cada 5s y publica eventos nuevos."""
    global _active_findings, _cached_security
    while True:
        try:
            result = analyze_zombie_status()
            with _security_lock:
                _cached_security = result

            current_findings = result.get("findings", [])
            current_keys: set[tuple] = set()

            for f in current_findings:
                key = (
                    f.get("category"), f.get("severity"),
                    f.get("pid"),      f.get("proc_name"),
                    f.get("description"),
                )
                current_keys.add(key)
                if key not in _active_findings:
                    log_security_finding(f, "DETECTED")
                    _active_findings.add(key)

            # Findings que ya no existen → RESOLVED
            for key in list(_active_findings - current_keys):
                log_security_finding({
                    "category":    key[0],
                    "severity":    key[1],
                    "pid":         key[2],
                    "proc_name":   key[3],
                    "description": key[4],
                }, "RESOLVED")
                _active_findings.discard(key)

        except psutil.AccessDenied:
            pass  # esperado sin root — no loguear para no saturar
        except Exception:
            log.exception("Error inesperado en _security_worker.")

        time.sleep(5)

def get_cached_security():
    with _security_lock:
        return dict(_cached_security)
# -------------------------------------------------------------------------

try:
    last_net_io = psutil.net_io_counters()
    last_net_time = time.time()
except Exception:
    pass

def get_dashboard_data(lang="en"):
    """
    Aggregates stats, processes, connections, and security telemetry.
    """
    global last_net_io, last_net_time
    
    stats = get_system_stats()
    
    # Calculate Rx/Tx bandwidth speeds in Mbps
    rx_speed = 0.0
    tx_speed = 0.0
    try:
        net_io = psutil.net_io_counters()
        now = time.time()
        if last_net_io is not None and last_net_time > 0:
            dt = now - last_net_time
            if dt > 0:
                rx_speed = ((net_io.bytes_recv - last_net_io.bytes_recv) * 8) / (1024 * 1024 * dt)
                tx_speed = ((net_io.bytes_sent - last_net_io.bytes_sent) * 8) / (1024 * 1024 * dt)
        last_net_io = net_io
        last_net_time = now
    except Exception:
        pass

    # Use cached security report (updated every 5s in background thread)
    security_report = get_cached_security()
    
    risk_level = security_report.get("risk_level", "BAJO")
    if lang == "en":
        risk_level_map = {
            "CRÍTICO": "CRITICAL",
            "ALTO": "HIGH",
            "MEDIO": "MEDIUM",
            "BAJO": "LOW",
            "DESACTIVADO": "DISABLED"
        }
        risk_level = risk_level_map.get(risk_level, risk_level)

    translated_findings = []
    for f in security_report.get("findings", []):
        f_copy = f.copy()
        cat = f_copy.get("category", "")
        desc = f_copy.get("description", "")
        from core.interpreter import CATEGORY_TRANSLATIONS, translate_description
        f_copy["category"] = CATEGORY_TRANSLATIONS.get(lang, {}).get(cat, cat)
        f_copy["description"] = translate_description(desc, lang)
        translated_findings.append(f_copy)

    # Active connections list
    raw_conns = get_all_connections()
    conns = []
    for c in raw_conns:
        # Generate rich human-readable description for each connection row
        interpretation = interpret_connection(c, lang=lang)
        c_copy = c.copy()
        c_copy["interpretation"] = interpretation
        conns.append(c_copy)

    # Processes list
    processes = get_process_list()

    # Dynamic updates from Snort, Firewall, and Scapy Sniffer
    from core.snort_manager import is_snort_running, is_snort_installed
    from core.firewall_manager import get_blocked_ips, detect_backend
    from core.traffic_analyzer import get_live_metrics
    
    snort_status = {
        "installed": is_snort_installed(),
        "running": is_snort_running()
    }
    
    firewall_status = {
        "backend": detect_backend(),
        "blocked_ips": get_blocked_ips()
    }
    
    scapy_metrics = get_live_metrics().copy()
    
    translated_dns_alerts = []
    translated_dlp_alerts = []
    with _alerts_lock:
        for alert in _dns_alerts:
            a_copy = alert.copy()
            cat = a_copy.get("category", "")
            desc = a_copy.get("description", "")
            from core.interpreter import CATEGORY_TRANSLATIONS, translate_description
            a_copy["category"] = CATEGORY_TRANSLATIONS.get(lang, {}).get(cat, cat)
            a_copy["description"] = translate_description(desc, lang)
            translated_dns_alerts.append(a_copy)
            
        for alert in _dlp_alerts:
            a_copy = alert.copy()
            cat = a_copy.get("category", "")
            desc = a_copy.get("description", "")
            from core.interpreter import CATEGORY_TRANSLATIONS, translate_description
            a_copy["category"] = CATEGORY_TRANSLATIONS.get(lang, {}).get(cat, cat)
            a_copy["description"] = translate_description(desc, lang)
            translated_dlp_alerts.append(a_copy)

    scapy_metrics["dns_alerts"] = translated_dns_alerts
    scapy_metrics["dlp_alerts"] = translated_dlp_alerts

    return {
        "cpu": stats.get("cpu", 0.0),
        "ram": stats.get("ram", 0.0),
        "used_ram": stats.get("used_ram", 0),
        "total_ram": stats.get("total_ram", 0),
        "rx_speed": round(rx_speed, 2),
        "tx_speed": round(tx_speed, 2),
        "security": {
            "score": security_report.get("score", 0),
            "risk_level": risk_level,
            "findings": translated_findings,
            "scanned_processes": security_report.get("scanned_processes", 0),
            "scanned_connections": security_report.get("scanned_connections", 0)
        },
        "processes": processes,
        "connections": conns,
        "snort": snort_status,
        "firewall": firewall_status,
        "scapy": scapy_metrics
    }
