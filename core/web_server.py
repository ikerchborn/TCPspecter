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
    """Validates a CSRF token. Tokens are single-use after validation."""
    if not token:
        return False
    with _csrf_lock:
        expiry = _csrf_tokens.get(token)
        if expiry and time.time() < expiry:
            # Single-use: remove after validation
            del _csrf_tokens[token]
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
        _rate_limit_store[client_ip] = [t for t in timestamps if now - t < _RATE_WINDOW_SECS]
        if len(_rate_limit_store[client_ip]) >= _RATE_MAX_REQUESTS:
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

HTML_CONTENT = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TCPspecter - Panel de Control Gráfico</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
    <style>
        :root {
            --bg-color: #080c14;
            --card-bg: rgba(17, 24, 39, 0.7);
            --card-border: rgba(255, 255, 255, 0.06);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #4a7a9d;
            --accent: #f2e8c9;
            --danger: #f87171;
            --warning: #fbbf24;
            --success: #34d399;
            --shadow: rgba(0, 0, 0, 0.4);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 10% 20%, rgba(74, 122, 157, 0.08) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(242, 232, 201, 0.05) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
            overflow-x: hidden;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--card-border);
        }

        .logo-section h1 {
            font-size: 28px;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: var(--text-main);
        }

        .logo-section h1 span {
            color: var(--primary);
        }

        .logo-section p {
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .status-badge {
            background: rgba(52, 211, 153, 0.15);
            border: 1px solid var(--success);
            color: var(--success);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--success);
            border-radius: 50%;
            display: inline-block;
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.9); opacity: 0.6; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.9); opacity: 0.6; }
        }

        /* Dashboard Grid Layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 10px 30px var(--shadow);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            cursor: pointer;
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
            border-color: rgba(74, 122, 157, 0.4);
        }

        .card-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* Large Stats Grid (Gauges / Charts) */
        .grid-span-2 {
            grid-column: span 2;
        }

        .grid-span-3 {
            grid-column: span 3;
        }

        /* Chart Canvas Sizing */
        .chart-container {
            position: relative;
            height: 150px;
            width: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .chart-container-large {
            position: relative;
            height: 220px;
            width: 100%;
        }

        /* Security Dashboard Alert styles */
        .security-score-container {
            display: flex;
            align-items: center;
            justify-content: space-around;
            height: 100%;
        }

        .score-circle {
            position: relative;
            width: 110px;
            height: 110px;
            border-radius: 50%;
            background: conic-gradient(var(--primary) 0%, #1e293b 0%);
            display: flex;
            justify-content: center;
            align-items: center;
            box-shadow: inset 0 0 10px rgba(0,0,0,0.5);
        }

        .score-circle-inner {
            width: 92px;
            height: 92px;
            background: #0f172a;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }

        .score-num {
            font-size: 26px;
            font-weight: 700;
        }

        .score-lbl {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .security-details {
            display: flex;
            flex-direction: column;
            gap: 12px;
            flex: 1;
            margin-left: 20px;
        }

        .detail-item {
            font-size: 14px;
        }

        .detail-value {
            font-weight: 700;
            font-size: 16px;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
        }

        .sev-bajo { background: rgba(52, 211, 153, 0.15); color: var(--success); }
        .sev-medio { background: rgba(74, 122, 157, 0.15); color: var(--primary); }
        .sev-alto { background: rgba(251, 191, 36, 0.15); color: var(--warning); }
        .sev-critico { background: rgba(248, 113, 113, 0.15); color: var(--danger); }

        /* Security Formula Explanation */
        .formula-card {
            background: rgba(30, 41, 59, 0.4);
            border-radius: 12px;
            padding: 12px;
            font-size: 12px;
            line-height: 1.5;
            color: var(--text-muted);
            border: 1px dashed rgba(255,255,255,0.05);
        }

        .formula-card strong {
            color: var(--text-main);
        }

        /* Connections section */
        .connections-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .connections-title h2 {
            font-size: 20px;
            font-weight: 600;
        }

        .search-box {
            display: flex;
            gap: 12px;
            align-items: center;
        }

        .search-input {
            background: rgba(17, 24, 39, 0.8);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 8px 16px;
            color: var(--text-main);
            outline: none;
            width: 300px;
            font-size: 14px;
            transition: border-color 0.3s;
        }

        .search-input:focus {
            border-color: var(--primary);
        }

        /* Connections Table styling */
        .table-container {
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid var(--card-border);
            max-height: 500px;
            overflow-y: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 14px;
        }

        thead {
            position: sticky;
            top: 0;
            background: #111827;
            z-index: 10;
        }

        th {
            padding: 14px 16px;
            font-weight: 600;
            color: var(--text-muted);
            border-bottom: 1px solid var(--card-border);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255,255,255,0.02);
            color: #d1d5db;
        }

        tr {
            transition: background-color 0.2s;
            cursor: pointer;
        }

        tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }

        .badge-status {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge-established { background: rgba(52, 211, 153, 0.15); color: var(--success); }
        .badge-listen { background: rgba(74, 122, 157, 0.15); color: var(--primary); }
        .badge-other { background: rgba(156, 163, 175, 0.15); color: var(--text-muted); }

        /* Dialog Modal styling for interpretations */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            z-index: 100;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .modal.active {
            display: flex;
            opacity: 1;
        }

        .modal-content {
            background: #0d131f;
            border: 1px solid var(--card-border);
            border-radius: 20px;
            width: 550px;
            padding: 28px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.8);
            transform: scale(0.9);
            transition: transform 0.3s ease;
            position: relative;
        }

        .modal.active .modal-content {
            transform: scale(1);
        }

        .close-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            font-size: 24px;
            color: var(--text-muted);
            cursor: pointer;
            transition: color 0.2s;
        }

        .close-btn:hover {
            color: var(--text-main);
        }

        .modal-header {
            margin-bottom: 20px;
        }

        .modal-header h3 {
            font-size: 22px;
            font-weight: 700;
            color: var(--text-main);
        }

        .modal-body {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .info-block {
            background: rgba(255,255,255,0.02);
            border-radius: 12px;
            padding: 14px;
            border-left: 4px solid var(--primary);
        }

        .info-block.block-danger {
            border-left-color: var(--danger);
            background: rgba(248, 113, 113, 0.03);
        }

        .info-block h4 {
            font-size: 13px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }

        .info-block p {
            font-size: 15px;
            line-height: 1.5;
            color: var(--text-main);
        }

        .interpret-banner {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 700;
            font-size: 15px;
            padding: 10px 14px;
            border-radius: 8px;
            margin-bottom: 8px;
        }

        /* Bandwidth Line Chart Grid */
        .bottom-section {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-section" style="cursor:pointer" onclick="window.location.href='/'">
            <h1>TCP<span>specter</span></h1>
            <p data-i18n="subtitle">Network Security Analytics &mdash; DLP + NDR + NTA + Explanation Engine</p>
        </div>
        <div style="display:flex; gap:16px; align-items:center;">
            <nav style="display:flex; gap:12px; margin-right: 16px; align-items: center;">
                <a href="/" style="color: var(--text-main); text-decoration: none; font-size: 14px; font-weight: 600;" data-i18n="nav_dashboard">Dashboard</a>
                <a href="/firewall" style="color: var(--text-main); text-decoration: none; font-size: 14px; font-weight: 600;" data-i18n="nav_firewall">Firewall & IDS</a>
                <a href="/logs" style="color: var(--text-main); text-decoration: none; font-size: 14px; font-weight: 600;" data-i18n="nav_logs">Logs</a>
                <a href="/configuration" style="color: var(--text-main); text-decoration: none; font-size: 14px; font-weight: 600;" data-i18n="nav_config">Configuración</a>
            </nav>
            <button id="security_toggle_btn"
                onclick="toggleSecurity()"
                style="background: rgba(52,211,153,0.15); color: #34d399; border: 1px solid #34d399;
                       padding: 6px 16px; border-radius: 8px; cursor: pointer; font-family: inherit;
                       font-size: 13px; font-weight: 600; letter-spacing: 0.05em;"
                data-i18n="btn_sec_active"
            >
                &#9679; ANALÍTICA ACTIVA
            </button>
            <div class="status-badge">
                <span class="status-dot"></span>
                <span data-i18n="status_live">Monitoreo en Vivo</span>
            </div>
            <div class="status-badge" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-main); font-weight: 500; gap: 12px;">
                <span>CPU: <span id="sys_cpu" style="color: var(--primary); font-weight: 700;">0.0%</span></span>
                <span style="border-left: 1px solid var(--card-border); padding-left: 12px;">RAM: <span id="sys_ram" style="color: var(--accent); font-weight: 700;">0.0%</span></span>
            </div>
        </div>
    </header>

    <!-- SPA Wrappers -->
    <div class="container">
    <!-- View: Dashboard -->
    <div id="view_dashboard" class="spa-view">
        <div class="dashboard-grid">
        <div class="card grid-span-2" onclick="showModuleHelp('security', event)">
            <div class="card-title" data-i18n="sec_analysis">Análisis de Seguridad de Red (C2 / Máquina Zombie)</div>
            <div class="security-score-container">
                <div class="score-circle" id="risk_gradient">
                    <div class="score-circle-inner">
                        <span class="score-num" id="risk_score">0</span>
                        <span class="score-lbl" data-i18n="score_lbl">Riesgo</span>
                    </div>
                </div>
                <div class="security-details">
                    <div>
                        <span class="text-muted" style="font-size: 13px;" data-i18n="sec_threat_level">Nivel de Amenaza:</span>
                        <span class="severity-badge" id="risk_level">CALCULANDO...</span>
                    </div>
                    <div class="detail-item"><span data-i18n="active_alerts_lbl">Alertas Activas:</span> <span class="detail-value text-main" id="findings_count">0</span></div>
                    <div class="formula-card" data-i18n="risk_formula">
                        <strong>Fórmula Heurística de Riesgo:</strong><br>
                        • Crítico (+40): Reverse Shell, C2, binario borrado<br>
                        • Alto (+25): Ejecución en /tmp, SUID con red<br>
                        • Medio (+10): Puerto abierto no confiable<br>
                        • Riesgo Máximo acotado a 100.
                    </div>
                </div>
            </div>
        </div>

        <!-- System Stats Pie Chart -->
        <div class="card" onclick="showModuleHelp('proto', event)">
            <div class="card-title" data-i18n="chart_proto_dist">Distribución de Protocolos</div>
            <div class="chart-container">
                <canvas id="protoChart"></canvas>
            </div>
        </div>

        <!-- Top CPU Processes Chart -->
        <div class="card" onclick="showModuleHelp('cpu', event)">
            <div class="card-title" data-i18n="chart_top_cpu">Top Procesos CPU (%)</div>
            <div class="chart-container">
                <canvas id="procChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Bandwidth History Chart, Entropy Chart & Security Alerts List -->
    <div class="dashboard-grid" style="grid-template-columns: 1.5fr 1.5fr 1fr; margin-bottom: 24px;">
        <div class="card" onclick="showModuleHelp('bandwidth', event)">
            <div class="card-title" data-i18n="chart_bandwidth">Tráfico de Red Histórico (Mbps)</div>
            <div class="chart-container-large">
                <canvas id="bandwidthChart"></canvas>
            </div>
        </div>
        <div class="card" onclick="showModuleHelp('entropy', event)">
            <div class="card-title">Entropía de Payload Histórica</div>
            <div class="chart-container-large">
                <canvas id="entropyChart"></canvas>
            </div>
        </div>
        <div class="card" style="display: flex; flex-direction: column;" onclick="showModuleHelp('alerts', event)">
            <div class="card-title" data-i18n="sec_alerts_active">Alertas C2 / Comportamientos Zombie</div>
            <div style="flex: 1; overflow-y: auto; max-height: 220px;" id="alerts_list">
                <div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 40px;" data-i18n="no_alerts">No se han detectado alertas de seguridad activas.</div>
            </div>
        </div>
    </div>

    <!-- DNS Tunneling & Heurísticas de Tráfico -->
    <div class="card" style="display: flex; flex-direction: column; margin-bottom: 24px;" onclick="showModuleHelp('dlp_ndr', event)">
        <div class="card-title">DNS Tunneling & Heurísticas de Tráfico</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 12px;">
            <div style="background: rgba(255,255,255,0.01); border: 1px solid var(--card-border); border-radius: 10px; padding: 10px; text-align: center;">
                <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Paquetes Sniffeados</div>
                <div id="scapy_packet_count" style="font-size: 20px; font-weight: 700; color: var(--primary); margin-top: 4px;">0</div>
            </div>
            <div style="background: rgba(255,255,255,0.01); border: 1px solid var(--card-border); border-radius: 10px; padding: 10px; text-align: center;">
                <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Entropía de Payload</div>
                <div id="scapy_avg_entropy" style="font-size: 20px; font-weight: 700; color: var(--accent); margin-top: 4px;">0.00</div>
            </div>
        </div>
        <div style="flex: 1; overflow-y: auto; max-height: 180px;">
            <strong style="font-size: 13px; color: var(--text-muted); display: block; margin-bottom: 8px; text-transform: uppercase;">Alertas de Tráfico / DNS / DLP:</strong>
            <div id="dns_dlp_alerts" style="display: flex; flex-direction: column; gap: 8px;">
                <div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 20px; font-size: 12px;">No hay alertas en tiempo real de Scapy/DNS.</div>
            </div>
        </div>
    </div>
</div> <!-- End View: Dashboard -->

    <!-- View: Firewall -->
    <div id="view_firewall" class="spa-view" style="display:none;">
        <!-- Firewall & Snort Enterprise Panel -->
        <div class="card" style="margin-bottom: 24px;" onclick="showModuleHelp('ids_fw', event)">
        <div class="connections-header" style="margin-bottom: 16px; border-bottom: 1px solid var(--card-border); padding-bottom: 12px;">
            <div class="connections-title">
                <h2 data-i18n="fw_title" style="font-size: 18px; color: var(--text-main); margin: 0;">Network Security Policies (Firewall & IDS)</h2>
                <p data-i18n="fw_subtitle" style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Configuración avanzada de interfaces, IPS y filtrado de red</p>
            </div>
            <div style="display: flex; gap: 12px; align-items: center;">
                <div style="display: flex; flex-direction: column; align-items: flex-end; margin-right: 12px;">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <strong data-i18n="fw_snort_lbl" style="font-size: 12px; color: var(--text-muted);">Servicio Snort:</strong>
                        <span id="snort_badge" class="severity-badge sev-bajo" style="font-size: 10px;">Cargando...</span>
                    </div>
                    <div id="snort_info" style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Detectando estado...</div>
                </div>
                <button id="install_snort_btn" onclick="installSnort()" style="display: none; background: rgba(74, 122, 157, 0.15); border: 1px solid var(--primary); color: var(--text-main); padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; transition: all 0.2s;" data-i18n="fw_install_btn">Instalar Snort</button>
                <button id="toggle_snort_btn" onclick="toggleSnort()" style="background: rgba(255,255,255,0.05); border: 1px solid var(--card-border); color: var(--text-main); padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; transition: all 0.2s;" data-i18n="fw_toggle_btn">Iniciar/Detener</button>
            </div>
        </div>

        <!-- Enterprise Rule Builder -->
        <div style="background: rgba(13, 19, 31, 0.4); border: 1px solid var(--card-border); border-radius: 8px; padding: 16px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <strong data-i18n="fw_builder_title" style="font-size: 14px; color: var(--primary);">+ Nueva Regla de Cortafuegos (Rule Builder)</strong>
                <div style="display: flex; gap: 8px;">
                    <input type="text" id="block_ip_input" placeholder="Quick Block: IP a bloquear" style="width: 220px; background: rgba(17, 24, 39, 0.8); border: 1px solid var(--card-border); border-radius: 6px; padding: 6px 12px; color: var(--text-main); outline: none; font-size: 12px;">
                    <button onclick="blockIP()" style="background: rgba(248, 113, 113, 0.15); border: 1px solid var(--danger); color: var(--danger); padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600;" data-i18n="fw_drop_btn">Drop (Quick)</button>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; align-items: end;">
                <div>
                    <label data-i18n="fw_action_lbl" style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px; font-weight: 600;">Acción *</label>
                    <select id="rb_action" style="width: 100%; background: rgba(17, 24, 39, 0.8); border: 1px solid var(--card-border); border-radius: 6px; padding: 8px; color: var(--text-main); font-size: 12px; outline: none; cursor: pointer;">
                        <option value="DENY" data-i18n="fw_opt_deny">Bloquear (DENY)</option>
                        <option value="ALLOW" data-i18n="fw_opt_allow">Permitir (ALLOW)</option>
                    </select>
                </div>
                <div>
                    <label data-i18n="fw_proto_lbl" style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px; font-weight: 600;">Protocolo</label>
                    <select id="rb_protocol" style="width: 100%; background: rgba(17, 24, 39, 0.8); border: 1px solid var(--card-border); border-radius: 6px; padding: 8px; color: var(--text-main); font-size: 12px; outline: none; cursor: pointer;">
                        <option value="all">ALL</option>
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                        <option value="icmp">ICMP</option>
                    </select>
                </div>
                <div>
                    <label data-i18n="fw_src_lbl" style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px; font-weight: 600;">IP Origen</label>
                    <input type="text" id="rb_src_ip" placeholder="Cualquiera" style="width: 100%; background: rgba(17, 24, 39, 0.8); border: 1px solid var(--card-border); border-radius: 6px; padding: 8px; color: var(--text-main); font-size: 12px; outline: none;">
                </div>
                <div>
                    <label data-i18n="fw_dst_lbl" style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px; font-weight: 600;">IP Destino</label>
                    <input type="text" id="rb_dst_ip" placeholder="Cualquiera" style="width: 100%; background: rgba(17, 24, 39, 0.8); border: 1px solid var(--card-border); border-radius: 6px; padding: 8px; color: var(--text-main); font-size: 12px; outline: none;">
                </div>
                <div>
                    <label data-i18n="fw_port_lbl" style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px; font-weight: 600;">Puerto</label>
                    <input type="number" id="rb_port" placeholder="Todos" style="width: 100%; background: rgba(17, 24, 39, 0.8); border: 1px solid var(--card-border); border-radius: 6px; padding: 8px; color: var(--text-main); font-size: 12px; outline: none;">
                </div>
                <div>
                    <button onclick="addCustomRule()" style="width: 100%; background: rgba(74, 122, 157, 0.2); border: 1px solid var(--primary); color: var(--text-main); padding: 9px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; transition: background 0.2s;" data-i18n="fw_apply_btn">Aplicar Regla</button>
                </div>
            </div>
        </div>

        <!-- Active Rules Table -->
        <div style="margin-top: 16px;">
            <strong data-i18n="fw_active_rules_lbl" style="font-size: 14px; display: block; margin-bottom: 12px; color: var(--text-main);">Reglas Cortafuegos Activas:</strong>
            <div class="table-container" style="max-height: 250px; border: 1px solid var(--card-border); border-radius: 8px; overflow: hidden;">
                <table style="font-size: 12px; width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: rgba(17, 24, 39, 0.9); border-bottom: 1px solid var(--card-border);">
                            <th data-i18n="fw_tbl_rule" style="padding: 12px; text-align: left; color: var(--text-muted); font-weight: 600;">Regla / IP Afectada</th>
                            <th data-i18n="fw_tbl_backend" style="padding: 12px; text-align: left; color: var(--text-muted); font-weight: 600;">Gestor (Backend)</th>
                            <th data-i18n="fw_tbl_policy" style="padding: 12px; text-align: left; color: var(--text-muted); font-weight: 600;">Política (Target)</th>
                            <th data-i18n="fw_tbl_action" style="padding: 12px; text-align: left; color: var(--text-muted); font-weight: 600; width: 100px;">Acción</th>
                        </tr>
                    </thead>
                    <tbody id="firewall_tbody">
                        <tr>
                            <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px 0;" data-i18n="fw_tbl_loading">Cargando reglas...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div> <!-- End View: Firewall -->

    <!-- Shared Map & Connections Container -->
    <div id="shared_monitoring">

    <!-- Cyber-Node Global Map Section -->
    <div class="card" style="margin-bottom: 24px;" onclick="showModuleHelp('map', event)">
        <div class="connections-header" style="margin-bottom: 0; display: flex; justify-content: space-between; align-items: center;">
            <div class="connections-title">
                <h2 data-i18n="map_title">Mapa Global de Conexiones</h2>
                <p data-i18n="map_desc" style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Análisis de Nodos de Tráfico en Tiempo Real</p>
            </div>
            <button onclick="resetMapView(); event.stopPropagation();" style="background: rgba(74, 122, 157, 0.15); border: 1px solid var(--primary); color: var(--text-main); padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600;" data-i18n="map_recenter_btn">Recentrar Mapa</button>
        </div>
        <div id="globeChart" style="width: 100%; height: 500px;"></div>
    </div>

    <!-- Active Connections Table Section -->
    <div class="card" onclick="showModuleHelp('connections', event)">
        <div class="connections-header">
            <div class="connections-title">
                <h2 data-i18n="conns_title">Conexiones del Sistema Activas</h2>
                <p data-i18n="conns_desc" style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Selecciona cualquier fila para traducir e interpretar lo que está pasando en la red.</p>
            </div>
            <div class="search-box">
                <input type="text" class="search-input" id="search_bar" placeholder="Buscar (proceso, PID, IP, puerto, estado)..." oninput="filterTable()">
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th data-i18n="hdr_proc">Proceso</th>
                        <th data-i18n="hdr_pid">PID</th>
                        <th data-i18n="hdr_proto">Proto</th>
                        <th data-i18n="hdr_src_ip">IP Origen</th>
                        <th data-i18n="hdr_src_port">Pto Orig.</th>
                        <th data-i18n="hdr_dst_ip">IP Destino</th>
                        <th data-i18n="hdr_dst_port">Pto Dest.</th>
                        <th data-i18n="hdr_status">Estado</th>
                        <th data-i18n="hdr_eval">Evaluación</th>
                    </tr>
                </thead>
                <tbody id="connections_tbody">
                    <tr>
                        <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 40px 0;" data-i18n="conns_loading">Cargando conexiones del sistema...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    </div> <!-- End Shared Monitoring -->

    <!-- View: Configuration -->
    <div id="view_configuration" class="spa-view" style="display:none;">
        <div class="card" style="margin-bottom: 24px;">
            <h2 data-i18n="config_title" style="margin-bottom: 16px;">Configuración del Sistema</h2>
            
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); padding: 16px; border-radius: 12px; margin-bottom: 16px;">
                <h3 data-i18n="config_lang">Idioma / Language</h3>
                <p data-i18n="config_lang_desc" style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Selecciona el idioma de la interfaz gráfica.</p>
                <div style="display: flex; gap: 12px;">
                    <button class="lang-btn" data-lang="es" onclick="changeLanguage('es')" style="background: rgba(74, 122, 157, 0.15); border: 1px solid var(--primary); color: var(--text-main); padding: 8px 24px; border-radius: 8px; cursor: pointer; font-weight: 600;">Español</button>
                    <button class="lang-btn" data-lang="en" onclick="changeLanguage('en')" style="background: rgba(255,255,255,0.05); border: 1px solid var(--card-border); color: var(--text-main); padding: 8px 24px; border-radius: 8px; cursor: pointer; font-weight: 600;">English</button>
                </div>
            </div>

            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); padding: 16px; border-radius: 12px;">
                <h3 data-i18n="config_tutorial">Tutoriales y Documentación</h3>
                <p data-i18n="config_tutorial_desc" style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Aprende cómo usar TCPspecter y explorar sus capacidades.</p>
                <a href="/tutorial" style="display: inline-block; background: rgba(52, 211, 153, 0.15); border: 1px solid var(--success); color: var(--success); padding: 8px 24px; border-radius: 8px; cursor: pointer; font-weight: 600; text-decoration: none;" data-i18n="config_tutorial_btn">Ver Tutorial Interactivo</a>
            </div>
        </div>
    </div> <!-- End View: Configuration -->
    </div> <!-- End Container -->

    <!-- Interpretation Dialog Modal -->
    <div class="modal" id="interpret_modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal()">&times;</span>
            <div class="modal-header">
                <h3 id="modal_proc_title" data-i18n="modal_title">Interpretación de Conexión</h3>
                <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;" id="modal_socket_title">PID: - | TCP | -</p>
            </div>
            <div class="modal-body">
                <div class="interpret-banner" id="modal_banner">
                    Evaluación de Riesgo: -
                </div>
                <div class="info-block" id="modal_ip_block">
                    <h4 data-i18n="modal_ip_scope">Ámbito de la IP Destino</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_port_block">
                    <h4 data-i18n="modal_port_purpose">Propósito del Puerto</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_status_block">
                    <h4 data-i18n="modal_conn_state">Estado de la Conexión</h4>
                    <p>-</p>
                </div>
                <div class="info-block block-danger" id="modal_danger_block">
                    <h4 data-i18n="modal_sec_analysis">Análisis de Seguridad Detallado</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_recommendation_block">
                    <h4 data-i18n="modal_recs">Recomendaciones</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_educational_block">
                    <h4 data-i18n="modal_edu">Contexto Educativo</h4>
                    <p>-</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let protoChart = null;
        let procChart = null;
        let bandwidthChart = null;
        let entropyChart = null;
        let globeChart = null;
        let bandwidthData = { rx: [], tx: [], labels: [] };
        let entropyHistoryData = { labels: [], values: [] };
        let allConnections = [];
        let geoIpCache = {}; // ip -> geo data or 'fetching' or 'local'
        let tracerouteCache = {}; // ip -> array of IPs or 'fetching'
        let localGeo = null; // Store real origin

        async function initGlobe() {
            try {
                // Fetch self-geo first
                const selfRes = await fetch('/api/self_geo');
                localGeo = await selfRes.json();
                if(!localGeo || localGeo.error) {
                    localGeo = {lon: 0, lat: 0, city: 'Unknown', country: 'Local'};
                }

                const res = await fetch('https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/json/world.json');
                const worldJson = await res.json();
                echarts.registerMap('world', worldJson);
                
                const chartDom = document.getElementById('globeChart');
                globeChart = echarts.init(chartDom);
                
                const option = {
                    backgroundColor: 'transparent',
                    geo: {
                        map: 'world',
                        roam: true,
                        zoom: 1.2,
                        scaleLimit: {
                            min: 1.0,
                            max: 8.0
                        },
                        itemStyle: {
                            areaColor: 'rgba(17, 24, 39, 0.8)',
                            borderColor: '#4a7a9d',
                            borderWidth: 1
                        },
                        emphasis: {
                            itemStyle: { areaColor: 'rgba(74, 122, 157, 0.4)' },
                            label: { show: false }
                        }
                    },
                    tooltip: {
                        trigger: 'item',
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        textStyle: { color: '#fff' },
                        formatter: function (params) {
                            if(params.seriesType === 'effectScatter') {
                                return `<strong>${params.data.name}</strong><br/>IP: ${params.data.ip}`;
                            }
                            return '';
                        }
                    },
                    series: [
                        {
                            type: 'lines',
                            coordinateSystem: 'geo',
                            zlevel: 1,
                            polyline: true, // IMPORTANT for drawing multiple hops
                            effect: {
                                show: true,
                                period: 4,
                                trailLength: 0.6,
                                symbolSize: 3
                            },
                            lineStyle: {
                                width: 0,
                                curveness: 0.2, // Still looks good with polylines
                                opacity: 0.5
                            },
                            data: []
                        },
                        {
                            type: 'effectScatter',
                            coordinateSystem: 'geo',
                            zlevel: 2,
                            rippleEffect: { brushType: 'stroke', scale: 4 },
                            symbolSize: 6,
                            itemStyle: { color: '#34d399' },
                            data: []
                        }
                    ]
                };
                globeChart.setOption(option);
            } catch (err) {
                console.error("Error cargando el mapa:", err);
            }
        }

        function resetMapView() {
            if (globeChart) {
                globeChart.setOption({
                    geo: {
                        zoom: 1.2,
                        center: null
                    }
                });
            }
        }

        function initCharts() {
            // Protocol Chart
            const ctxProto = document.getElementById('protoChart').getContext('2d');
            protoChart = new Chart(ctxProto, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'LISTEN'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#4a7a9d', '#f2e8c9', '#888888'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 11 } } }
                    }
                }
            });

            // Processes Chart
            const ctxProc = document.getElementById('procChart').getContext('2d');
            procChart = new Chart(ctxProc, {
                type: 'pie',
                data: {
                    labels: ['Ninguno'],
                    datasets: [{
                        data: [1],
                        backgroundColor: ['#4a7a9d', '#f2e8c9', '#888888', '#555555'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 } } }
                    }
                }
            });

            // Bandwidth Chart
            const ctxBand = document.getElementById('bandwidthChart').getContext('2d');
            bandwidthChart = new Chart(ctxBand, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Bajada (RX)',
                            data: [],
                            borderColor: '#34d399',
                            backgroundColor: 'rgba(52, 211, 153, 0.05)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Subida (TX)',
                            data: [],
                            borderColor: '#4a7a9d',
                            backgroundColor: 'rgba(74, 122, 157, 0.05)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } },
                        y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#9ca3af' } }
                    }
                }
            });

            // Entropy Chart
            const ctxEnt = document.getElementById('entropyChart').getContext('2d');
            entropyChart = new Chart(ctxEnt, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Entropía Promedio',
                        data: [],
                        borderColor: '#fbbf24',
                        backgroundColor: 'rgba(251, 191, 36, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } },
                        y: { min: 0, max: 8, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#9ca3af' } }
                    }
                }
            });
        }


        let currentFirewallBackend = 'none';

        async function refreshData() {
            try {
                const lang = localStorage.getItem('language') || 'en';
                const response = await fetch(`/api/data?lang=${lang}`);
                const data = await response.json();
                currentFirewallBackend = data.firewall.backend;

                // Update CPU & RAM headers
                const cpuEl = document.getElementById('sys_cpu');
                const ramEl = document.getElementById('sys_ram');
                if (cpuEl) cpuEl.innerText = `${data.cpu.toFixed(1)}%`;
                if (ramEl) {
                    const usedGb = (data.used_ram / (1024 * 1024 * 1024)).toFixed(2);
                    const totalGb = (data.total_ram / (1024 * 1024 * 1024)).toFixed(2);
                    ramEl.innerText = `${data.ram.toFixed(1)}% (${usedGb} GB / ${totalGb} GB)`;
                }

                // 1. Update Security Panel
                document.getElementById('risk_score').innerText = data.security.score;
                const circle = document.getElementById('risk_gradient');
                
                // Color mapping
                let riskColor = '#34d399';
                let riskClass = 'sev-bajo';
                if (data.security.score >= 60) {
                    riskColor = '#f87171';
                    riskClass = 'sev-critico';
                } else if (data.security.score >= 35) {
                    riskColor = '#fbbf24';
                    riskClass = 'sev-alto';
                } else if (data.security.score >= 15) {
                    riskColor = '#4a7a9d';
                    riskClass = 'sev-medio';
                }
                circle.style.background = `conic-gradient(${riskColor} ${data.security.score}%, #1e293b 0%)`;
                
                const riskLevelEl = document.getElementById('risk_level');
                riskLevelEl.innerText = data.security.risk_level;
                riskLevelEl.className = `severity-badge ${riskClass}`;

                document.getElementById('findings_count').innerText = data.security.findings.length;

                // 2. Update Alerts list
                const alertsList = document.getElementById('alerts_list');
                if (data.security.findings.length === 0) {
                    alertsList.innerHTML = `<div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 40px;">No se han detectado alertas de seguridad activas.</div>`;
                } else {
                    alertsList.innerHTML = data.security.findings.map(f => {
                        let fclass = 'sev-bajo';
                        if (f.severity === 'CRITICAL') fclass = 'sev-critico';
                        else if (f.severity === 'HIGH') fclass = 'sev-alto';
                        else if (f.severity === 'MEDIUM') fclass = 'sev-medio';
                        
                        const pidText = f.pid ? `PID ${f.pid}` : '';
                        const nameText = f.proc_name ? `(${f.proc_name})` : '';

                        return `
                            <div style="background: rgba(255,255,255,0.02); margin-bottom: 8px; padding: 10px; border-radius: 8px; border-left: 3px solid ${riskColor};">
                                <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                                    <span class="severity-badge ${fclass}" style="padding:1px 6px; font-size:10px;">${f.severity}</span>
                                    <span style="font-size:11px; color:var(--text-muted);">${pidText} ${nameText}</span>
                                </div>
                                <div style="font-size:13px; color:var(--text-main);">${f.description}</div>
                            </div>
                        `;
                    }).join('');
                }

                // 3. Update Charts
                // Protocol Pie Chart
                let tc = 0, uc = 0, lc = 0;
                data.connections.forEach(c => {
                    if (c.status === 'LISTEN') lc++;
                    else if (c.proto === 'TCP') tc++;
                    else if (c.proto === 'UDP') uc++;
                });
                protoChart.data.datasets[0].data = [tc, uc, lc];
                protoChart.update();

                // Process Pie Chart
                let procCpuMap = {};
                data.processes.forEach(p => {
                    if (p.cpu > 0) {
                        procCpuMap[p.name] = (procCpuMap[p.name] || 0) + p.cpu;
                    }
                });
                const procLabels = Object.keys(procCpuMap);
                const procValues = Object.values(procCpuMap);
                if (procLabels.length > 0) {
                    procChart.data.labels = procLabels;
                    procChart.data.datasets[0].data = procValues;
                } else {
                    procChart.data.labels = ['Sin actividad'];
                    procChart.data.datasets[0].data = [1];
                }
                procChart.update();

                // Bandwidth History Chart
                const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                bandwidthData.labels.push(timeStr);
                bandwidthData.rx.push(data.rx_speed);
                bandwidthData.tx.push(data.tx_speed);

                if (bandwidthData.labels.length > 15) {
                    bandwidthData.labels.shift();
                    bandwidthData.rx.shift();
                    bandwidthData.tx.shift();
                }

                bandwidthChart.data.labels = bandwidthData.labels;
                bandwidthChart.data.datasets[0].data = bandwidthData.rx;
                bandwidthChart.data.datasets[1].data = bandwidthData.tx;
                bandwidthChart.update();

                // Entropy History Chart
                entropyHistoryData.labels.push(timeStr);
                entropyHistoryData.values.push(data.scapy.avg_entropy);
                if (entropyHistoryData.labels.length > 15) {
                    entropyHistoryData.labels.shift();
                    entropyHistoryData.values.shift();
                }
                entropyChart.data.labels = entropyHistoryData.labels;
                entropyChart.data.datasets[0].data = entropyHistoryData.values;
                entropyChart.update();

                // Snort Status Update
                const snortBadge = document.getElementById('snort_badge');
                const snortInfo = document.getElementById('snort_info');
                const toggleSnortBtn = document.getElementById('toggle_snort_btn');
                const installBtn = document.getElementById('install_snort_btn');
                
                if (!data.snort.installed) {
                    snortBadge.innerText = 'NO INSTALADO';
                    snortBadge.className = 'severity-badge sev-alto';
                    snortInfo.innerText = 'Snort IDS no está instalado en el sistema.';
                    installBtn.style.display = 'inline-block';
                    toggleSnortBtn.style.display = 'none';
                } else {
                    installBtn.style.display = 'none';
                    toggleSnortBtn.style.display = 'inline-block';
                    if (data.snort.running) {
                        snortBadge.innerText = 'ACTIVO';
                        snortBadge.className = 'severity-badge sev-bajo';
                        snortInfo.innerText = 'Snort está ejecutándose en modo pasivo IDS.';
                        toggleSnortBtn.innerText = 'Detener Snort';
                        toggleSnortBtn.style.background = 'rgba(248, 113, 113, 0.1)';
                        toggleSnortBtn.style.borderColor = 'var(--danger)';
                        toggleSnortBtn.style.color = 'var(--danger)';
                    } else {
                        snortBadge.innerText = 'INACTIVO';
                        snortBadge.className = 'severity-badge sev-medio';
                        snortInfo.innerText = 'El servicio Snort está detenido.';
                        toggleSnortBtn.innerText = 'Iniciar Snort';
                        toggleSnortBtn.style.background = 'rgba(52, 211, 153, 0.1)';
                        toggleSnortBtn.style.borderColor = 'var(--success)';
                        toggleSnortBtn.style.color = 'var(--success)';
                    }
                }

                // Firewall blocked rules table update
                const fwTbody = document.getElementById('firewall_tbody');
                if (data.firewall.blocked_ips.length === 0) {
                    fwTbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px 0; border-bottom: 1px solid var(--card-border);">Ninguna política activa encontrada.</td></tr>`;
                } else {
                    fwTbody.innerHTML = data.firewall.blocked_ips.map(rule => {
                        return `
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
                                <td style="padding: 12px; font-weight: 600; color: var(--danger);">${rule.ip}</td>
                                <td style="padding: 12px; color: var(--text-main);">${rule.backend}</td>
                                <td style="padding: 12px; color: var(--text-main);">
                                    <span style="background: rgba(248, 113, 113, 0.1); color: var(--danger); padding: 2px 6px; border-radius: 4px; font-size: 10px;">${rule.target}</span>
                                </td>
                                <td style="padding: 12px;">
                                    <button onclick="unblockIP('${rule.ip}')" style="background: rgba(52, 211, 153, 0.1); border: 1px solid var(--success); color: var(--success); padding: 4px 8px; border-radius: 4px; font-size: 11px; cursor: pointer; transition: all 0.2s;">Desbloquear</button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                }

                // Scapy Metrics and Alerts
                document.getElementById('scapy_packet_count').innerText = data.scapy.stats.packet_count;
                document.getElementById('scapy_avg_entropy').innerText = data.scapy.avg_entropy.toFixed(2);
                
                const dnsDlpAlerts = document.getElementById('dns_dlp_alerts');
                const combinedAlerts = [...data.scapy.dns_alerts, ...data.scapy.dlp_alerts];
                
                combinedAlerts.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
                
                if (combinedAlerts.length === 0) {
                    dnsDlpAlerts.innerHTML = `<div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 20px; font-size: 12px;">No hay alertas en tiempo real de Scapy/DNS.</div>`;
                } else {
                    dnsDlpAlerts.innerHTML = combinedAlerts.map(alert => {
                        let color = '#fbbf24'; 
                        let typeLabel = alert.category || 'ALERTA';
                        
                        if (typeLabel.includes('TÚNEL') || typeLabel.includes('ENTROPÍA') || typeLabel.includes('Reverse Shell')) {
                            color = '#f87171';
                        }
                        
                        const desc = alert.description;
                        const queryInfo = alert.query ? ` [Query: ${alert.query}]` : '';
                        
                        return `
                            <div style="background: rgba(255,255,255,0.02); padding: 8px; border-radius: 6px; border-left: 3px solid ${color}; font-size: 11px;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                                    <span style="color: ${color}; font-weight: 600; text-transform: uppercase;">${typeLabel}</span>
                                    <span style="color: var(--text-muted);">${alert.timestamp}</span>
                                </div>
                                <div style="color: var(--text-main); font-size: 12px;">${desc}${queryInfo}</div>
                            </div>
                        `;
                    }).join('');
                }

                // 4. Update Connections Table
                allConnections = data.connections;
                filterTable();

                // 5. Update Map Data (Traceroutes and Hops)
                const uniqueRemoteIPs = [...new Set(data.connections.map(c => c.raddr_ip).filter(ip => ip && ip !== '-' && ip !== '0.0.0.0' && ip !== '127.0.0.1'))];
                const fetchPromises = [];
                
                uniqueRemoteIPs.forEach(ip => {
                    // Fetch traceroute hops
                    if (!tracerouteCache[ip]) {
                        tracerouteCache[ip] = 'fetching';
                        fetchPromises.push(
                            fetch(`/api/traceroute?ip=${ip}`).then(r => r.json()).then(hops => {
                                tracerouteCache[ip] = hops || [];
                                // Kick off geoip fetch for all new hops
                                (hops || []).forEach(hop_ip => {
                                    if(!geoIpCache[hop_ip]) {
                                        geoIpCache[hop_ip] = 'fetching';
                                        fetchPromises.push(
                                            fetch(`/api/geoip?ip=${hop_ip}`).then(r => r.json()).then(geo => {
                                                geoIpCache[hop_ip] = (geo && !geo.is_local) ? geo : 'local';
                                            }).catch(()=> geoIpCache[hop_ip] = 'local')
                                        );
                                    }
                                });
                            }).catch(() => {
                                tracerouteCache[ip] = [ip]; // fallback to direct
                            })
                        );
                    }
                    
                    // Also make sure dest IP geo is fetching
                    if (!geoIpCache[ip]) {
                        geoIpCache[ip] = 'fetching';
                        fetchPromises.push(
                            fetch(`/api/geoip?ip=${ip}`).then(r => r.json()).then(geo => {
                                geoIpCache[ip] = (geo && !geo.is_local) ? geo : 'local';
                            }).catch(() => {
                                geoIpCache[ip] = 'local';
                            })
                        );
                    }
                });

                if (fetchPromises.length > 0) {
                    await Promise.all(fetchPromises);
                }

                if (globeChart && localGeo) {
                    const linesData = [];
                    const scatterData = [];
                    
                    // Center local node
                    scatterData.push({ name: `${localGeo.city}, ${localGeo.country}`, ip: localGeo.ip || '127.0.0.1', value: [localGeo.lon, localGeo.lat], itemStyle: { color: '#4a7a9d' } });

                    data.connections.forEach(c => {
                        const destIp = c.raddr_ip;
                        if(destIp === '-' || destIp === '0.0.0.0' || destIp === '127.0.0.1') return;
                        
                        const destGeo = geoIpCache[destIp];
                        if (destGeo && destGeo !== 'local' && destGeo !== 'fetching') {
                            let color = '#34d399'; // Normal
                            if (c.interpretation && c.interpretation.assessment.includes('CRÍTICO')) {
                                color = '#f87171'; // Danger
                            } else if (c.interpretation && c.interpretation.assessment.includes('REVISAR')) {
                                color = '#fbbf24'; // Warning
                            }
                            
                            // Add destination node
                            scatterData.push({
                                name: `${destGeo.city}, ${destGeo.country}`,
                                ip: destIp,
                                value: [destGeo.lon, destGeo.lat],
                                itemStyle: { color: color }
                            });
                            
                            // Build polyline coordinates
                            const hops = tracerouteCache[destIp];
                            let coords = [[localGeo.lon, localGeo.lat]];
                            
                            if (Array.isArray(hops)) {
                                hops.forEach(hop_ip => {
                                    const hGeo = geoIpCache[hop_ip];
                                    if (hGeo && hGeo !== 'local' && hGeo !== 'fetching') {
                                        coords.push([hGeo.lon, hGeo.lat]);
                                        // Also add hop point to scatter so it glows too, but smaller
                                        if (hop_ip !== destIp) {
                                            scatterData.push({
                                                name: `${hGeo.city}, ${hGeo.country} (Hop)`,
                                                ip: hop_ip,
                                                value: [hGeo.lon, hGeo.lat],
                                                symbolSize: 3,
                                                itemStyle: { color: '#4a7a9d' }
                                            });
                                        }
                                    }
                                });
                            }
                            
                            // Ensure destination is the last point if not already
                            const lastCoord = coords[coords.length - 1];
                            if (!lastCoord || lastCoord[0] !== destGeo.lon || lastCoord[1] !== destGeo.lat) {
                                coords.push([destGeo.lon, destGeo.lat]);
                            }

                            linesData.push({
                                coords: coords,
                                lineStyle: { color: color }
                            });
                        }
                    });

                    // Remove duplicates in scatterData by coordinates to avoid double rendering
                    const uniqueScatter = [];
                    const seenCoords = new Set();
                    scatterData.forEach(pt => {
                        const key = `${pt.value[0]},${pt.value[1]}`;
                        if(!seenCoords.has(key)) {
                            seenCoords.add(key);
                            uniqueScatter.push(pt);
                        }
                    });

                    globeChart.setOption({
                        series: [
                            {
                                type: 'lines',
                                coordinateSystem: 'geo',
                                data: linesData
                            },
                            {
                                type: 'effectScatter',
                                coordinateSystem: 'geo',
                                data: uniqueScatter
                            }
                        ]
                    });
                }

            } catch (err) {
                console.error("Error al refrescar información del backend:", err);
            }
        }

        function filterTable() {
            const query = document.getElementById('search_bar').value.toLowerCase().trim();
            const tbody = document.getElementById('connections_tbody');
            
            const filtered = allConnections.filter(c => {
                if (!query) return true;
                return (
                    (c.name || '').toLowerCase().includes(query) ||
                    String(c.pid || '').includes(query) ||
                    (c.proto || '').toLowerCase().includes(query) ||
                    (c.laddr_ip || '').toLowerCase().includes(query) ||
                    String(c.laddr_port || '').includes(query) ||
                    (c.raddr_ip || '').toLowerCase().includes(query) ||
                    String(c.raddr_port || '').includes(query) ||
                    (c.status || '').toLowerCase().includes(query)
                );
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 40px 0;">No se encontraron conexiones que coincidan.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map((c, idx) => {
                let statusBadge = 'badge-other';
                if (c.status === 'ESTABLISHED') statusBadge = 'badge-established';
                else if (c.status === 'LISTEN') statusBadge = 'badge-listen';

                let evalClass = 'sev-bajo';
                if (c.interpretation.assessment.includes('CRÍTICO')) evalClass = 'sev-critico';
                else if (c.interpretation.assessment.includes('REVISAR')) evalClass = 'sev-alto';

                const nameText = c.name || '-';
                const pidText = c.pid || '-';

                return `
                    <tr onclick="openModal(${idx})">
                        <td><strong>${nameText}</strong></td>
                        <td>${pidText}</td>
                        <td>${c.proto}</td>
                        <td>${c.laddr_ip}</td>
                        <td>${c.laddr_port}</td>
                        <td>${c.raddr_ip}</td>
                        <td>${c.raddr_port}</td>
                        <td><span class="badge-status ${statusBadge}">${c.status}</span></td>
                        <td><span class="severity-badge ${evalClass}" style="padding: 2px 6px; font-size: 11px;">${c.interpretation.assessment}</span></td>
                    </tr>
                `;
            }).join('');
        }

        function openModal(idx) {
            const conn = allConnections[idx];
            if (!conn) return;
            const lang = localStorage.getItem('language') || 'en';

            if (lang === 'es') {
                document.getElementById('modal_proc_title').innerText = `Interpretación de '${conn.name}'`;
                document.getElementById('modal_socket_title').innerText = `PID: ${conn.pid} | Protocolo: ${conn.proto} | IP Destino: ${conn.raddr_ip}:${conn.raddr_port}`;
            } else {
                document.getElementById('modal_proc_title').innerText = `Interpretation of '${conn.name}'`;
                document.getElementById('modal_socket_title').innerText = `PID: ${conn.pid} | Protocol: ${conn.proto} | Destination IP: ${conn.raddr_ip}:${conn.raddr_port}`;
            }
            
            const banner = document.getElementById('modal_banner');
            if (lang === 'es') {
                banner.innerText = `Evaluación: ${conn.interpretation.assessment}`;
            } else {
                banner.innerText = `Assessment: ${conn.interpretation.assessment}`;
            }
            
            let bannerBg = 'rgba(52, 211, 153, 0.15)';
            let bannerColor = 'var(--success)';
            if (conn.interpretation.assessment.includes('CRÍTICO') || conn.interpretation.assessment.includes('CRITICAL')) {
                bannerBg = 'rgba(248, 113, 113, 0.15)';
                bannerColor = 'var(--danger)';
            } else if (conn.interpretation.assessment.includes('REVISAR') || conn.interpretation.assessment.includes('SUSPICIOUS')) {
                bannerBg = 'rgba(251, 191, 36, 0.15)';
                bannerColor = 'var(--warning)';
            }
            banner.style.background = bannerBg;
            banner.style.color = bannerColor;

            document.getElementById('modal_ip_block').querySelector('p').innerText = conn.interpretation.ip_desc;
            document.getElementById('modal_port_block').querySelector('p').innerText = conn.interpretation.port_desc;
            document.getElementById('modal_status_block').querySelector('p').innerText = conn.interpretation.status_desc;
            document.getElementById('modal_danger_block').querySelector('p').innerText = conn.interpretation.explanation;
            
            const recs = conn.interpretation.recommendations || [];
            if (recs.length > 0) {
                document.getElementById('modal_recommendation_block').querySelector('p').innerText = `• ${recs.join('\\n• ')}`;
            } else {
                document.getElementById('modal_recommendation_block').querySelector('p').innerText = lang === 'es' ? "No hay recomendaciones específicas." : "No specific recommendations.";
            }
            
            document.getElementById('modal_educational_block').querySelector('p').innerText = conn.interpretation.educational || "-";

            document.getElementById('interpret_modal').classList.add('active');
        }

        function closeModal() {
            document.getElementById('interpret_modal').classList.remove('active');
        }

        async function toggleSecurity() {
            const res = await fetch('/api/toggle_security', {method: 'POST'});
            const data = await res.json();
            const btn = document.getElementById('security_toggle_btn');
            if (data.enabled) {
                btn.style.background = 'rgba(52,211,153,0.15)';
                btn.style.color = '#34d399';
                btn.style.border = '1px solid #34d399';
                btn.innerHTML = '&#9679; ANALÍTICA ACTIVA';
            } else {
                btn.style.background = 'rgba(136,136,136,0.1)';
                btn.style.color = '#888888';
                btn.style.border = '1px solid #444444';
                btn.innerHTML = '&#9675; ANALÍTICA DESACTIVADA';
            }
        }

        async function installSnort() {
            const lang = localStorage.getItem('language') || 'en';
            let warnMsg = lang === 'es'
                ? '¿Estás seguro de que deseas instalar Snort? Se realizará de forma no interactiva (apt-get install -y snort).'
                : 'Are you sure you want to install Snort? It will be done non-interactively (apt-get install -y snort).';
            if (currentFirewallBackend !== 'none') {
                warnMsg = lang === 'es'
                    ? '⚠️ ADVERTENCIA: Se ha detectado un Firewall activo (' + currentFirewallBackend.toUpperCase() + ') en el sistema. La instalación de Snort puede interferir con la captura de paquetes o requerir reglas adicionales de filtrado para no bloquear tráfico legítimo.\\n\\n' + warnMsg
                    : '⚠️ WARNING: An active Firewall (' + currentFirewallBackend.toUpperCase() + ') has been detected on the system. Installing Snort may interfere with packet capture or require additional filtering rules to avoid blocking legitimate traffic.\\n\\n' + warnMsg;
            }
            if (!confirm(warnMsg)) {
                return;
            }
            const btn = document.getElementById('install_snort_btn');
            btn.innerText = lang === 'es' ? 'Instalando...' : 'Installing...';
            btn.disabled = true;
            try {
                const res = await fetch('/api/install_snort', { method: 'POST' });
                const data = await res.json();
                alert(data.message);
            } catch(e) {
                alert((lang === 'es' ? 'Error al instalar Snort: ' : 'Error installing Snort: ') + e);
            } finally {
                refreshData();
            }
        }

        async function toggleSnort() {
            const lang = localStorage.getItem('language') || 'en';
            try {
                const res = await fetch('/api/toggle_snort', { method: 'POST' });
                const data = await res.json();
                if (!data.success) {
                    alert(lang === 'es'
                        ? 'Operación fallida. Asegúrate de ejecutar tcpspecter con privilegios de root/sudo.'
                        : 'Operation failed. Make sure to run tcpspecter with root/sudo privileges.');
                }
            } catch(e) {
                alert((lang === 'es' ? 'Error al alternar Snort: ' : 'Error toggling Snort: ') + e);
            } finally {
                refreshData();
            }
        }

        async function blockIP(ip) {
            const lang = localStorage.getItem('language') || 'en';
            const ipToBlock = ip || document.getElementById('block_ip_input').value.trim();
            if (!ipToBlock) return;
            
            const confirmMsg = lang === 'es'
                ? `¿Bloquear tráfico de la IP ${ipToBlock}?`
                : `Block traffic from IP ${ipToBlock}?`;
            if (!confirm(confirmMsg)) return;
            
            try {
                const res = await fetch('/api/block_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ipToBlock })
                });
                const data = await res.json();
                if (data.success) {
                    if (!ip) document.getElementById('block_ip_input').value = '';
                } else {
                    alert(lang === 'es'
                        ? 'Error al bloquear la IP. ¿Tienes permisos sudo?'
                        : 'Error blocking IP. Do you have sudo privileges?');
                }
            } catch(e) {
                alert('Error: ' + e);
            } finally {
                refreshData();
            }
        }

        async function unblockIP(ip) {
            const lang = localStorage.getItem('language') || 'en';
            if (!ip) return;
            const confirmMsg = lang === 'es'
                ? `¿Desbloquear tráfico de la IP ${ip}?`
                : `Unblock traffic from IP ${ip}?`;
            if (!confirm(confirmMsg)) return;
            
            try {
                const res = await fetch('/api/unblock_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                const data = await res.json();
                if (!data.success) {
                    alert(lang === 'es'
                        ? 'Error al desbloquear la IP. ¿Tienes permisos sudo?'
                        : 'Error unblocking IP. Do you have sudo privileges?');
                }
            } catch(e) {
                alert('Error: ' + e);
            } finally {
                refreshData();
            }
        }

        async function addCustomRule() {
            const lang = localStorage.getItem('language') || 'en';
            const action = document.getElementById('rb_action').value;
            const protocol = document.getElementById('rb_protocol').value;
            const src_ip = document.getElementById('rb_src_ip').value.trim();
            const dst_ip = document.getElementById('rb_dst_ip').value.trim();
            const port = document.getElementById('rb_port').value.trim();
            
            const confirmMsg = lang === 'es'
                ? `¿Aplicar nueva regla de firewall?\nAcción: ${action}\nProtocolo: ${protocol}\nOrigen: ${src_ip || 'Cualquiera'}\nDestino: ${dst_ip || 'Cualquiera'}\nPuerto: ${port || 'Todos'}`
                : `Apply new firewall rule?\nAction: ${action}\nProtocol: ${protocol}\nSource: ${src_ip || 'Any'}\nDestination: ${dst_ip || 'Any'}\nPort: ${port || 'All'}`;
            if (!confirm(confirmMsg)) return;
            
            try {
                const res = await fetch('/api/firewall/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.csrfToken || '' },
                    body: JSON.stringify({ action, protocol, src_ip, dst_ip, port })
                });
                const data = await res.json();
                if (data.success) {
                    document.getElementById('rb_src_ip').value = '';
                    document.getElementById('rb_dst_ip').value = '';
                    document.getElementById('rb_port').value = '';
                    alert(lang === 'es'
                        ? 'Regla de firewall aplicada correctamente.'
                        : 'Firewall rule applied successfully.');
                } else {
                    const fallbackError = lang === 'es' ? 'Operación fallida. ¿Tienes permisos sudo?' : 'Operation failed. Do you have sudo privileges?';
                    alert('Error: ' + (data.error || fallbackError));
                }
            } catch(e) {
                alert('Error: ' + e);
            } finally {
                refreshData();
            }
        }

        const translations = {
            es: {
                subtitle: "Network Security Analytics — DLP + NDR + NTA + Engine de Explicación",
                nav_tutorial: "📖 Tutorial",
                nav_logs: "📄 Logs de Seguridad",
                btn_sec_active: "● ANALÍTICA ACTIVA",
                btn_sec_inactive: "○ ANALÍTICA DESACTIVADA",
                status_live: "Monitoreo en Vivo",
                sec_analysis: "Análisis de Seguridad de Red (C2 / Máquina Zombie)",
                score_lbl: "Riesgo",
                sec_threat_level: "Nivel de Amenaza:",
                active_alerts_lbl: "Alertas Activas:",
                risk_formula: "<strong>Fórmula Heurística de Riesgo:</strong><br>• Crítico (+40): Reverse Shell, C2, binario borrado<br>• Alto (+25): Ejecución en /tmp, SUID con red<br>• Medio (+10): Puerto abierto no confiable<br>• Riesgo Máximo acotado a 100.",
                chart_proto_dist: "Distribución de Protocolos",
                chart_top_cpu: "Top Procesos CPU (%)",
                chart_bandwidth: "Tráfico de Red Histórico (Mbps)",
                sec_alerts_active: "Alertas C2 / Comportamientos Zombie",
                no_alerts: "No se han detectado alertas de seguridad activas.",
                no_conns: "No se encontraron conexiones que coincidan.",
                nav_dashboard: "Dashboard",
                nav_firewall: "Cortafuegos e IDS",
                nav_logs: "📄 Logs de Seguridad",
                nav_config: "Configuración",
                config_title: "Configuración del Sistema",
                config_lang: "Idioma / Language",
                config_lang_desc: "Selecciona el idioma de la interfaz gráfica.",
                config_tutorial: "Tutoriales y Documentación",
                config_tutorial_desc: "Aprende cómo usar TCPspecter y explorar sus capacidades.",
                config_tutorial_btn: "Ver Tutorial Interactivo",
                // Firewall view keys
                fw_title: "Políticas de Seguridad de Red (Firewall e IDS)",
                fw_subtitle: "Configuración avanzada de interfaces, IPS y filtrado de red",
                fw_snort_lbl: "Servicio Snort:",
                fw_install_btn: "Instalar Snort",
                fw_toggle_btn: "Iniciar/Detener",
                fw_builder_title: "+ Nueva Regla de Cortafuegos (Rule Builder)",
                fw_drop_btn: "Bloquear (Quick)",
                fw_action_lbl: "Acción *",
                fw_opt_deny: "Bloquear (DENY)",
                fw_opt_allow: "Permitir (ALLOW)",
                fw_proto_lbl: "Protocolo",
                fw_src_lbl: "IP Origen",
                fw_dst_lbl: "IP Destino",
                fw_port_lbl: "Puerto",
                fw_apply_btn: "Aplicar Regla",
                fw_active_rules_lbl: "Reglas Cortafuegos Activas:",
                fw_tbl_rule: "Regla / IP Afectada",
                fw_tbl_backend: "Gestor (Backend)",
                fw_tbl_policy: "Política (Target)",
                fw_tbl_action: "Acción",
                fw_tbl_loading: "Cargando reglas...",
                // Map view keys
                map_title: "Mapa Global de Conexiones",
                map_desc: "Análisis de Nodos de Tráfico en Tiempo Real",
                map_recenter_btn: "Recentrar Mapa",
                // Connections view keys
                conns_title: "Conexiones del Sistema Activas",
                conns_desc: "Selecciona cualquier fila para traducir e interpretar lo que está pasando en la red.",
                conns_loading: "Cargando conexiones del sistema...",
                hdr_proc: "Proceso",
                hdr_pid: "PID",
                hdr_proto: "Proto",
                hdr_src_ip: "IP Origen",
                hdr_src_port: "Pto Orig.",
                hdr_dst_ip: "IP Destino",
                hdr_dst_port: "Pto Dest.",
                hdr_status: "Estado",
                hdr_eval: "Evaluación",
                // Modal translation keys
                modal_title: "Interpretación de Conexión",
                modal_ip_scope: "Ámbito de la IP Destino",
                modal_port_purpose: "Propósito del Puerto",
                modal_conn_state: "Estado de la Conexión",
                modal_sec_analysis: "Análisis de Seguridad Detallado",
                modal_recs: "Recomendaciones",
                modal_edu: "Contexto Educativo"
            },
            en: {
                subtitle: "Network Security Analytics — DLP + NDR + NTA + Explanation Engine",
                nav_tutorial: "📖 Tutorial",
                nav_logs: "📄 Security Logs",
                btn_sec_active: "● SECURITY ANALYTICS ACTIVE",
                btn_sec_inactive: "○ SECURITY ANALYTICS INACTIVE",
                status_live: "Live Monitoring",
                sec_analysis: "Network Security Analysis (C2 / Botnet)",
                score_lbl: "Risk",
                sec_threat_level: "Threat Level:",
                active_alerts_lbl: "Active Alerts:",
                risk_formula: "<strong>Risk Heuristic Formula:</strong><br>• Critical (+40): Reverse Shell, C2, deleted binary<br>• High (+25): Execution in /tmp, SUID with network<br>• Medium (+10): Untrusted open listening port<br>• Max Risk capped at 100.",
                chart_proto_dist: "Protocol Distribution",
                chart_top_cpu: "Top CPU Processes (%)",
                chart_bandwidth: "Historical Network Traffic (Mbps)",
                sec_alerts_active: "C2 Alerts / Botnet Behaviors",
                no_alerts: "No active security alerts detected.",
                no_conns: "No matching connections found.",
                nav_dashboard: "Dashboard",
                nav_firewall: "Firewall & IDS",
                nav_logs: "📄 Security Logs",
                nav_config: "Settings",
                config_title: "System Configuration",
                config_lang: "Language / Idioma",
                config_lang_desc: "Select the graphical interface language.",
                config_tutorial: "Tutorials & Documentation",
                config_tutorial_desc: "Learn how to use TCPspecter and explore its capabilities.",
                config_tutorial_btn: "View Interactive Tutorial",
                // Firewall view keys
                fw_title: "Network Security Policies (Firewall & IDS)",
                fw_subtitle: "Advanced interface, IPS and network filtering configuration",
                fw_snort_lbl: "Snort Service:",
                fw_install_btn: "Install Snort",
                fw_toggle_btn: "Start/Stop",
                fw_builder_title: "+ New Firewall Rule (Rule Builder)",
                fw_drop_btn: "Drop (Quick)",
                fw_action_lbl: "Action *",
                fw_opt_deny: "Block (DENY)",
                fw_opt_allow: "Allow (ALLOW)",
                fw_proto_lbl: "Protocol",
                fw_src_lbl: "Source IP",
                fw_dst_lbl: "Destination IP",
                fw_port_lbl: "Port",
                fw_apply_btn: "Apply Rule",
                fw_active_rules_lbl: "Active Firewall Rules:",
                fw_tbl_rule: "Rule / Affected IP",
                fw_tbl_backend: "Manager (Backend)",
                fw_tbl_policy: "Policy (Target)",
                fw_tbl_action: "Action",
                fw_tbl_loading: "Loading rules...",
                // Map view keys
                map_title: "Global Connection Map",
                map_desc: "Real-Time Traffic Node Analysis",
                map_recenter_btn: "Recenter Map",
                // Connections view keys
                conns_title: "Active System Connections",
                conns_desc: "Select any row to translate and interpret what is happening in the network.",
                conns_loading: "Loading system connections...",
                hdr_proc: "Process",
                hdr_pid: "PID",
                hdr_proto: "Proto",
                hdr_src_ip: "Source IP",
                hdr_src_port: "Src Port",
                hdr_dst_ip: "Dest IP",
                hdr_dst_port: "Dst Port",
                hdr_status: "State",
                hdr_eval: "Assessment",
                // Modal translation keys
                modal_title: "Connection Interpretation",
                modal_ip_scope: "Destination IP Scope",
                modal_port_purpose: "Port Purpose",
                modal_conn_state: "Connection State",
                modal_sec_analysis: "Detailed Security Analysis",
                modal_recs: "Recommendations",
                modal_edu: "Educational Context"
            }
        };

        function changeLanguage(lang) {
            localStorage.setItem('language', lang);
            applyLanguage();
        }

        function applyLanguage() {
            const lang = localStorage.getItem('language') || 'en';
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (translations[lang][key]) {
                    el.innerHTML = translations[lang][key];
                }
            });
            const searchBar = document.getElementById('search_bar');
            if (searchBar) {
                searchBar.placeholder = lang === 'es' ? "Buscar por proceso, PID, IP, puerto..." : "Search by process, PID, IP, port...";
            }
            const blockIpInput = document.getElementById('block_ip_input');
            if (blockIpInput) {
                blockIpInput.placeholder = lang === 'es' ? "Quick Block: IP a bloquear" : "Quick Block: IP to block";
            }
            const rbSrc = document.getElementById('rb_src_ip');
            if (rbSrc) rbSrc.placeholder = lang === 'es' ? "Cualquiera" : "Any";
            const rbDst = document.getElementById('rb_dst_ip');
            if (rbDst) rbDst.placeholder = lang === 'es' ? "Cualquiera" : "Any";
            const rbPort = document.getElementById('rb_port');
            if (rbPort) rbPort.placeholder = lang === 'es' ? "Todos" : "All";
            
            // Re-label security toggle button text based on state and language
            const btn = document.getElementById('security_toggle_btn');
            if (btn) {
                const isActive = btn.innerHTML.includes('●') || btn.innerHTML.includes('ACTIVE') || btn.innerHTML.includes('ACTIVA');
                btn.innerHTML = isActive ? translations[lang]['btn_sec_active'] : translations[lang]['btn_sec_inactive'];
            }

            // Style active language button
            document.querySelectorAll('.lang-btn').forEach(b => {
                const isCurrent = b.getAttribute('data-lang') === lang;
                b.style.background = isCurrent ? 'rgba(74, 122, 157, 0.3)' : 'rgba(255,255,255,0.03)';
                b.style.borderColor = isCurrent ? 'var(--primary)' : 'var(--card-border)';
                b.style.color = isCurrent ? 'var(--text-main)' : 'var(--text-muted)';
            });
        }


        const helpTranslations = {
            es: {
                security: {
                    title: "Análisis de Seguridad (C2 / Zombie)",
                    desc: "Este panel muestra el cálculo del puntaje de riesgo del host basado en heurísticas del Zombie Detector. Evalúa patrones de beaconing C2, conexiones reversas de shell activas, binarios ejecutándose desde archivos eliminados del disco, binarios SUID con actividad de red y ejecutables ubicados en rutas volátiles como /tmp."
                },
                proto: {
                    title: "Distribución de Protocolos",
                    desc: "Este gráfico muestra la distribución de sockets de red abiertos en tu máquina. Clasifica en conexiones TCP activas, UDP de datagramas y puertos LISTEN que están a la escucha de nuevas conexiones entrantes."
                },
                cpu: {
                    title: "Top Procesos por CPU",
                    desc: "Muestra en tiempo real los procesos del sistema operativo que están consumiendo mayor porcentaje de CPU, permitiendo identificar picos de carga o hilos de malware de minería (cryptominers) en ejecución."
                },
                bandwidth: {
                    title: "Tráfico de Red Histórico",
                    desc: "Mide y grafica la velocidad de entrada (RX) y salida (TX) de paquetes en Mbps en todas tus interfaces de red. Útil para capturar picos de exfiltración o de tráfico inusual."
                },
                entropy: {
                    title: "Entropía de Payload Histórica",
                    desc: "Gráfico de la entropía de Shannon promedio detectada en las cargas de red TCP. Valores altos (> 7.3) sugieren que se están enviando datos cifrados o archivos altamente comprimidos, lo cual podría indicar canales cifrados C2 o exfiltración encubierta de backups."
                },
                alerts: {
                    title: "Alertas C2 / Comportamientos Zombie",
                    desc: "Registra incidentes graves detectados por el motor heurístico local. Ejemplos incluyen llamadas a Reverse Shell, masquarading de procesos (ejecutables con nombres comunes corriendo desde rutas no estándar) y persistencia del sistema."
                },
                ids_fw: {
                    title: "IDS Snort & Firewall",
                    desc: "Permite gestionar el cortafuegos local (iptables/ufw) e iniciar/detener el servicio pasivo de detección de intrusos Snort. Puedes ver la lista de IPs bloqueadas y agregar nuevas reglas de bloqueo o aislamiento."
                },
                dlp_ndr: {
                    title: "Alertas DLP & NDR (Scapy/DNS)",
                    desc: "Muestra alertas en tiempo real extraídas por el sniffer de red de Scapy y DNS: detección de exfiltración de archivos críticos por firmas de Magic Bytes (DLP), consultas de dominios aleatorios (DGA) y túneles DNS en el puerto 53."
                },
                map: {
                    title: "Mapa Global de Conexiones",
                    desc: "Visualiza geográficamente las direcciones IP públicas de tus sockets activos. Utiliza el módulo Traceroute asíncrono para mapear los saltos intermedios en un globo interactivo Apache ECharts."
                },
                connections: {
                    title: "Conexiones del Sistema Activas",
                    desc: "Tabla interactiva de flujos y sockets de red en tiempo real. Al hacer clic en cualquier fila, el Explanation Engine de TCPspecter traduce las variables de red (como puertos conocidos, DNS o ASN) a descripciones comprensibles para humanos."
                }
            },
            en: {
                security: {
                    title: "Security Analysis (C2 / Botnet)",
                    desc: "This card shows the heuristic risk score calculated by the Zombie Detector. It monitors active reverse shells, process name masquerading, execution from deleted binaries, SUID binaries communicating over the network, and scripts running from volatile paths like /tmp."
                },
                proto: {
                    title: "Protocol Distribution",
                    desc: "Displays the relative percentage of open sockets categorized into active TCP connections, UDP datagrams, and LISTEN ports waiting for inbound traffic."
                },
                cpu: {
                    title: "Top CPU Processes",
                    desc: "Shows running system processes that consume the highest amount of processor resources, helpful for pinpointing system spikes or silent mining malware."
                },
                bandwidth: {
                    title: "Historical Network Traffic",
                    desc: "Graphs the inbound (RX) and outbound (TX) transfer rates in Mbps across all system network interfaces to help you detect network exfiltration spikes."
                },
                entropy: {
                    title: "Historical Payload Entropy",
                    desc: "Tracks the average Shannon entropy of TCP packet payloads. High values (> 7.3) signify encrypted channels (like AES) or compressed files, which are common signatures of C2 channels or database exfiltration."
                },
                alerts: {
                    title: "C2 Alerts / Zombie Behaviors",
                    desc: "Lists critical security events captured by the host heuristics agent, such as reverse shell calls, process masquerading, system persistence setups, and orphaned C2 processes."
                },
                ids_fw: {
                    title: "IDS Snort & Firewall",
                    desc: "Provides centralized firewall control (iptables/ufw) and lifecycle management of the Snort Intrusion Detection System. Allows you to block suspect IPs and manage quarantine rules."
                },
                dlp_ndr: {
                    title: "DLP & NDR Alerts (Scapy/DNS)",
                    desc: "Real-time network alerts processed by the passive sniffer: Data Loss Prevention (DLP) magic byte detection, Domain Generation Algorithms (DGA), and DNS Tunneling exfiltration over port 53."
                },
                map: {
                    title: "Global Connection Map",
                    desc: "Geographically visualizes public IP addresses of active connections. Uses asynchronous traceroute routines to plot network hops on an interactive Apache ECharts globe."
                },
                connections: {
                    title: "Active Network Connections",
                    desc: "Real-time interactive sockets table. Clicking any row triggers TCPspecter's Explanation Engine to translate network attributes (such as ports, DNS, and ASN) into plain human-readable text."
                }
            }
        };

        function showModuleHelp(moduleKey, event) {
            // Prevent triggering modal when clicking interactive controls (buttons, links, inputs, canvas)
            if (event && (
                event.target.tagName === 'BUTTON' || 
                event.target.tagName === 'A' || 
                event.target.tagName === 'INPUT' || 
                event.target.tagName === 'CANVAS' ||
                event.target.closest('button') ||
                event.target.closest('a') ||
                event.target.closest('input')
            )) {
                return;
            }
            const lang = localStorage.getItem('language') || 'en';
            const info = helpTranslations[lang][moduleKey];
            if (info) {
                document.getElementById('help_title').innerText = info.title;
                document.getElementById('help_desc').innerHTML = info.desc;
                document.getElementById('help_modal').style.display = 'flex';
            }
        }

        function closeHelpModal() {
            document.getElementById('help_modal').style.display = 'none';
        }

        function handleRouting() {
            const path = window.location.pathname;
            document.querySelectorAll('.spa-view').forEach(v => v.style.display = 'none');
            
            // Adjust header nav active states
            document.querySelectorAll('nav a').forEach(a => {
                a.style.color = 'var(--text-main)';
                if (a.getAttribute('href') === path) {
                    a.style.color = 'var(--primary)';
                }
            });

            const sharedMonitoring = document.getElementById('shared_monitoring');

            if (path === '/firewall') {
                document.getElementById('view_firewall').style.display = 'block';
                if (sharedMonitoring) sharedMonitoring.style.display = 'block';
            } else if (path === '/configuration') {
                document.getElementById('view_configuration').style.display = 'block';
                if (sharedMonitoring) sharedMonitoring.style.display = 'none';
            } else {
                // Default to dashboard
                document.getElementById('view_dashboard').style.display = 'block';
                if (sharedMonitoring) sharedMonitoring.style.display = 'block';
                // Trigger resize for Echarts to render correctly if it was hidden
                if (globeChart) globeChart.resize();
            }
        }

        window.onload = () => {
            initCharts();
            initGlobe();
            refreshData();
            applyLanguage();
            handleRouting(); // Render the correct SPA view based on URL
            setInterval(refreshData, 1500);
        };
    </script>

    <!-- Interactive Explanation Modal Overlay -->
    <div id="help_modal" onclick="if(event.target===this) closeHelpModal()" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); backdrop-filter: blur(6px); z-index: 10000; align-items: center; justify-content: center;">
        <div style="background: #0f172a; border: 1px solid var(--primary); padding: 24px; border-radius: 16px; max-width: 500px; width: 90%; position: relative; box-shadow: 0 20px 50px rgba(0,0,0,0.5);">
            <button onclick="closeHelpModal()" style="position: absolute; top: 12px; right: 12px; background: none; border: none; color: var(--text-muted); font-size: 20px; cursor: pointer; font-weight: bold; line-height: 1;">&times;</button>
            <h3 id="help_title" style="color: var(--primary); margin-top: 0; margin-bottom: 12px; font-size: 16px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px;">Módulo</h3>
            <p id="help_desc" style="color: var(--text-main); font-size: 13px; line-height: 1.6; margin-bottom: 20px; text-align: justify;">Explicación del módulo.</p>
            <div style="text-align: right;">
                <button onclick="closeHelpModal()" style="background: var(--primary); border: none; color: #fff; padding: 6px 16px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer;">Entendido</button>
            </div>
        </div>
    </div>
</body>
</html>
"""

LOGS_HTML_CONTENT = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TCPspecter - Logs de Seguridad Avanzada</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #080c14;
            --card-bg: rgba(17, 24, 39, 0.7);
            --card-border: rgba(255, 255, 255, 0.06);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #4a7a9d;
            --accent: #f2e8c9;
            --danger: #f87171;
            --warning: #fbbf24;
            --success: #34d399;
            --shadow: rgba(0, 0, 0, 0.4);
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }
        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 10% 20%, rgba(74, 122, 157, 0.08) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(242, 232, 201, 0.05) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--card-border);
        }
        .logo-section h1 {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-main);
        }
        .logo-section h1 span {
            color: var(--danger);
        }
        .logo-section p {
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 4px;
        }
        .nav-btn {
            background: rgba(74, 122, 157, 0.15);
            border: 1px solid var(--primary);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }
        .nav-btn:hover {
            background: rgba(74, 122, 157, 0.3);
        }
        .container {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 24px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 30px var(--shadow);
        }
        .filter-row {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        .search-bar {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--card-border);
            border-radius: 6px;
            color: var(--text-main);
            padding: 8px 12px;
            font-size: 13px;
            flex-grow: 1;
            min-width: 200px;
        }
        .search-bar:focus {
            outline: none;
            border-color: var(--primary);
        }
        .filter-btn {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--card-border);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn.active, .filter-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-main);
            border-color: var(--text-muted);
        }
        .log-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }
        .log-table th {
            text-align: left;
            padding: 12px;
            color: var(--text-muted);
            border-bottom: 2px solid var(--card-border);
            font-weight: 600;
        }
        .log-table td {
            padding: 12px;
            border-bottom: 1px solid var(--card-border);
        }
        .log-table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        .badge {
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
        }
        .badge-detected {
            background: rgba(248, 113, 113, 0.15);
            color: var(--danger);
            border: 1px solid var(--danger);
        }
        .badge-resolved {
            background: rgba(52, 211, 153, 0.15);
            color: var(--success);
            border: 1px solid var(--success);
        }
        .sev-critico {
            background: rgba(248, 113, 113, 0.15);
            color: var(--danger);
        }
        .sev-alto {
            background: rgba(251, 191, 36, 0.15);
            color: var(--warning);
        }
        .sev-medio {
            background: rgba(74, 122, 157, 0.15);
            color: var(--primary);
        }
        .sev-bajo {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
        }
        .timestamp {
            color: var(--text-muted);
            font-family: monospace;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-section">
            <h1 data-i18n="logs_title">TCPspecter - <span>Seguridad Historial</span></h1>
            <p data-i18n="logs_subtitle">Logs y Auditoría de Amenazas Avanzadas en Tiempo Real</p>
        </div>
        <div style="display:flex; gap:16px; align-items:center;">
            <div class="lang-selector" style="display:flex; gap:6px; margin-right:8px;">
                <button class="lang-btn" data-lang="es" onclick="changeLanguage('es')" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">ES</button>
                <button class="lang-btn" data-lang="en" onclick="changeLanguage('en')" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">EN</button>
            </div>
            <a href="/" class="nav-btn" data-i18n="nav_dashboard">📊 Volver al Dashboard</a>
        </div>
    </header>
    <div class="container">
        <div class="filter-row">
            <input type="text" id="search_log" class="search-bar" placeholder="Buscar por proceso, PID, descripción..." oninput="filterLogs()">
            <button class="filter-btn active" id="btn_filter_all" onclick="setFilter('status', 'ALL', this)" data-i18n="filter_all">Todos</button>
            <button class="filter-btn" id="btn_filter_det" onclick="setFilter('status', 'DETECTED', this)" data-i18n="filter_det">⚠️ Detectados</button>
            <button class="filter-btn" id="btn_filter_res" onclick="setFilter('status', 'RESOLVED', this)" data-i18n="filter_res">✅ Resueltos</button>
            <button class="filter-btn" id="btn_filter_crit" onclick="setFilter('severity', 'CRITICAL', this)" data-i18n="filter_crit">🔴 Crítico</button>
            <button class="filter-btn" id="btn_filter_high" onclick="setFilter('severity', 'HIGH', this)" data-i18n="filter_high">🟡 Alto</button>
        </div>
        <div style="overflow-x: auto;">
            <table class="log-table">
                <thead>
                    <tr>
                        <th data-i18n="col_date">Fecha/Hora</th>
                        <th data-i18n="col_status">Estado</th>
                        <th data-i18n="col_sev">Severidad</th>
                        <th data-i18n="col_cat">Categoría</th>
                        <th>PID</th>
                        <th data-i18n="col_proc">Proceso</th>
                        <th data-i18n="col_desc">Descripción</th>
                    </tr>
                </thead>
                <tbody id="logs_tbody">
                    <!-- Dynamic content -->
                </tbody>
            </table>
        </div>
    </div>
    <script>
        let allLogs = [];
        let statusFilter = 'ALL';
        let severityFilter = 'ALL';

        async function fetchLogs() {
            try {
                const res = await fetch('/api/logs');
                allLogs = await res.json();
                renderLogs();
            } catch (err) {
                console.error("Error al cargar logs:", err);
            }
        }

        function setFilter(type, val, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            if (type === 'status') {
                statusFilter = val;
                severityFilter = 'ALL';
            } else if (type === 'severity') {
                severityFilter = val;
                statusFilter = 'ALL';
            }
            renderLogs();
        }

        function filterLogs() {
            renderLogs();
        }

        function renderLogs() {
            const tbody = document.getElementById('logs_tbody');
            const searchVal = document.getElementById('search_log').value.toLowerCase().trim();
            
            const filtered = allLogs.filter(log => {
                // Status Filter
                if (statusFilter !== 'ALL' && log.status !== statusFilter) return false;
                // Severity Filter
                if (severityFilter !== 'ALL' && log.severity !== severityFilter) return false;
                // Search query
                if (searchVal) {
                    return (
                        (log.proc_name || '').toLowerCase().includes(searchVal) ||
                        String(log.pid || '').includes(searchVal) ||
                        (log.description || '').toLowerCase().includes(searchVal) ||
                        (log.category || '').toLowerCase().includes(searchVal)
                    );
                }
                return true;
            });

            if (filtered.length === 0) {
                const lang = localStorage.getItem('language') || 'en';
                tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px 0;">${translations[lang]['no_logs']}</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(log => {
                const lang = localStorage.getItem('language') || 'en';
                const statusBadge = log.status === 'DETECTED' ? 'badge-detected' : 'badge-resolved';
                const statusLabel = log.status === 'DETECTED' 
                    ? (lang === 'es' ? '⚠️ DETECTADO' : '⚠️ DETECTED') 
                    : (lang === 'es' ? '✅ RESUELTO' : '✅ RESOLVED');
                
                let sevClass = 'sev-bajo';
                if (log.severity === 'CRITICAL') sevClass = 'sev-critico';
                else if (log.severity === 'HIGH') sevClass = 'sev-alto';
                else if (log.severity === 'MEDIUM') sevClass = 'sev-medio';

                return `
                    <tr>
                        <td class="timestamp">${log.timestamp}</td>
                        <td><span class="badge ${statusBadge}">${statusLabel}</span></td>
                        <td><span class="badge ${sevClass}">${log.severity}</span></td>
                        <td><strong>${log.category}</strong></td>
                        <td>${log.pid || '-'}</td>
                        <td><code>${log.proc_name || '-'}</code></td>
                        <td>${log.description}</td>
                    </tr>
                `;
            }).join('');
        }

        const translations = {
            es: {
                logs_title: "TCPspecter - <span>Seguridad Historial</span>",
                logs_subtitle: "Logs y Auditoría de Amenazas Avanzadas en Tiempo Real",
                nav_dashboard: "📊 Volver al Dashboard",
                filter_all: "Todos",
                filter_det: "⚠️ Detectados",
                filter_res: "✅ Resueltos",
                filter_crit: "🔴 Crítico",
                filter_high: "🟡 Alto",
                col_date: "Fecha/Hora",
                col_status: "Estado",
                col_sev: "Severidad",
                col_cat: "Categoría",
                col_proc: "Proceso",
                col_desc: "Descripción",
                no_logs: "No se encontraron registros en la bitácora."
            },
            en: {
                logs_title: "TCPspecter - <span>Security History</span>",
                logs_subtitle: "Logs & Audit of Advanced Threats in Real-Time",
                nav_dashboard: "📊 Back to Dashboard",
                filter_all: "All",
                filter_det: "⚠️ Detected",
                filter_res: "✅ Resolved",
                filter_crit: "🔴 Critical",
                filter_high: "🟡 High",
                col_date: "Date/Time",
                col_status: "Status",
                col_sev: "Severity",
                col_cat: "Category",
                col_proc: "Process",
                col_desc: "Description",
                no_logs: "No logs found in the audit trail."
            }
        };

        function changeLanguage(lang) {
            localStorage.setItem('language', lang);
            applyLanguage();
            renderLogs();
        }

        function applyLanguage() {
            const lang = localStorage.getItem('language') || 'en';
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (translations[lang][key]) {
                    el.innerHTML = translations[lang][key];
                }
            });
            const searchBar = document.getElementById('search_log');
            if (searchBar) {
                searchBar.placeholder = lang === 'es' ? "Buscar por proceso, PID, descripción..." : "Search by process, PID, description...";
            }
            // Style active language button
            document.querySelectorAll('.lang-btn').forEach(b => {
                const isCurrent = b.getAttribute('data-lang') === lang;
                b.style.background = isCurrent ? 'rgba(74, 122, 157, 0.3)' : 'rgba(255,255,255,0.03)';
                b.style.borderColor = isCurrent ? 'var(--primary)' : 'var(--card-border)';
                b.style.color = isCurrent ? 'var(--text-main)' : 'var(--text-muted)';
            });
        }

        window.onload = () => {
            fetchLogs();
            applyLanguage();
            setInterval(fetchLogs, 3000);
        };
    </script>
</body>
</html>
"""

TUTORIAL_HTML_CONTENT = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TCPspecter - Centro de Aprendizaje &amp; Guía de Uso</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #080c14;
            --card-bg: rgba(17, 24, 39, 0.7);
            --card-border: rgba(255, 255, 255, 0.06);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #4a7a9d;
            --accent: #f2e8c9;
            --danger: #f87171;
            --warning: #fbbf24;
            --success: #34d399;
            --shadow: rgba(0, 0, 0, 0.4);
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }
        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 10% 20%, rgba(74, 122, 157, 0.08) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(242, 232, 201, 0.05) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--card-border);
        }
        .logo-section h1 {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-main);
        }
        .logo-section h1 span {
            color: var(--primary);
        }
        .logo-section p {
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 4px;
        }
        .nav-btn {
            background: rgba(74, 122, 157, 0.15);
            border: 1px solid var(--primary);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }
        .nav-btn:hover {
            background: rgba(74, 122, 157, 0.3);
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 30px var(--shadow);
        }
        h2 {
            font-size: 22px;
            margin: 30px 0 15px;
            color: var(--accent);
            border-bottom: 1px solid rgba(255,255,255,0.05);
            padding-bottom: 8px;
        }
        h2:first-of-type {
            margin-top: 0;
        }
        p {
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-main);
            margin-bottom: 16px;
        }
        ul, ol {
            margin-left: 20px;
            margin-bottom: 16px;
            font-size: 14px;
            line-height: 1.6;
        }
        li {
            margin-bottom: 8px;
        }
        code {
            background: rgba(0,0,0,0.3);
            color: var(--accent);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
        }
        .code-block {
            background: #04060b;
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 16px;
            font-family: monospace;
            font-size: 13px;
            color: #d1d5db;
            overflow-x: auto;
            margin: 16px 0;
            white-space: pre;
        }
        .highlight {
            color: var(--danger);
            font-weight: 600;
        }
        .highlight-success {
            color: var(--success);
            font-weight: 600;
        }
        .card-tip {
            background: rgba(74, 122, 157, 0.1);
            border-left: 4px solid var(--primary);
            padding: 16px;
            border-radius: 0 8px 8px 0;
            margin: 20px 0;
        }
        .card-warning {
            background: rgba(248, 113, 113, 0.1);
            border-left: 4px solid var(--danger);
            padding: 16px;
            border-radius: 0 8px 8px 0;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-section">
            <h1 data-i18n="tut_title">TCPspecter - <span>Guía &amp; Aprendizaje</span></h1>
            <p data-i18n="tut_subtitle">Centro educativo para Analistas y Administradores de Redes</p>
        </div>
        <div style="display:flex; gap:16px; align-items:center;">
            <div class="lang-selector" style="display:flex; gap:6px; margin-right:8px;">
                <button class="lang-btn" data-lang="es" onclick="changeLanguage('es')" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">ES</button>
                <button class="lang-btn" data-lang="en" onclick="changeLanguage('en')" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">EN</button>
            </div>
            <a href="/" class="nav-btn" data-i18n="nav_dashboard">📊 Volver al Dashboard</a>
        </div>
    </header>
    <div class="container" id="tut_content">
        <!-- Dynamic content mapped from language dictionary -->
    </div>
    <script>
        const translations = {
            es: {
                nav_dashboard: "📊 Volver al Dashboard",
                tut_title: "TCPspecter - <span>Guía &amp; Aprendizaje</span>",
                tut_subtitle: "Centro educativo para Analistas y Administradores de Redes",
                content: `
                    <h2>📖 Guía de Uso Rápido de TCPspecter</h2>
                    <p>TCPspecter no es un simple analizador de tráfico pasivo. Es una plataforma orientada a la <strong>Detección de Amenazas y Prevención de Fugas de Datos (DLP)</strong> en sistemas GNU/Linux, combinando análisis de sockets en tiempo real con una interfaz TUI intuitiva y un dashboard gráfico en el navegador.</p>
                    
                    <h2>🔬 Módulos de Ciberseguridad</h2>
                    
                    <h3>1. Prevención de Pérdida de Datos (DLP)</h3>
                    <p>El motor DLP monitoriza el uso no autorizado de canales de red salientes por parte de utilidades del sistema. Las alertas de DLP se disparan cuando:</p>
                    <ul>
                        <li><span class="highlight">Intérpretes de comandos en red:</span> Consolas tipo <code>bash</code>, <code>sh</code>, o ejecutables como <code>nc</code> (Netcat) o <code>python</code> abren sockets activos hacia IPs públicas. Esto suele ser evidencia de una <strong>Reverse Shell (consola inversa)</strong> o un script exfiltrando datos locales.</li>
                        <li><span class="highlight">SUID con permisos de red:</span> Un archivo binario con bit de ejecución SUID o SGID configurado se ejecuta y abre sockets activos en red.</li>
                        <li><span class="highlight">Binarios volátiles:</span> Procesos corriendo desde rutas temporales o volátiles como <code>/tmp</code> o <code>/dev/shm</code> que establecen flujos de red.</li>
                    </ul>

                    <h3>2. Detección y Respuesta en Red (NDR)</h3>
                    <p>El motor NDR evalúa el comportamiento de red global de la máquina para detectar actividades sospechosas o de comando y control (C2):</p>
                    <ul>
                        <li><span class="highlight">Conexiones Masivas (DDoS/Escaneos):</span> Si un script o binario no autorizado intenta abrir conexiones simultáneas hacia múltiples IPs públicas (más de 5 o 10 destinos), el sistema alerta de inmediato. <em>Nota: Los navegadores y chats comunes están excluidos (whitelisted) para evitar falsas alarmas.</em></li>
                        <li><span class="highlight">Conexiones C2 (Botnets / Cryptominers):</span> Monitoreo en tiempo real de sockets con destinos asociados a puertos comunes de botnets IRC (<code>6667</code>), nodos Tor (<code>9050</code>), consolas de RATs o mineros (Stratum <code>3333</code>).</li>
                    </ul>

                    <div class="card-tip">
                        <strong>💡 Consejo Práctico (Mitigación Manual):</strong><br>
                        Como TCPspecter es un detector pasivo seguro, <strong>no bloquea tráfico de forma automática</strong> para prevenir cortes accidentales en servicios legítimos del sistema. Toda la mitigación queda bajo tu control.
                    </div>

                    <h2>🛠️ Comandos de Respuesta y Mitigación en Linux</h2>
                    <p>Si detectas un evento malicioso (marcado como <code>CRITICAL</code> o <code>HIGH</code>), puedes tomar acción inmediata con las siguientes herramientas nativas del sistema operativo:</p>
                    
                    <h3>A. Terminar el Proceso Sospechoso (Kill)</h3>
                    <p>Desde la TUI de TCPspecter, puedes presionar la tecla <kbd>x</kbd> sobre el proceso para cerrarlo. Alternativamente en tu terminal puedes ejecutar:</p>
                    <div class="code-block">sudo kill -9 [PID]</div>
                    
                    <h3>B. Bloquear la IP atacante o C2 (Firewall)</h3>
                    <p>Para cerrar la comunicación con una IP pública sospechosa, agrégala a las reglas de tu firewall de Linux:</p>
                    <div class="code-block"># Usando UFW (Uncomplicated Firewall)
sudo ufw deny out to [IP_SOSPECHOSA]

# Usando IPTables directamente
sudo iptables -A OUTPUT -d [IP_SOSPECHOSA] -j DROP</div>

                    <h3>C. Investigar persistencia en el sistema</h3>
                    <p>El malware suele crear persistencia. Investiga si el proceso tiene tareas programadas o servicios de systemd configurados:</p>
                    <div class="code-block"># Buscar en cronjobs de root
sudo crontab -l

# Revisar servicios systemd recientemente modificados
ls -lt /etc/systemd/system/ | head -n 10</div>

                    <h3>🐙 Repositorio Oficial y GitHub</h3>
                    <p>El código fuente completo y las instrucciones sumamente detalladas sobre <strong>cómo usar, configurar y probar el sistema</strong> (incluyendo la emulación de adversarios mediante playbooks, configuraciones del firewall y solución de problemas) están documentados en nuestro repositorio oficial de <strong>GitHub</strong>. Te recomendamos consultar el README principal y la wiki del proyecto para obtener un manual detallado paso a paso.</p>
                `
            },
            en: {
                nav_dashboard: "📊 Back to Dashboard",
                tut_title: "TCPspecter - <span>Guide &amp; Learning</span>",
                tut_subtitle: "Educational hub for Network Analysts &amp; Administrators",
                content: `
                    <h2>📖 TCPspecter Quick Start Guide</h2>
                    <p>TCPspecter is not just a passive packet sniffer. It is a live <strong>Threat Detection and Data Loss Prevention (DLP)</strong> platform for GNU/Linux systems, combining real-time socket analysis with an intuitive TUI and a premium web-based dashboard.</p>
                    
                    <h2>🔬 Cybersecurity Modules</h2>
                    
                    <h3>1. Data Loss Prevention (DLP)</h3>
                    <p>The DLP engine monitors unauthorized use of outbound network channels by local utilities. DLP alerts trigger when:</p>
                    <ul>
                        <li><span class="highlight">Command interpreters on network:</span> Shells like <code>bash</code>, <code>sh</code>, or utilities like <code>nc</code> (Netcat) or <code>python</code> open active sockets to public IPs. This is common evidence of a <strong>Reverse Shell</strong> or data exfiltration.</li>
                        <li><span class="highlight">SUID with Network Privileges:</span> A binary file with active SUID or SGID permissions runs and holds open network sockets.</li>
                        <li><span class="highlight">Volatile binaries:</span> Processes running from temporary folders like <code>/tmp</code> or <code>/dev/shm</code> that initiate network flows.</li>
                    </ul>

                    <h3>2. Network Detection and Response (NDR)</h3>
                    <p>The NDR engine evaluates the host's overall network behaviors to detect zombie node activity or Command & Control (C2) beacons:</p>
                    <ul>
                        <li><span class="highlight">Massive Outbound Connections (DDoS/Scanning):</span> If an untrusted script or rogue binary opens sockets to multiple public IPs (more than 5 or 10 destinations), the system flags it instantly. <em>Note: Common web browsers and chat apps are whitelisted to prevent false positives.</em></li>
                        <li><span class="highlight">C2/Botnet Connections:</span> Live socket scans matching destination ports of IRC botnets (<code>6667</code>), Tor nodes (<code>9050</code>), RAT consoles, or cryptominers (Stratum <code>3333</code>).</li>
                    </ul>

                    <div class="card-tip">
                        <strong>💡 Practical Tip (Manual Mitigation):</strong><br>
                        Since TCPspecter is a safe passive detector, <strong>it does not block traffic automatically</strong> to prevent accidentally bringing down critical services. Mitigation is fully left to the operator.
                    </div>

                    <h2>🛠️ Mitigation &amp; Response Commands in Linux</h2>
                    <p>If you detect a malicious event (marked <code>CRITICAL</code> or <code>HIGH</code>), you can take action using native Linux tools:</p>
                    
                    <h3>A. Terminate the Suspicious Process (Kill)</h3>
                    <p>In the TCPspecter TUI, highlight the process and press <kbd>x</kbd>. Alternatively, run from your terminal:</p>
                    <div class="code-block">sudo kill -9 [PID]</div>
                    
                    <h3>B. Block the Attacking or C2 IP (Firewall)</h3>
                    <p>To drop all outbound packets destined to a suspicious public IP, add it to your Linux firewall:</p>
                    <div class="code-block"># Using UFW (Uncomplicated Firewall)
sudo ufw deny out to [SUSPICIOUS_IP]

# Using IPTables directly
sudo iptables -A OUTPUT -d [SUSPICIOUS_IP] -j DROP</div>

                    <h3>C. Audit System Persistence</h3>
                    <p>Malware often establishes persistence. Check if the process has scheduled cronjobs or active systemd services:</p>
                    <div class="code-block"># List root cronjobs
sudo crontab -l

# Check recently updated systemd services
ls -lt /etc/systemd/system/ | head -n 10</div>

                    <h3>🐙 Official Repository &amp; GitHub</h3>
                    <p>The complete source code and highly detailed instructions on <strong>how to run, configure, and use the platform</strong> (including incident response playbooks for adversary emulation, firewall rules setup, and system diagnostics) are thoroughly documented in our official <strong>GitHub</strong> repository. Please refer to the main README and project wiki for a complete step-by-step user guide.</p>
                `
            }
        };

        function changeLanguage(lang) {
            localStorage.setItem('language', lang);
            applyLanguage();
        }

        function applyLanguage() {
            const lang = localStorage.getItem('language') || 'en';
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (translations[lang][key]) {
                    el.innerHTML = translations[lang][key];
                }
            });
            document.getElementById('tut_content').innerHTML = translations[lang]['content'];

            // Style active language button
            document.querySelectorAll('.lang-btn').forEach(b => {
                const isCurrent = b.getAttribute('data-lang') === lang;
                b.style.background = isCurrent ? 'rgba(74, 122, 157, 0.3)' : 'rgba(255,255,255,0.03)';
                b.style.borderColor = isCurrent ? 'var(--primary)' : 'var(--card-border)';
                b.style.color = isCurrent ? 'var(--text-main)' : 'var(--text-muted)';
            });
        }

        window.onload = () => {
            applyLanguage();
        };
    </script>
</body>
</html>
"""


def start_web_server(port=None):
    """
    Spins up the web server daemon thread serving on the requested port.
    """
    global _server, _thread
    
    if port is None:
        port = PORT

    if _server is not None:
        return  # already running
        
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass # suppress requests console clutter

        def _send_security_headers(self):
            """Adds HTTP security headers to every response."""
            # Prevent clickjacking
            self.send_header('X-Frame-Options', 'DENY')
            # Prevent MIME sniffing
            self.send_header('X-Content-Type-Options', 'nosniff')
            # XSS protection (legacy browsers)
            self.send_header('X-XSS-Protection', '1; mode=block')
            # Content Security Policy — only allow inline scripts (dashboard uses them)
            self.send_header(
                'Content-Security-Policy',
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self' https://cdn.jsdelivr.net"
            )
            # HSTS: only via HTTPS, but set as best practice
            self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
            # Restrict browser features
            self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

        def _get_client_ip(self) -> str:
            """Returns the client IP for rate limiting."""
            return self.client_address[0] if self.client_address else "unknown"

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path in ('/', '/firewall', '/configuration'):
                csrf_token = generate_csrf_token()
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Set-Cookie', f'csrf_token={csrf_token}; Path=/; SameSite=Strict')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(HTML_CONTENT.encode('utf-8'))
            elif url.path == '/logs':
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(LOGS_HTML_CONTENT.encode('utf-8'))
            elif url.path == '/tutorial':
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(TUTORIAL_HTML_CONTENT.encode('utf-8'))
            elif url.path == '/api/csrf_token':
                # Endpoint to refresh CSRF token via AJAX
                new_token = generate_csrf_token()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Set-Cookie', f'csrf_token={new_token}; Path=/; SameSite=Strict')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"csrf_token": new_token}).encode('utf-8'))
            elif url.path == '/api/logs':
                query_components = urllib.parse.parse_qs(url.query)
                lang = query_components.get("lang", ["en"])[0]
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps(get_parsed_logs(lang=lang)).encode('utf-8'))
            elif url.path == '/api/data':
                query_components = urllib.parse.parse_qs(url.query)
                lang = query_components.get("lang", ["en"])[0]
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                try:
                    data = get_dashboard_data(lang=lang)
                except Exception as e:
                    data = {"error": str(e)}
                self.wfile.write(json.dumps(data).encode('utf-8'))
            elif url.path == '/api/geoip':
                query_components = urllib.parse.parse_qs(url.query)
                ip = query_components.get("ip", [""])[0]
                try:
                    res = asyncio.run(lookup_ip_geoip(ip))
                except Exception:
                    res = None
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps(res).encode('utf-8'))
            elif url.path == '/api/self_geo':
                try:
                    res = asyncio.run(lookup_self_geoip())
                except Exception:
                    res = None
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps(res).encode('utf-8'))
            elif url.path == '/api/traceroute':
                query_components = urllib.parse.parse_qs(url.query)
                ip = query_components.get("ip", [""])[0]
                try:
                    res = asyncio.run(get_hops(ip))
                except Exception:
                    res = []
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps(res).encode('utf-8'))
            else:
                self.send_response(404)
                self._send_security_headers()
                self.end_headers()

        def do_POST(self):
            url = urllib.parse.urlparse(self.path)
            client_ip = self._get_client_ip()

            # ── Rate Limiting ─────────────────────────────────────────────
            if not check_rate_limit(client_ip):
                self.send_response(429)  # Too Many Requests
                self.send_header('Content-type', 'application/json')
                self.send_header('Retry-After', '60')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Rate limit exceeded. Max 30 mutating requests per minute."
                }).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 65536:  # Cap body at 64KB
                self.send_response(413)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Request body too large"}).encode('utf-8'))
                return

            post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            
            body = {}
            if post_data:
                try:
                    body = json.loads(post_data)
                except Exception:
                    try:
                        body = {k: v[0] for k, v in urllib.parse.parse_qs(post_data).items()}
                    except Exception:
                        pass

            # ── CSRF Validation ───────────────────────────────────────────
            # Skip CSRF check for read-only toggle_security (non-destructive)
            CSRF_EXEMPT_PATHS = {'/api/toggle_security'}
            if url.path not in CSRF_EXEMPT_PATHS:
                # Accept token from header (X-CSRF-Token) or body
                csrf_token = (
                    self.headers.get('X-CSRF-Token') or
                    body.get('csrf_token') or
                    urllib.parse.parse_qs(url.query).get('csrf_token', [''])[0]
                )
                if not validate_csrf_token(csrf_token):
                    self.send_response(403)  # Forbidden
                    self.send_header('Content-type', 'application/json')
                    self._send_security_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "Invalid or missing CSRF token. Refresh the dashboard page."
                    }).encode('utf-8'))
                    return

            if url.path == '/api/toggle_security':
                from core import zombie_detector
                zombie_detector.ADVANCED_SECURITY_ENABLED = not zombie_detector.ADVANCED_SECURITY_ENABLED
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"enabled": zombie_detector.ADVANCED_SECURITY_ENABLED}).encode('utf-8'))
                
            elif url.path == '/api/block_ip':
                ip = body.get("ip")
                if not ip:
                    query_components = urllib.parse.parse_qs(url.query)
                    ip = query_components.get("ip", [""])[0]
                
                from core.firewall_manager import block_ip, validate_ip
                safe_ip = validate_ip(ip) if ip else None
                success = block_ip(safe_ip) if safe_ip else False
                
                self.send_response(200 if success else 400)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": success,
                    "ip": safe_ip or ip,
                    "error": None if success else "Invalid IP or firewall operation failed"
                }).encode('utf-8'))

            elif url.path == '/api/unblock_ip':
                ip = body.get("ip")
                if not ip:
                    query_components = urllib.parse.parse_qs(url.query)
                    ip = query_components.get("ip", [""])[0]
                
                from core.firewall_manager import unblock_ip, validate_ip
                safe_ip = validate_ip(ip) if ip else None
                success = unblock_ip(safe_ip) if safe_ip else False
                
                self.send_response(200 if success else 400)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": success,
                    "ip": safe_ip or ip,
                    "error": None if success else "Invalid IP or firewall operation failed"
                }).encode('utf-8'))

            elif url.path == '/api/firewall/rules':
                action = body.get("action", "")
                src_ip = body.get("src_ip", "")
                dst_ip = body.get("dst_ip", "")
                port = body.get("port", "")
                protocol = body.get("protocol", "")
                
                from core.firewall_manager import add_custom_rule
                success = add_custom_rule(action, src_ip, dst_ip, port, protocol)
                
                self.send_response(200 if success else 400)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": success,
                    "error": None if success else "Failed to add firewall rule. Check inputs or permissions."
                }).encode('utf-8'))


            elif url.path == '/api/toggle_snort':
                from core.snort_manager import is_snort_running, start_snort, stop_snort
                if is_snort_running():
                    success = stop_snort()
                    status = "stopped"
                else:
                    success = start_snort()
                    status = "started"
                
                self.send_response(200 if success else 500)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": success, "status": status}).encode('utf-8'))

            elif url.path == '/api/install_snort':
                from core.snort_manager import install_snort
                success, msg = install_snort()
                
                self.send_response(200 if success else 500)
                self.send_header('Content-type', 'application/json')
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": success, "message": msg}).encode('utf-8'))
                
            else:
                self.send_response(404)
                self._send_security_headers()
                self.end_headers()

    # Instantiate the server synchronously to catch bind errors (like port already in use)
    _server = ThreadingHTTPServer(('127.0.0.1', port), DashboardHandler)

    def run_server():
        try:
            _server.serve_forever()
        except Exception:
            pass

    _thread = threading.Thread(target=run_server)
    _thread.daemon = True
    _thread.start()

    # Launch background security analysis worker
    _sec_thread = threading.Thread(target=_security_worker, daemon=True)
    _sec_thread.start()

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
