# -*- coding: utf-8 -*-
import threading
import json
import time
import urllib.parse
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler

import psutil
from core.sysinfo import get_system_stats, get_process_list, get_all_connections
from core.zombie_detector import analyze_zombie_status
from core.interpreter import interpret_connection
from core.geoip import lookup_ip_geoip, lookup_self_geoip
from core.traceroute import get_hops

import os
import re
import datetime

def get_configured_port():
    try:
        with open("config.json", "r") as f:
            cfg = json.load(f)
            return int(cfg.get("web_server_port", 8050))
    except Exception:
        return 8050

PORT = get_configured_port()

# Global server controls
_server = None
_thread = None
last_net_io = None
last_net_time = 0.0

# --- Security report cache & logging -------------------------------------
SECURITY_LOG_FILE = "security_events.log"
_active_findings = set()

def log_security_finding(finding, status="DETECTED"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pid_str = f"PID {finding.get('pid') or '-'}"
    proc_str = finding.get('proc_name') or 'N/A'
    log_line = f"[{timestamp}] [{status}] [{finding.get('severity', 'INFO')}] [{finding.get('category', 'General')}] ({pid_str}: {proc_str}) - {finding.get('description', '')}\n"
    
    # Rotate log file if it exceeds 2MB (approx 15,000 log entries) to cap disk usage
    try:
        if os.path.exists(SECURITY_LOG_FILE) and os.path.getsize(SECURITY_LOG_FILE) > 2 * 1024 * 1024:
            old_file = SECURITY_LOG_FILE + ".old"
            if os.path.exists(old_file):
                os.remove(old_file)
            os.rename(SECURITY_LOG_FILE, old_file)
    except Exception:
        pass

    try:
        with open(SECURITY_LOG_FILE, "a") as f:
            f.write(log_line)
    except Exception:
        pass

def get_parsed_logs():
    logs = []
    try:
        if os.path.exists(SECURITY_LOG_FILE):
            with open(SECURITY_LOG_FILE, "r") as f:
                for line in f:
                    # [2026-06-20 21:06:37] [DETECTED] [CRITICAL] [Category] (PID 1234: proc) - Desc
                    m = re.match(r"^\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+\(PID (.*?):\s+(.*?)\)\s+-\s+(.*)$", line.strip())
                    if m:
                        logs.append({
                            "timestamp": m.group(1),
                            "status": m.group(2),
                            "severity": m.group(3),
                            "category": m.group(4),
                            "pid": m.group(5),
                            "proc_name": m.group(6),
                            "description": m.group(7)
                        })
    except Exception:
        pass
    return list(reversed(logs))

_cached_security = {
    "score": 0,
    "risk_level": "CALCULANDO...",
    "findings": [],
    "scanned_processes": 0,
    "scanned_connections": 0
}
_security_lock = threading.Lock()

def _security_worker():
    """Background thread: refresh security analysis every 5 seconds & log events."""
    global _cached_security, _active_findings
    while True:
        try:
            result = analyze_zombie_status()
            with _security_lock:
                _cached_security = result
            
            # Keep history logs of changes in findings
            current_findings = result.get("findings", [])
            current_keys = set()
            for f in current_findings:
                key = (f.get("category"), f.get("severity"), f.get("pid"), f.get("proc_name"), f.get("description"))
                current_keys.add(key)
                if key not in _active_findings:
                    log_security_finding(f, "DETECTED")
                    _active_findings.add(key)
            
            # Check resolved
            resolved_keys = _active_findings - current_keys
            for key in list(resolved_keys):
                f = {
                    "category": key[0],
                    "severity": key[1],
                    "pid": key[2],
                    "proc_name": key[3],
                    "description": key[4]
                }
                log_security_finding(f, "RESOLVED")
                _active_findings.remove(key)
        except Exception:
            pass
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
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
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
        <div class="logo-section">
            <h1>TCP<span>specter</span></h1>
            <p data-i18n="subtitle">Network Security Analytics &mdash; DLP + NDR + NTA + Explanation Engine</p>
        </div>
        <div style="display:flex; gap:16px; align-items:center;">
            <div class="lang-selector" style="display:flex; gap:6px; margin-right:8px;">
                <button class="lang-btn" data-lang="es" onclick="changeLanguage('es')" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">ES</button>
                <button class="lang-btn" data-lang="en" onclick="changeLanguage('en')" style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">EN</button>
            </div>
            <a href="/tutorial" 
               style="background: rgba(74, 122, 157, 0.15); color: var(--text-main); border: 1px solid var(--primary);
                      padding: 6px 16px; border-radius: 8px; cursor: pointer; text-decoration: none;
                      font-size: 13px; font-weight: 600;"
               data-i18n="nav_tutorial"
            >
                📖 Tutorial
            </a>
            <a href="/logs" 
               style="background: rgba(248, 113, 113, 0.15); color: #f87171; border: 1px solid #f87171;
                      padding: 6px 16px; border-radius: 8px; cursor: pointer; text-decoration: none;
                      font-size: 13px; font-weight: 600;"
               data-i18n="nav_logs"
            >
                📄 Logs de Seguridad
            </a>
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
        </div>
    </header>

    <!-- Main Grid Dashboard -->
    <div class="dashboard-grid">
        <!-- Security Widget Card -->
        <div class="card grid-span-2">
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
        <div class="card">
            <div class="card-title" data-i18n="chart_proto_dist">Distribución de Protocolos</div>
            <div class="chart-container">
                <canvas id="protoChart"></canvas>
            </div>
        </div>

        <!-- Top CPU Processes Chart -->
        <div class="card">
            <div class="card-title" data-i18n="chart_top_cpu">Top Procesos CPU (%)</div>
            <div class="chart-container">
                <canvas id="procChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Bandwidth History Chart & Security Alerts List -->
    <div class="dashboard-grid" style="grid-template-columns: 2fr 1fr; margin-bottom: 24px;">
        <div class="card">
            <div class="card-title" data-i18n="chart_bandwidth">Tráfico de Red Histórico (Mbps)</div>
            <div class="chart-container-large">
                <canvas id="bandwidthChart"></canvas>
            </div>
        </div>
        <div class="card" style="display: flex; flex-direction: column;">
            <div class="card-title" data-i18n="sec_alerts_active">Alertas C2 / Comportamientos Zombie</div>
            <div style="flex: 1; overflow-y: auto; max-height: 220px;" id="alerts_list">
                <div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 40px;" data-i18n="no_alerts">No se han detectado alertas de seguridad activas.</div>
            </div>
        </div>
    </div>

    <!-- Cyber-Node Global Map Section -->
    <div class="card" style="margin-bottom: 24px;">
        <div class="connections-header" style="margin-bottom: 0;">
            <div class="connections-title">
                <h2>Mapa Global de Conexiones</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Análisis de Nodos de Tráfico en Tiempo Real</p>
            </div>
        </div>
        <div id="globeChart" style="width: 100%; height: 500px;"></div>
    </div>

    <!-- Active Connections Table Section -->
    <div class="card">
        <div class="connections-header">
            <div class="connections-title">
                <h2>Conexiones del Sistema Activas</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Selecciona cualquier fila para traducir e interpretar lo que está pasando en la red.</p>
            </div>
            <div class="search-box">
                <input type="text" class="search-input" id="search_bar" placeholder="Buscar (proceso, PID, IP, puerto, estado)..." oninput="filterTable()">
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Proceso</th>
                        <th>PID</th>
                        <th>Proto</th>
                        <th>IP Origen</th>
                        <th>Pto Orig.</th>
                        <th>IP Destino</th>
                        <th>Pto Dest.</th>
                        <th>Estado</th>
                        <th>Evaluación</th>
                    </tr>
                </thead>
                <tbody id="connections_tbody">
                    <tr>
                        <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 40px 0;">Cargando conexiones del sistema...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Interpretation Dialog Modal -->
    <div class="modal" id="interpret_modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal()">&times;</span>
            <div class="modal-header">
                <h3 id="modal_proc_title">Interpretación de Conexión</h3>
                <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;" id="modal_socket_title">PID: - | TCP | -</p>
            </div>
            <div class="modal-body">
                <div class="interpret-banner" id="modal_banner">
                    Evaluación de Riesgo: -
                </div>
                <div class="info-block" id="modal_ip_block">
                    <h4>Ámbito de la IP Destino</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_port_block">
                    <h4>Propósito del Puerto</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_status_block">
                    <h4>Estado de la Conexión</h4>
                    <p>-</p>
                </div>
                <div class="info-block block-danger" id="modal_danger_block">
                    <h4>Análisis de Seguridad Detallado</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_recommendation_block">
                    <h4>Recomendaciones</h4>
                    <p>-</p>
                </div>
                <div class="info-block" id="modal_educational_block">
                    <h4>Contexto Educativo</h4>
                    <p>-</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let protoChart = null;
        let procChart = null;
        let bandwidthChart = null;
        let globeChart = null;
        let bandwidthData = { rx: [], tx: [], labels: [] };
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
        }

        async function refreshData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();

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
                            { data: linesData },
                            { data: uniqueScatter }
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

            document.getElementById('modal_proc_title').innerText = `Interpretación de '${conn.name}'`;
            document.getElementById('modal_socket_title').innerText = `PID: ${conn.pid} | Protocolo: ${conn.proto} | IP Destino: ${conn.raddr_ip}:${conn.raddr_port}`;
            
            const banner = document.getElementById('modal_banner');
            banner.innerText = `Evaluación: ${conn.interpretation.assessment}`;
            
            let bannerBg = 'rgba(52, 211, 153, 0.15)';
            let bannerColor = 'var(--success)';
            if (conn.interpretation.assessment.includes('CRÍTICO')) {
                bannerBg = 'rgba(248, 113, 113, 0.15)';
                bannerColor = 'var(--danger)';
            } else if (conn.interpretation.assessment.includes('REVISAR')) {
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
            document.getElementById('modal_recommendation_block').querySelector('p').innerText = recs.length > 0 ? "• " + recs.join("\\n• ") : "No hay recomendaciones específicas.";
            
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
                no_conns: "No se encontraron conexiones que coincidan."
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
                no_conns: "No matching connections found."
            }
        };

        function changeLanguage(lang) {
            localStorage.setItem('language', lang);
            applyLanguage();
        }

        function applyLanguage() {
            const lang = localStorage.getItem('language') || 'es';
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

        window.onload = () => {
            initCharts();
            initGlobe();
            refreshData();
            applyLanguage();
            setInterval(refreshData, 1500);
        };
    </script>
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
                const lang = localStorage.getItem('language') || 'es';
                tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px 0;">${translations[lang]['no_logs']}</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(log => {
                const lang = localStorage.getItem('language') || 'es';
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
            const lang = localStorage.getItem('language') || 'es';
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
                `
            }
        };

        function changeLanguage(lang) {
            localStorage.setItem('language', lang);
            applyLanguage();
        }

        function applyLanguage() {
            const lang = localStorage.getItem('language') || 'es';
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

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(HTML_CONTENT.encode('utf-8'))
            elif url.path == '/logs':
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(LOGS_HTML_CONTENT.encode('utf-8'))
            elif url.path == '/tutorial':
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(TUTORIAL_HTML_CONTENT.encode('utf-8'))
            elif url.path == '/api/logs':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(get_parsed_logs()).encode('utf-8'))
            elif url.path == '/api/data':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                try:
                    data = get_dashboard_data()
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
                self.end_headers()
                self.wfile.write(json.dumps(res).encode('utf-8'))
            elif url.path == '/api/self_geo':
                try:
                    res = asyncio.run(lookup_self_geoip())
                except Exception:
                    res = None
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
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
                self.end_headers()
                self.wfile.write(json.dumps(res).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            url = urllib.parse.urlparse(self.path)
            if url.path == '/api/toggle_security':
                from core import zombie_detector
                zombie_detector.ADVANCED_SECURITY_ENABLED = not zombie_detector.ADVANCED_SECURITY_ENABLED
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"enabled": zombie_detector.ADVANCED_SECURITY_ENABLED}).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()

    def run_server():
        global _server
        try:
            _server = HTTPServer(('127.0.0.1', port), DashboardHandler)
            _server.serve_forever()
        except Exception:
            pass

    _thread = threading.Thread(target=run_server)
    _thread.daemon = True
    _thread.start()

    # Launch background security analysis worker
    _sec_thread = threading.Thread(target=_security_worker, daemon=True)
    _sec_thread.start()

def get_dashboard_data():
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
    
    # Active connections list
    raw_conns = get_all_connections()
    conns = []
    for c in raw_conns:
        # Generate rich human-readable description for each connection row
        interpretation = interpret_connection(c)
        c_copy = c.copy()
        c_copy["interpretation"] = interpretation
        conns.append(c_copy)

    # Processes list
    processes = get_process_list()

    return {
        "cpu": stats.get("cpu", 0.0),
        "ram": stats.get("ram", 0.0),
        "rx_speed": round(rx_speed, 2),
        "tx_speed": round(tx_speed, 2),
        "security": {
            "score": security_report.get("score", 0),
            "risk_level": security_report.get("risk_level", "BAJO"),
            "findings": security_report.get("findings", []),
            "scanned_processes": security_report.get("scanned_processes", 0),
            "scanned_connections": security_report.get("scanned_connections", 0)
        },
        "processes": processes,
        "connections": conns
    }
