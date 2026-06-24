import os
import threading
import json
import asyncio
import logging
from fastapi import FastAPI, Request, WebSocket, HTTPException, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import psutil

from core.data_aggregator import (
    get_dashboard_data,
    get_parsed_logs,
    _security_worker,
    get_cached_security,
    log_security_finding,
    generate_csrf_token,
    validate_csrf_token,
    check_rate_limit,
    get_configured_port,
    _alert_callback,
    PORT,              # re-exported so screens can do: from core.web_server import PORT
)
from core.alerts import subscribe as _subscribe_alert
from core.geoip import lookup_ip_geoip, lookup_self_geoip
from core.traceroute import get_hops
from core.firewall_manager import block_ip, unblock_ip, add_custom_rule
from core import zombie_detector

log = logging.getLogger(__name__)

app = FastAPI(title="TCPspecter Enterprise")

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(_BASE_DIR, "web", "static")
TEMPLATES_DIR = os.path.join(_BASE_DIR, "web", "templates")

# Add Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Basic CSP: allow self, inline scripts/styles for UI, and specific CDNs for ECharts/Chart.js
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss: https://cdn.jsdelivr.net; img-src 'self' data:;"
    return response

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
@app.get("/firewall", response_class=HTMLResponse)
@app.get("/intelligence", response_class=HTMLResponse)
@app.get("/configuration", response_class=HTMLResponse)
@app.get("/logs", response_class=HTMLResponse)
async def serve_dashboard():
    with open(os.path.join(TEMPLATES_DIR, "dashboard.html"), "r", encoding="utf-8") as f:
        html = f.read()
    token = generate_csrf_token()
    script = f'<script>window.csrfToken = "{token}";</script>'
    return html.replace("</head>", f"{script}</head>")

@app.get("/tutorial", response_class=HTMLResponse)
async def serve_tutorial():
    with open(os.path.join(TEMPLATES_DIR, "tutorial.html"), "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/intelligence")
async def api_intelligence():
    from core.intelligence_engine import get_engine
    stats = get_engine().get_stats()
    return JSONResponse(content={
        "enabled": stats.enabled,
        "feed_dir": stats.feed_dir,
        "total_entries": stats.total_entries,
        "match_count": stats.match_count,
        "last_reload": stats.last_reload,
        "feeds": [
            {
                "name": f.name,
                "path": f.path,
                "loaded": f.loaded,
                "entry_count": f.entry_count,
                "last_loaded": f.last_loaded,
                "error": f.error,
            }
            for f in stats.feeds
        ],
        "recent_matches": stats.recent_matches,
    })

@app.post("/api/intelligence/reload")
async def api_intelligence_reload(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    if not check_rate_limit(request.client.host if request.client else "127.0.0.1"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    from core.intelligence_engine import initialize_intelligence
    stats = initialize_intelligence()
    return JSONResponse(content={
        "success": True,
        "total_entries": stats.total_entries,
        "last_reload": stats.last_reload,
    })

@app.post("/api/intelligence/toggle")
async def api_intelligence_toggle(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    from core.intelligence_engine import get_engine
    engine = get_engine()
    engine.set_enabled(not engine.enabled)
    return JSONResponse(content={"enabled": engine.enabled})

@app.get("/api/data")
async def api_data(lang: str = "en"):
    return JSONResponse(content=get_dashboard_data(lang))

@app.get("/api/logs")
async def api_logs(lang: str = "en"):
    return JSONResponse(content=get_parsed_logs(lang))

@app.get("/api/geoip")
async def api_geoip(ip: str = ""):
    res = await lookup_ip_geoip(ip)
    return JSONResponse(content=res)

@app.get("/api/self_geo")
async def api_self_geo():
    res = await lookup_self_geoip()
    return JSONResponse(content=res)

@app.get("/api/traceroute")
async def api_traceroute(ip: str = ""):
    res = await get_hops(ip)
    return JSONResponse(content=res)

@app.post("/api/install_snort")
async def api_install_snort(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    from core.snort_manager import install_snort
    success, msg = install_snort()
    return JSONResponse(content={"success": success, "message": msg}, status_code=200 if success else 500)

@app.post("/api/toggle_snort")
async def api_toggle_snort(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    from core.snort_manager import is_snort_running, start_snort, stop_snort
    if is_snort_running():
        success = stop_snort()
        status = "stopped"
    else:
        success = start_snort()
        status = "started"
    return JSONResponse(content={"success": success, "status": status}, status_code=200 if success else 500)

@app.post("/api/toggle_security")
async def api_toggle_security(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    zombie_detector.ADVANCED_SECURITY_ENABLED = not zombie_detector.ADVANCED_SECURITY_ENABLED
    return JSONResponse(content={"enabled": zombie_detector.ADVANCED_SECURITY_ENABLED})

@app.post("/api/block_ip")
async def api_block_ip(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    data = await request.json()
    ip = data.get("ip")
    from core.firewall_manager import validate_ip, block_ip
    safe_ip = validate_ip(ip) if ip else None
    success = block_ip(safe_ip) if safe_ip else False
    return JSONResponse(content={"success": success, "ip": safe_ip or ip}, status_code=200 if success else 400)

@app.post("/api/unblock_ip")
async def api_unblock_ip(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    data = await request.json()
    ip = data.get("ip")
    from core.firewall_manager import validate_ip, unblock_ip
    safe_ip = validate_ip(ip) if ip else None
    success = unblock_ip(safe_ip) if safe_ip else False
    return JSONResponse(content={"success": success, "ip": safe_ip or ip}, status_code=200 if success else 400)

@app.post("/api/firewall/rules")
async def api_firewall_rules(request: Request):
    token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    data = await request.json()
    action = data.get("action", "")
    src_ip = data.get("src_ip", "")
    dst_ip = data.get("dst_ip", "")
    port = data.get("port", "")
    protocol = data.get("protocol", "")
    
    from core.firewall_manager import add_custom_rule
    success = add_custom_rule(action, src_ip, dst_ip, port, protocol)
    return JSONResponse(content={"success": success}, status_code=200 if success else 400)

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    lang = websocket.query_params.get("lang", "en")
    if lang not in ("en", "es"):
        lang = "en"
    try:
        while True:
            data = get_dashboard_data(lang)
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass

def start_web_server(port=None):
    if port is None:
        port = get_configured_port()

    try:
        from core.intelligence_engine import initialize_intelligence
        initialize_intelligence()
    except Exception:
        log.exception("Failed to initialize threat intelligence engine")

    _sec_thread = threading.Thread(target=_security_worker, daemon=True)
    _sec_thread.start()
    
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", loop="asyncio")
    server = uvicorn.Server(config)
    
    _thread = threading.Thread(target=server.run, daemon=True)
    _thread.start()
