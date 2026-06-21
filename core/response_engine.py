import threading
import json
import time
import os
import hmac
import hashlib
import urllib.request
import logging
import queue
from core.alerts import subscribe, SecurityAlert

log = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(_BASE_DIR, "config.json")
WEBHOOK_DEBUG_FILE = os.path.join(_BASE_DIR, "webhook_debug.log")

_work_queue = queue.Queue()
_worker_thread = None

def get_config() -> dict:
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def _alert_callback(alert: SecurityAlert) -> None:
    # Phase 3: Instantiate as a subscriber with an asynchronous work queue.
    _work_queue.put(alert)

def _dispatcher_worker() -> None:
    while True:
        try:
            alert: SecurityAlert = _work_queue.get()
            _process_alert(alert)
        except Exception:
            log.exception("Error in response engine worker")
        finally:
            _work_queue.task_done()

def _process_alert(alert: SecurityAlert) -> None:
    config = get_config()
    webhook_url = config.get("webhook_url") or config.get("SOAR_WEBHOOK_URL", "")
    webhook_secret = config.get("webhook_secret") or config.get("SOAR_WEBHOOK_SECRET", "super_secret_key")
    active_response = config.get("ACTIVE_RESPONSE_ENABLED", False)
    admin_ips = config.get("MANAGEMENT_IP_WHITELIST", ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    tarpit_port = config.get("TARPIT_PORT", 2222)

    payload = alert.to_ecs()
    payload_bytes = json.dumps(payload).encode('utf-8')

    # Phase 3: Webhooks (SOAR Dispatcher)
    if not webhook_url:
        try:
            with open(WEBHOOK_DEBUG_FILE, "a") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception:
            pass
    else:
        signature = hmac.new(
            webhook_secret.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        try:
            req = urllib.request.Request(webhook_url, data=payload_bytes, method='POST')
            req.add_header('Content-Type', 'application/json')
            req.add_header('X-TCPspecter-Signature', signature)
            urllib.request.urlopen(req, timeout=5.0)
        except Exception as e:
            log.error(f"Failed to dispatch webhook: {e}")

    # Phase 4: Aislamiento y Tecnología de Engaño
    if alert.severity == "CRITICAL" and alert.category in ("C2 Beaconing", "Memoria Fileless", "Zombie"):
        if active_response:
            from core.firewall_manager import quarantine_host
            success = quarantine_host(admin_ips=admin_ips)
            if success:
                from core.alerts import publish as publish_alert, SecurityAlert
                log.info(f"Active Response triggered: Host isolated due to {alert.category}")
                publish_alert(SecurityAlert.now(
                    engine="response",
                    category="Aislamiento Dinámico",
                    severity="CRITICAL",
                    description=f"Host aislado automáticamente por alerta de {alert.category}.",
                    compliance_tags=("NIST-IR-8011", "ISO-27001-A.13.1")
                ))
    
    if alert.category == "Escaneo de Puertos" or alert.category == "Escaneo de Red":
        from core.firewall_manager import enable_tarpit
        if alert.source_ip:
            success = enable_tarpit(attacker_ip=alert.source_ip, tarpit_port=int(tarpit_port))
            if success:
                from core.alerts import publish as publish_alert, SecurityAlert
                log.info(f"Tarpit triggered: {alert.source_ip} redirected to port {tarpit_port}")
                publish_alert(SecurityAlert.now(
                    engine="response",
                    category="Bloqueo de Firewall",
                    severity="HIGH",
                    description=f"Escaneo masivo detectado desde {alert.source_ip}. Tráfico redirigido al Tarpit en puerto {tarpit_port}.",
                    source_ip=alert.source_ip,
                    compliance_tags=("NIST-IR-8011", "ISO-27001-A.13.1")
                ))

def start_engine() -> None:
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        subscribe(_alert_callback)
        _worker_thread = threading.Thread(target=_dispatcher_worker, daemon=True, name="ResponseEngineWorker")
        _worker_thread.start()
