# core/alerts.py
"""
Alert Bus — módulo central de comunicación de alertas sin acoplamiento circular.

Patrón: Observer / Event Bus desacoplado.
- Los detectores (snort, scapy, zombie) SOLO publican aquí.
- El web_server y la TUI se SUSCRIBEN aquí.
- Ningún módulo de detección importa módulos de UI/servidor.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import queue
import socket
import threading
import hmac
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Literal, Final

log = logging.getLogger(__name__)

# ─── Tipos ────────────────────────────────────────────────────────────────────

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING", "INFO"]
AlertStatus = Literal["DETECTED", "RESOLVED"]

_BASE_DIR: Final[Path] = Path(__file__).parent.parent
SECURITY_LOG_FILE: Final[Path] = _BASE_DIR / "security_events.log"
SECURITY_ALERTS_JSON: Final[Path] = _BASE_DIR / "security_alerts.json"

# ─── Modelo de Alerta ─────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """
    Representa un evento de seguridad normalizado e inmutable.
    """
    timestamp: str
    engine: str                     # "snort" | "dns" | "dlp" | "zombie"
    category: str
    severity: Severity
    description: str
    source_ip: str = ""
    dest_ip: str = ""
    pid: int | None = None
    proc_name: str = ""
    status: AlertStatus = "DETECTED"
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    mitre_tactic: str | None = None
    nist_controls: tuple[str, ...] = ()
    iso_controls: tuple[str, ...] = ()

    @classmethod
    def now(cls, **kwargs: object) -> "SecurityAlert":
        """Factory que inyecta el timestamp UTC automáticamente."""
        return cls(
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            **kwargs,  # type: ignore[arg-type]
        )

    def to_text_log_line(self, status: str | None = None) -> str:
        """Formatea la alerta como línea de log legible por humanos."""
        s = status or self.status
        pid_str = f"PID {self.pid}" if self.pid is not None else "PID -"
        proc_str = self.proc_name or "N/A"
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"[{ts}] [{s}] [{self.severity}] [{self.category}] "
            f"({pid_str}: {proc_str}) - {self.description}\n"
        )

    def to_ecs(self) -> dict:
        """
        Serializa al formato Elastic Common Schema (ECS) v1.12.
        """
        _sev_num = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50,
                    "LOW": 30, "WARNING": 20, "INFO": 10}
        _risk    = {"CRITICAL": 95, "HIGH": 73, "MEDIUM": 47,
                    "LOW": 21, "WARNING": 15, "INFO": 5}

        doc: dict = {
            "@timestamp": self.timestamp,
            "ecs": {"version": "1.12.0"},
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["info" if self.status == "RESOLVED" else "indicator"],
                "action": self.status.lower(),
                "severity": _sev_num.get(self.severity, 10),
                "risk_score": _risk.get(self.severity, 5),
                "provider": "TCPspecter",
                "dataset": "tcpspecter.security",
                "module": self.category,
            },
            "host": {
                "name": socket.gethostname(),
                "os": {"family": "linux", "platform": "linux"},
            },
            "message": self.description,
            "tcpspecter": {
                "engine": self.engine,
                "status": self.status,
                "severity": self.severity,
                "category": self.category,
            },
        }

        if self.pid is not None:
            doc["process"] = {"name": self.proc_name or "unknown", "pid": self.pid}

        if self.source_ip:
            doc["source"] = {"ip": self.source_ip}

        if self.dest_ip:
            doc["destination"] = {"ip": self.dest_ip}

        if self.mitre_technique_id:
            doc["threat"] = {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": self.mitre_technique_id,
                    "name": self.mitre_technique_name,
                },
                "tactic": {"name": self.mitre_tactic},
            }

        if self.nist_controls:
            doc.setdefault("compliance", {})["nist"] = list(self.nist_controls)

        if self.iso_controls:
            doc.setdefault("compliance", {})["iso"] = list(self.iso_controls)

        return doc


# ─── Persistencia ─────────────────────────────────────────────────────────────

_io_lock = threading.Lock()   # protege escritura concurrente al disco
_MAX_ALERTS_ON_DISK: Final[int] = 5_000
_MAX_LOG_BYTES: Final[int] = 2 * 1024 * 1024  # 2 MB


def _persist_alert(alert: SecurityAlert) -> None:
    with _io_lock:
        try:
            if SECURITY_LOG_FILE.exists() and SECURITY_LOG_FILE.stat().st_size > _MAX_LOG_BYTES:
                bak = SECURITY_LOG_FILE.with_suffix(".log.old")
                if bak.exists():
                    bak.unlink()
                SECURITY_LOG_FILE.rename(bak)
        except OSError as exc:
            log.warning("No se pudo rotar el log de seguridad: %s", exc)

        try:
            with SECURITY_LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(alert.to_text_log_line())
        except OSError as exc:
            log.error("Error al escribir en security_events.log: %s", exc)

        try:
            alerts: list[dict] = []
            if SECURITY_ALERTS_JSON.exists():
                try:
                    alerts = json.loads(SECURITY_ALERTS_JSON.read_bytes())
                except json.JSONDecodeError:
                    log.warning("security_alerts.json corrupto — reiniciando.")

            alerts.append(alert.to_ecs())

            if len(alerts) > _MAX_ALERTS_ON_DISK:
                alerts = alerts[-_MAX_ALERTS_ON_DISK:]

            SECURITY_ALERTS_JSON.write_text(
                json.dumps(alerts, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("Error al escribir en security_alerts.json: %s", exc)


# ─── Bus de Eventos y Webhooks ────────────────────────────────────────────────

_bus: queue.Queue[SecurityAlert] = queue.Queue(maxsize=10_000)
_subscribers: list[Callable[[SecurityAlert], None]] = []
_subscribers_lock = threading.Lock()


def publish(alert: SecurityAlert) -> None:
    try:
        _bus.put_nowait(alert)
    except queue.Full:
        log.error(
            "Alert bus saturado (10k pendientes). Descartando alerta [%s] %s",
            alert.severity, alert.category,
        )


def subscribe(callback: Callable[[SecurityAlert], None]) -> None:
    with _subscribers_lock:
        _subscribers.append(callback)


def _trigger_webhook(alert: SecurityAlert) -> None:
    config_path = _BASE_DIR / "config.json"
    if not config_path.exists():
        return
    try:
        with config_path.open("r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except Exception:
        return

    url = cfg.get("webhook_url")
    if not url:
        return

    secret = cfg.get("webhook_secret", "")
    payload_dict = alert.to_ecs()
    payload_bytes = json.dumps(payload_dict).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "TCPspecter-SOAR-Webhook"
    }

    if secret:
        sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        headers["X-TCPspecter-Signature"] = sig

    def _send():
        try:
            req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=2.0) as res:
                res.read()
        except urllib.error.URLError as e:
            log.warning("Error al enviar webhook a %s: %s", url, e)
        except Exception as e:
            log.warning("Excepción inesperada al enviar webhook: %s", e)

    threading.Thread(target=_send, daemon=True).start()


def _dispatcher_worker() -> None:
    while True:
        try:
            alert = _bus.get(timeout=1.0)
        except queue.Empty:
            continue

        _persist_alert(alert)

        # Triggers webhook asynchronously
        _trigger_webhook(alert)

        with _subscribers_lock:
            for cb in list(_subscribers):
                try:
                    cb(alert)
                except Exception:
                    log.exception("Subscriber %r lanzó una excepción.", cb)


_dispatcher_thread = threading.Thread(
    target=_dispatcher_worker,
    name="alerts-dispatcher",
    daemon=True,
)
_dispatcher_thread.start()
