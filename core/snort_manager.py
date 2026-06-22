# core/snort_manager.py
"""
Manages the Snort IDS process lifecycle.

Single responsibility: control the Snort process and parse its alerts.
Publishes to the Alert Bus. Does not import web_server and has no UI knowledge.

Fixes aplicados vs versión anterior:
- Eliminada importación circular (from core.web_server import log_security_finding)
- signal.signal() REMOVIDO del módulo (solo va en app.py — hilo principal)
- check_active_firewall() falso-positivo corregido (iptables siempre imprime 3+ líneas)
- setup_local_rules() ahora hace backup antes de sobreescribir
- Reglas Snort mejoradas con variables $HOME_NET y content matching real
- except Exception: pass reemplazado por excepciones específicas con log
- systemctl check: usa 'is-active' (API correcta) en vez de parsear stdout
- Timeout específicos para cada subprocess con mensajes de error útiles
- Rutas via pathlib.Path en lugar de os.path.join
"""
from __future__ import annotations

import atexit
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Final

import psutil  # type: ignore[import]

from core.alerts import SecurityAlert, publish

log = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

_SNORT_PATHS: Final[tuple[str, ...]] = (
    "/usr/sbin/snort",
    "/usr/bin/snort",
    "snort",
)

_SNORT_LOG_CANDIDATES: Final[tuple[Path, ...]] = (
    Path("/var/log/snort/alert"),
    Path("/var/log/snort/alert.fast"),
)

_RULES_DIR  = Path("/etc/snort/rules")
_RULES_FILE = _RULES_DIR / "local.rules"

# ─── Improved Snort Rules ────────────────────────────────────────────────────
# Usan variables $HOME_NET/$EXTERNAL_NET (definidas en snort.conf) y
# content matching donde aplica — mucho más precisas que "alert tcp any any".

_LOCAL_RULES: Final[str] = """\
# TCPspecter — Local IDS Rules (Passive Mode / Alert Only)
# Auto-generated. Edit with care.
# To disable a rule, comment the line with #.

# ── C2 / Reverse Shells ──────────────────────────────────────────────────────
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 \\
    (msg:"TCPSPECTER C2: Salida a puerto Metasploit/Meterpreter"; \\
     flow:established,to_server; \\
     classtype:trojan-activity; sid:9100001; rev:3;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 5555 \\
    (msg:"TCPSPECTER C2: Puerto Android Meterpreter"; \\
     flow:established,to_server; \\
     classtype:trojan-activity; sid:9100006; rev:1;)

# ── Botnets IRC ───────────────────────────────────────────────────────────────
alert tcp $HOME_NET any -> $EXTERNAL_NET 6667:6669 \\
    (msg:"TCPSPECTER BOTNET: Tráfico IRC hacia servidor externo"; \\
     flow:established,to_server; \\
     classtype:trojan-activity; sid:9100002; rev:2;)

# ── Cryptominers — Stratum Protocol ──────────────────────────────────────────
alert tcp $HOME_NET any -> $EXTERNAL_NET 3333 \\
    (msg:"TCPSPECTER MINER: Protocolo Stratum (Minería de Criptomonedas)"; \\
     flow:established,to_server; dsize:>50; \\
     content:"mining.subscribe"; nocase; \\
     classtype:policy-violation; sid:9100003; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 14444 \\
    (msg:"TCPSPECTER MINER: Puerto Stratum XMRig alternativo"; \\
     flow:established,to_server; \\
     classtype:policy-violation; sid:9100007; rev:1;)

# ── Tor ───────────────────────────────────────────────────────────────────────
alert tcp $HOME_NET any -> $EXTERNAL_NET 9050:9051 \\
    (msg:"TCPSPECTER TOR: Conexión a nodo Tor/SOCKS proxy"; \\
     flow:established,to_server; \\
     classtype:policy-violation; sid:9100005; rev:1;)

# ── DNS Tunneling ─────────────────────────────────────────────────────────────
alert udp $HOME_NET any -> any 53 \\
    (msg:"TCPSPECTER DNS TXT: Query TXT excesivamente larga (posible túnel DNS)"; \\
     content:"|00 10|"; offset:2; depth:4; \\
     dsize:>100; \\
     classtype:policy-violation; sid:9100004; rev:2;)

# ── VNC / RAT ─────────────────────────────────────────────────────────────────
alert tcp $HOME_NET any -> $EXTERNAL_NET 5900:5901 \\
    (msg:"TCPSPECTER RAT: Conexión VNC saliente sospechosa"; \\
     flow:established,to_server; \\
     classtype:trojan-activity; sid:9100008; rev:1;)
"""

# Mapeo SID → severidad para clasificación al parsear alertas
_SID_SEVERITY: Final[dict[str, str]] = {
    "9100001": "CRITICAL",  # Meterpreter
    "9100002": "CRITICAL",  # IRC botnet
    "9100003": "HIGH",      # Stratum miner
    "9100004": "MEDIUM",    # DNS tunnel
    "9100005": "HIGH",      # Tor
    "9100006": "CRITICAL",  # Android Meterpreter
    "9100007": "HIGH",      # XMRig
    "9100008": "HIGH",      # VNC/RAT
}

# ─── Regex de parseo de alertas Snort (fast-alert format) ────────────────────
# Ejemplo de línea:
# 06/21-03:15:30.123456  [**] [1:9100001:3] C2 msg [**] [Priority: 1] {TCP} 1.2.3.4:54321 -> 5.6.7.8:4444

_FAST_ALERT_RE = re.compile(
    r"\[\*\*\]\s+\[(?P<gen>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\]"
    r".*\{(?P<proto>\w+)\}\s+"
    r"(?P<src>[\d.:a-fA-F]+?)(?::(?P<sport>\d+))?\s+->\s+"
    r"(?P<dst>[\d.:a-fA-F]+?)(?::(?P<dport>\d+))?$"
)

# ─── Estado del módulo ────────────────────────────────────────────────────────

_process: subprocess.Popen | None = None
_log_thread: threading.Thread | None = None
_stop_event = threading.Event()
_state_lock = threading.Lock()


# ─── Detección e instalación ──────────────────────────────────────────────────

def _find_snort_binary() -> str | None:
    """Busca el binario de Snort. Retorna la primera ruta válida o None."""
    for path in _SNORT_PATHS:
        try:
            result = subprocess.run(
                [path, "-V"],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            if "Snort" in result.stdout or "Snort" in result.stderr:
                return path
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            log.debug("Timeout al verificar binario Snort en: %s", path)
    return None


def is_snort_installed() -> bool:
    """Returns True if Snort is available on the system."""
    return _find_snort_binary() is not None


def _get_default_interface() -> str:
    """
    Detecta la interfaz de red con ruta por defecto leyendo /proc/net/route.
    Fallback: primer iface no-loopback y no-virtual.
    """
    try:
        lines = Path("/proc/net/route").read_text().splitlines()
        for line in lines[1:]:  # salta cabecera
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "00000000":
                return parts[0]
    except OSError as exc:
        log.debug("No se pudo leer /proc/net/route: %s", exc)

    for iface in psutil.net_if_addrs():
        if not any(iface.startswith(p) for p in ("lo", "docker", "veth", "br-")):
            return iface

    return "eth0"


def setup_local_rules(overwrite: bool = False) -> bool:
    """
    Escribe las reglas locales de Snort en /etc/snort/rules/local.rules.
    Si el archivo ya existe y overwrite=False, crea un backup .rules.bak primero.

    Returns:
        True si tuvo éxito, False en caso de error de permisos o I/O.
    """
    try:
        _RULES_DIR.mkdir(parents=True, exist_ok=True)

        if _RULES_FILE.exists() and not overwrite:
            bak = _RULES_FILE.with_suffix(".rules.bak")
            _RULES_FILE.rename(bak)
            log.info("Reglas previas respaldadas en: %s", bak)

        _RULES_FILE.write_text(_LOCAL_RULES, encoding="utf-8")
        log.info("TCPspecter rules written to: %s", _RULES_FILE)
        
        # Ensure it's included in snort.conf
        snort_conf = Path("/etc/snort/snort.conf")
        if snort_conf.exists():
            conf_content = snort_conf.read_text()
            if "include $RULE_PATH/local.rules" not in conf_content:
                with snort_conf.open("a") as f:
                    f.write("\n# TCPspecter injection\ninclude $RULE_PATH/local.rules\n")
        return True

    except PermissionError:
        log.error("Permission denied writing to %s — run as root?", _RULES_DIR)
        return False
    except OSError as exc:
        log.error("Error de I/O al escribir reglas Snort: %s", exc)
        return False


def install_snort() -> tuple[bool, str]:
    """
    Instala Snort vía apt-get de forma no interactiva.

    Returns:
        (success: bool, message: str) — message es legible por el usuario.
    """
    if os.getuid() != 0:
        return False, "Permiso denegado: Se requieren privilegios de root (sudo) para instalar Snort."

    if is_snort_installed():
        return True, "Snort ya está instalado."

    import shutil
    if not shutil.which("apt-get"):
        return False, "Autoinstalación fallida: Sólo soportamos sistemas basados en Debian/Ubuntu (apt). Instala Snort manualmente usando tu gestor de paquetes (yum, dnf, pacman)."

    log.info("Iniciando instalación de Snort via apt-get...")
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}

    try:
        # Pre-seed Snort configuration to avoid interactive setup prompt blockers
        subprocess.run(
            ["debconf-set-selections"],
            input=b"snort snort/interface string any\nsnort snort/address_range string 10.0.0.0/8\n",
            check=False,
            timeout=5.0
        )
        
        subprocess.run(
            ["apt-get", "update", "-qq"],
            check=True,
            timeout=60.0,
            capture_output=True,
        )
        subprocess.run(
            [
                "apt-get", "install", "-y", "-qq", 
                "-o", "Dpkg::Options::=--force-confdef",
                "-o", "Dpkg::Options::=--force-confold",
                "snort"
            ],
            env=env,
            check=True,
            timeout=120.0,
            capture_output=True,
        )
    except subprocess.TimeoutExpired:
        return False, "Timeout: apt-get tardó demasiado. Verifica tu conexión a internet."
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace")[:300]
        return False, f"apt-get falló (código {exc.returncode}): {stderr}"
    except FileNotFoundError:
        return False, "apt-get no encontrado. ¿Estás en un sistema Debian/Ubuntu?"

    if not is_snort_installed():
        return False, "apt-get completó pero Snort no fue encontrado post-instalación."

    setup_local_rules()
    return True, "Snort instalado y reglas TCPspecter configuradas exitosamente."


# ─── Process Control ────────────────────────────────────────────────────────

def is_snort_running() -> bool:
    """
    Verifica si Snort está activo en tres capas:
      1. systemd (más confiable si el servicio está registrado)
      2. Nuestro propio subprocess gestionado
      3. Búsqueda genérica en tabla de procesos del SO
    """
    # 1. systemd — 'is-active' retorna "active\n" limpiamente (sin parsear texto libre)
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "snort"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if result.stdout.strip() == "active":
            return True
    except FileNotFoundError:
        pass  # systemctl no disponible en este sistema
    except subprocess.TimeoutExpired:
        log.debug("systemctl is-active snort: timeout.")

    # 2. Nuestro subprocess
    with _state_lock:
        if _process is not None and _process.poll() is None:
            return True

    # 3. Búsqueda en tabla de procesos (generator — no materializa lista completa)
    return any(
        True
        for proc in psutil.process_iter(["name"])
        if proc.info.get("name") == "snort"
    )


def start_snort() -> bool:
    """Inicia Snort (via systemd o subprocess directo)."""
    global _process, _log_thread

    if not is_snort_installed():
        log.error("Snort not installed. Call install_snort() first.")
        return False

    if is_snort_running():
        return True

    # 1. Intenta via systemd
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", "snort"],
            capture_output=True, text=True, timeout=2.0,
        )
        if result.stdout.strip() in ("enabled", "disabled"):
            subprocess.run(
                ["systemctl", "start", "snort"],
                check=True, timeout=8.0, capture_output=True,
            )
            log.info("Snort iniciado via systemd.")
            _start_log_tailer()
            return True
    except FileNotFoundError:
        pass  # systemctl no disponible
    except subprocess.CalledProcessError as exc:
        log.warning("systemctl start snort falló: %s", exc.stderr.decode(errors="replace")[:150])
    except subprocess.TimeoutExpired:
        log.warning("systemctl start snort: timeout.")

    # 2. Subprocess directo como fallback
    binary = _find_snort_binary()
    if not binary:
        log.error("No se encontró binario de Snort.")
        return False

    iface = _get_default_interface()
    cmd = [binary, "-q", "-A", "fast", "-c", "/etc/snort/snort.conf", "-i", iface]

    with _state_lock:
        try:
            _stop_event.clear()
            
            # Prevent pipe buffer deadlock by redirecting to a file
            err_log = open("/var/log/snort/tcpspecter_error.log", "a")
            _process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=err_log,
            )
            log.info("Snort started as subprocess (PID %d) on %s.", _process.pid, iface)
            _start_log_tailer()
            return True
        except PermissionError:
            log.error("Snort requiere privilegios root para capturar en %s.", iface)
            return False
        except FileNotFoundError:
            log.error("Binario Snort no encontrado: %s", binary)
            return False


def stop_snort() -> bool:
    """Para Snort de forma ordenada (SIGTERM → wait → SIGKILL si necesario)."""
    global _process
    _stop_event.set()

    # 1. systemd
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "snort"],
            capture_output=True, text=True, timeout=2.0,
        )
        if result.stdout.strip() == "active":
            subprocess.run(
                ["systemctl", "stop", "snort"],
                check=True, timeout=8.0, capture_output=True,
            )
            log.info("Snort detenido via systemd.")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    # 2. Nuestro subprocess
    with _state_lock:
        if _process is not None:
            try:
                _process.terminate()
                _process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                log.warning("Snort no terminó en 3s → SIGKILL.")
                _process.kill()
            except OSError:
                pass
            finally:
                _process = None
            log.info("Snort subprocess detenido.")

    return True


# ─── Log Tailer ─────────────────────────────────────────────────────────────

def _start_log_tailer() -> None:
    """Inicia el hilo lector de alertas en background."""
    global _log_thread
    _stop_event.clear()
    _log_thread = threading.Thread(
        target=_tail_log_worker,
        name="snort-log-tailer",
        daemon=True,
    )
    _log_thread.start()


def _tail_log_worker() -> None:
    """
    Equivalente a 'tail -f' sobre el archivo de alertas Snort.
    Espera hasta 10 segundos a que el archivo exista antes de rendirse.
    Cada línea se parsea y publica en el Alert Bus.
    """
    log_file: Path | None = None

    # Espera con timeout a que Snort cree el archivo de alertas
    for _ in range(20):  # 20 × 0.5s = 10s máximo
        for candidate in _SNORT_LOG_CANDIDATES:
            if candidate.exists():
                log_file = candidate
                break
        if log_file:
            break
        time.sleep(0.5)

    if log_file is None:
        log.error(
            "No se encontró el archivo de alertas Snort. Rutas buscadas: %s",
            [str(p) for p in _SNORT_LOG_CANDIDATES],
        )
        return

    log.info("Leyendo alertas Snort desde: %s", log_file)

    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)  # solo alertas nuevas desde este momento

            while not _stop_event.is_set():
                line = fh.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                _parse_and_publish(line.strip())

    except PermissionError:
        log.error("Sin permisos para leer %s.", log_file)
    except OSError as exc:
        log.error("Error de I/O leyendo log Snort: %s", exc)


def _parse_and_publish(line: str) -> None:
    """Parsea una línea de alerta Snort fast-format y la publica en el bus."""
    m = _FAST_ALERT_RE.search(line)
    if not m:
        return

    sid      = m.group("sid")
    msg      = m.group("msg")
    proto    = m.group("proto")
    src      = m.group("src") or ""
    dst      = m.group("dst") or ""
    sport    = m.group("sport") or "-"
    dport    = m.group("dport") or "-"
    severity = _SID_SEVERITY.get(sid, "HIGH")

    publish(SecurityAlert.now(
        engine="snort",
        category="IDS/Snort",
        severity=severity,  # type: ignore[arg-type]
        description=f"{msg} ({proto} {sport}→{dport})",
        source_ip=src,
        dest_ip=dst,
        mitre_technique_id="T1071",
        mitre_technique_name="Application Layer Protocol",
        mitre_tactic="Command and Control",
    ))


# ─── Teardown ─────────────────────────────────────────────────────────────────

def _cleanup() -> None:
    """Limpieza ordenada registrada via atexit. Solo para flush de recursos."""
    if is_snort_running():
        stop_snort()


atexit.register(_cleanup)

# ── NOTA SOBRE signal.signal() ────────────────────────────────────────────────
# Los manejadores de señales SOLO pueden registrarse desde el hilo principal.
# Si este módulo se importa desde un hilo de Textual o un worker, lanzaría:
#   ValueError: signal only works in main thread of the main interpreter
# Por eso, la gestión de SIGTERM/SIGINT está en app.py (punto de entrada),
# NO aquí. El atexit.register(_cleanup) garantiza cleanup ante exit normal.
