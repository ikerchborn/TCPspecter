# core/traffic_analyzer.py
"""
Motor de Análisis de Tráfico en Tiempo Real.

Responsabilidad ÚNICA: capturar paquetes, extraer señales de seguridad,
y publicarlas en el Alert Bus. No importa web_server ni snort_manager.

Fixes aplicados vs versión anterior:
- Eliminada importación circular (from core.snort_manager import ...)
- _sampled_flows usa OrderedDict con evicción LRU O(1) (antes: clear() nuclear)
- Deduplicación de alertas via set de hashes O(1) (antes: list.pop(0) O(n))
- deque(maxlen=N) para entropy_history (antes: list con pop(0) O(n))
- Excepciones específicas con log.debug/error (antes: except Exception: pass)
- Constantes tipadas con Final (antes: magic numbers sueltos)
- detect_magic_bytes: catálogo de datos en lugar de if/elif chain
- is_dga_domain: itertools para max consecutive run sin variable acumuladora
- time.monotonic() para intervalos (inmune a ajustes NTP)
"""
from __future__ import annotations

import itertools
import logging
import math
import threading
import time
from collections import Counter, OrderedDict, deque
from typing import Final

from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR  # type: ignore[import]

from core.alerts import SecurityAlert, publish

log = logging.getLogger(__name__)

# ─── Constantes ───────────────────────────────────────────────────────────────

_SAMPLE_BYTES: Final[int] = 256
_MAX_FLOW_CACHE: Final[int] = 5_000
_DNS_TUNNEL_THRESHOLD: Final[int] = 20
_DNS_TUNNEL_WINDOW_SECS: Final[float] = 10.0
_DGA_MIN_LEN: Final[int] = 12
_DGA_ENTROPY_THRESHOLD: Final[float] = 3.5
_DGA_CONSONANT_VOWEL_RATIO: Final[float] = 3.5
_HIGH_ENTROPY_THRESHOLD: Final[float] = 7.3
_DEDUP_MAX_SIZE: Final[int] = 1_000

# ─── Catálogo de Magic Bytes ─────────────────────────────────────────────────
# Data-driven: extensible sin tocar lógica. startswith() para prefijos exactos.

_MAGIC_PREFIX: Final[list[tuple[bytes, str]]] = [
    (b"\x50\x4b\x03\x04", "ZIP/Office Document"),
    (b"%PDF",              "PDF Document"),
    (b"\x7fELF",           "Linux Executable (ELF)"),
    (b"MZ",                "Windows Executable (PE)"),
    (b"\x1f\x8b",          "GZ Compressed File"),
]

_MAGIC_SEARCH: Final[list[tuple[bytes, str]]] = [
    (b"-----BEGIN",    "Encryption Key / Credentials"),
    (b"INSERT INTO",   "SQL Database Backup"),
    (b"CREATE TABLE",  "SQL Database Backup"),
    (b"-- MySQL dump", "SQL Database Backup"),
]

# ─── Estado del módulo ───────────────────────────────────────────────────────

_lock = threading.Lock()
_stop_event = threading.Event()
_sniff_thread: threading.Thread | None = None

# Contadores de tráfico
_stats: dict[str, int] = {
    "packet_count": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "dns_count": 0,
    "icmp_count": 0,
    "bytes_total": 0,
}

# Rolling entropy history — deque(maxlen) hace trim O(1) automáticamente
_entropy_history: deque[float] = deque(maxlen=100)
# Timed entropy history: stores (iso_timestamp, entropy_value) for frontend charts
_entropy_timed: deque[tuple] = deque(maxlen=30)

# Flow sampler: OrderedDict para LRU eviction O(1) vía popitem(last=False)
# Key: (src_ip, sport, dst_ip, dport) → bytes ya muestreados
_sampled_flows: OrderedDict[tuple, int] = OrderedDict()

# DNS tunnel tracker: parent_domain → deque de timestamps monotónicos
_dns_tracker: dict[str, deque[float]] = {}

# Sets de deduplicación por categoría — hash lookup O(1) vs list.in O(n)
_dns_dedup: set[int] = set()
_dlp_dedup: set[int] = set()
_dedup_lock = threading.Lock()

# Port scan tracking
# Key: (src_ip, dst_ip) -> (set of dst_ports, last_timestamp)
_scan_tracker: dict[tuple[str, str], tuple[set[int], float]] = {}


# ─── Utilidades puras (sin estado, 100% testeables) ──────────────────────────

def calculate_entropy(data: bytes) -> float:
    """Calcula la entropía de Shannon H(X) en bits para una secuencia de bytes."""
    if not data:
        return 0.0
    total = len(data)
    # Generador: no materializa lista intermedia
    return -sum(
        (c / total) * math.log2(c / total)
        for c in Counter(data).values()
    )


def detect_magic_bytes(data: bytes) -> str:
    """
    Retorna el tipo de archivo si se detectan magic bytes conocidos,
    o 'UNKNOWN' si el payload no coincide con ningún patrón conocido.

    Catálogo de datos en lugar de if/elif chain — extensible sin modificar lógica.
    Retorna 'UNKNOWN' (no None) para mantener compatibilidad con la API original.
    """
    header = data[:50]
    for prefix, label in _MAGIC_PREFIX:
        if data.startswith(prefix):
            return label
    for needle, label in _MAGIC_SEARCH:
        if needle in header:
            return label
    return "UNKNOWN"


def get_parent_domain(domain: str) -> str:
    """Extrae el dominio registrable (eTLD+1) de un FQDN."""
    domain = domain.rstrip(".")
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def is_dga_domain(label: str) -> bool:
    """
    Detector heurístico de DGA usando cuatro señales en cascada:
      1. Longitud mínima (gate barato)
      2. Entropía Shannon (gate moderado)
      3. Ratio consonantes/vocales
      4. Racha máxima de consonantes consecutivas (via itertools — sin variables acumuladoras)
    """
    if not label or len(label) < _DGA_MIN_LEN:
        return False

    if calculate_entropy(label.encode()) < _DGA_ENTROPY_THRESHOLD:
        return False

    vowels = frozenset("aeiou")  # frozenset: lookup O(1) garantizado
    alpha = [c.lower() for c in label if c.isalpha()]
    if not alpha:
        return False

    v_count = sum(1 for c in alpha if c in vowels)
    c_count = len(alpha) - v_count

    if v_count == 0 and c_count > 5:
        return True

    if v_count > 0 and (c_count / v_count) > _DGA_CONSONANT_VOWEL_RATIO:
        return True

    # Racha máxima de consonantes usando itertools.groupby — Pythonic, sin estado manual
    max_run = max(
        (sum(1 for _ in grp)
         for is_consonant, grp in itertools.groupby(alpha, key=lambda c: c not in vowels)
         if is_consonant),
        default=0,
    )
    return max_run >= 5


# ─── Publicación de alertas con deduplicación ─────────────────────────────────

def _dedup_key(category: str, description: str) -> int:
    """Hash de deduplicación basado en categoría + descripción truncada (sin timestamp)."""
    return hash((category, description[:80]))


def _publish_dns_alert(category: str, qname: str, description: str) -> None:
    """Publica alerta DNS con deduplicación O(1)."""
    key = _dedup_key(category, description)
    with _dedup_lock:
        if key in _dns_dedup:
            return
        _dns_dedup.add(key)
        if len(_dns_dedup) > _DEDUP_MAX_SIZE:
            _dns_dedup.clear()

    publish(SecurityAlert.now(
        engine="dns",
        category=category,
        severity="HIGH" if "TÚNEL" in category else "MEDIUM",
        description=description,
        source_ip=qname,
        dest_ip="port/53",
        mitre_technique_id="T1071.004",
        mitre_technique_name="DNS (Application Layer Protocol)",
        mitre_tactic="Command and Control",
        nist_controls=("PR.PT-4",),
        iso_controls=("A.13.1.1",),
    ))


def _publish_dlp_alert(
    category: str,
    file_type: str,
    description: str,
    src_ip: str,
    dst_ip: str,
) -> None:
    """Publica alerta DLP con deduplicación O(1)."""
    key = _dedup_key(category, description)
    with _dedup_lock:
        if key in _dlp_dedup:
            return
        _dlp_dedup.add(key)
        if len(_dlp_dedup) > _DEDUP_MAX_SIZE:
            _dlp_dedup.clear()

    publish(SecurityAlert.now(
        engine="dlp",
        category=category,
        severity="HIGH",
        description=f"[{file_type}] {description}",
        source_ip=src_ip,
        dest_ip=dst_ip,
        mitre_technique_id="T1048",
        mitre_technique_name="Exfiltration Over Alternative Protocol",
        mitre_tactic="Exfiltration",
        nist_controls=("PR.DS-5",),
        iso_controls=("A.8.2.3",),
    ))


def _publish_scan_alert(src_ip: str, dst_ip: str, description: str) -> None:
    """Publica alerta de escaneo de puertos (NDR) con deduplicación O(1)."""
    key = _dedup_key("ESCANEO PUERTOS", description)
    with _dedup_lock:
        if key in _dlp_dedup:
            return
        _dlp_dedup.add(key)
        if len(_dlp_dedup) > _DEDUP_MAX_SIZE:
            _dlp_dedup.clear()

    publish(SecurityAlert.now(
        engine="ndr",
        category="Escaneo de Puertos",
        severity="HIGH",
        description=description,
        source_ip=src_ip,
        dest_ip=dst_ip,
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        mitre_tactic="Discovery",
        nist_controls=("DE.AE-2",),
        iso_controls=("A.13.1.1",),
    ))


def _check_port_scan(src_ip: str, dst_ip: str, dst_port: int) -> None:
    """Detecta escaneo de puertos (SYN scan) en una ventana deslizante de 10s."""
    now = time.monotonic()
    key = (src_ip, dst_ip)
    with _lock:
        # Prevent unbounded growth by periodically cleaning stale keys
        if len(_scan_tracker) > 2000:
            stale_keys = [k for k, v in _scan_tracker.items() if now - v[1] > 60.0]
            for k in stale_keys:
                if k != key:
                    del _scan_tracker[k]

        if key not in _scan_tracker:
            _scan_tracker[key] = (set(), now)
        
        ports, last_ts = _scan_tracker[key]
        if now - last_ts > 10.0:
            ports = set()
        
        ports.add(dst_port)
        _scan_tracker[key] = (ports, now)
        
        if len(ports) >= 15:
            description = f"Escaneo de puertos detectado desde {src_ip} hacia {dst_ip} ({len(ports)} puertos en <10s)"
            ports.clear()  # reset to avoid flood
            _publish_scan_alert(src_ip, dst_ip, description)


# ─── Procesamiento de paquetes ────────────────────────────────────────────────

def _process_dns(packet) -> None:
    """Analiza un paquete DNS en busca de DGA y tunneling."""
    if not packet.haslayer(DNSQR) or packet[DNS].qr != 0:
        return

    qname: str = packet[DNSQR].qname.decode("utf-8", errors="ignore")
    qtype: int = packet[DNSQR].qtype

    # 1. DGA: any() hace short-circuit en el primer subdomain positivo
    if any(is_dga_domain(sub) for sub in qname.split(".")[:-1]):
        _publish_dns_alert("DGA", qname, f"Posible dominio DGA detectado: {qname}")

    # 2. DNS Tunneling por frecuencia de consultas al mismo dominio raíz
    parent = get_parent_domain(qname)
    if parent:
        now = time.monotonic()  # monotonic: no salta por ajustes de NTP/reloj
        with _lock:
            # Prevent unbounded growth
            if len(_dns_tracker) > 2000:
                stale = [d for d, q in _dns_tracker.items() if not q or now - q[-1] > 60.0]
                for d in stale:
                    if d != parent:
                        del _dns_tracker[d]

            tracker = _dns_tracker.setdefault(parent, deque())
            tracker.append(now)
            # Trim O(1) por la izquierda: eliminamos entradas fuera de ventana
            while tracker and now - tracker[0] > _DNS_TUNNEL_WINDOW_SECS:
                tracker.popleft()

            if len(tracker) > _DNS_TUNNEL_THRESHOLD:
                _publish_dns_alert(
                    "TÚNEL DNS",
                    qname,
                    f"Inundación DNS a '{parent}': {len(tracker)} queries "
                    f"en {_DNS_TUNNEL_WINDOW_SECS:.0f}s (posible túnel)",
                )
                tracker.clear()

    # 3. Query TXT con payload excesivamente largo
    if qtype == 16 and len(qname) > 100:
        _publish_dns_alert(
            "TÚNEL DNS (TXT)",
            qname,
            f"Query TXT anómalamente larga: {len(qname)} bytes → posible exfiltración",
        )


def _process_tcp(packet, src_ip: str, dst_ip: str) -> None:
    """Muestrea los primeros 256 bytes de cada flujo TCP para análisis DLP."""
    tcp = packet[TCP]
    payload = bytes(tcp.payload)
    if not payload:
        return

    flow_key = (src_ip, tcp.sport, dst_ip, tcp.dport)

    with _lock:
        already_sampled = _sampled_flows.get(flow_key, 0)

        if already_sampled >= _SAMPLE_BYTES:
            return

        chunk_size = min(len(payload), _SAMPLE_BYTES - already_sampled)
        sample = payload[:chunk_size]

        # LRU eviction: mover al final + eliminar el más antiguo si supera límite
        _sampled_flows[flow_key] = already_sampled + chunk_size
        _sampled_flows.move_to_end(flow_key)
        if len(_sampled_flows) > _MAX_FLOW_CACHE:
            _sampled_flows.popitem(last=False)  # O(1) con OrderedDict

    ent = calculate_entropy(sample)

    with _lock:
        _entropy_history.append(ent)  # O(1) — deque(maxlen=100) hace trim automático
        import datetime as _dt
        _entropy_timed.append((_dt.datetime.now().strftime("%H:%M:%S"), round(ent, 3)))

    if ent > _HIGH_ENTROPY_THRESHOLD:
        _publish_dlp_alert(
            "ALTA ENTROPÍA",
            "Datos Cifrados/Ofuscados",
            f"Posible exfiltración (entropía={ent:.2f}/8.0) [{src_ip}→{dst_ip}]",
            src_ip, dst_ip,
        )

    # Solo en el primer paquete del flujo revisamos magic bytes del header
    if already_sampled == 0:
        file_type = detect_magic_bytes(sample)
        if file_type != "UNKNOWN":
            _publish_dlp_alert(
                "TRANSFERENCIA ARCHIVO",
                file_type,
                f"Archivo detectado en tráfico de red: {file_type} [{src_ip}→{dst_ip}]",
                src_ip, dst_ip,
            )


def packet_callback(packet) -> None:
    """
    Callback invocado por Scapy para cada paquete capturado.
    Diseño: lo más delgado posible — solo clasifica y delega.
    """
    if _stop_event.is_set():
        return

    try:
        with _lock:
            _stats["packet_count"] += 1
            _stats["bytes_total"] += len(packet)

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        else:
            return

        if packet.haslayer(UDP) and packet[UDP].dport == 53:
            with _lock:
                _stats["udp_count"] += 1
                _stats["dns_count"] += 1
            _process_dns(packet)
            return

        if packet.haslayer(TCP):
            with _lock:
                _stats["tcp_count"] += 1
            tcp = packet[TCP]
            is_syn = False
            if tcp.flags is not None:
                try:
                    flags_val = int(tcp.flags)
                    is_syn = (flags_val & 0x02) != 0
                except (ValueError, TypeError):
                    is_syn = 'S' in str(tcp.flags)
            if is_syn:
                _check_port_scan(src_ip, dst_ip, tcp.dport)
            _process_tcp(packet, src_ip, dst_ip)

    except Exception:
        # Debug level: paquetes malformados son comunes en redes reales.
        # NUNCA silencio con 'pass'. El log preserva la traza para análisis.
        log.debug("Error procesando paquete (no crítico):", exc_info=True)


# ─── API Pública ──────────────────────────────────────────────────────────────

def start_analyzer() -> bool:
    """Inicia el sniffer de Scapy en un hilo daemon."""
    global _sniff_thread

    if _sniff_thread and _sniff_thread.is_alive():
        return True

    _stop_event.clear()

    def _run() -> None:
        try:
            try:
                sniff(
                    iface="any",
                    filter="udp port 53 or tcp",
                    prn=packet_callback,
                    store=False,
                    stop_filter=lambda _: _stop_event.is_set(),
                )
            except Exception:
                sniff(
                    filter="udp port 53 or tcp",
                    prn=packet_callback,
                    store=False,
                    stop_filter=lambda _: _stop_event.is_set(),
                )
        except PermissionError:
            log.error(
                "Scapy requiere CAP_NET_RAW para capturar paquetes. "
                "Ejecuta TCPspecter con 'sudo' o configura: "
                "sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
            )
        except Exception:
            log.exception("Error fatal en el sniffer de Scapy.")

    _sniff_thread = threading.Thread(
        target=_run,
        name="scapy-sniffer",
        daemon=True,
    )
    _sniff_thread.start()
    return True


def stop_analyzer() -> bool:
    """Señaliza al sniffer que pare. Non-blocking."""
    _stop_event.set()
    return True


def get_live_metrics() -> dict:
    """
    Snapshot thread-safe de las métricas de tráfico actuales.

    NOTA: Esta función es SOLO de lectura. No tiene side effects destructivos.
    La limpieza de caché se hace implícitamente en el ciclo de escritura (_process_tcp).
    """
    with _lock:
        avg_entropy = (
            sum(_entropy_history) / len(_entropy_history)
            if _entropy_history else 0.0
        )
        # Export timed series: list of [label, value] pairs
        timed = list(_entropy_timed)
        return {
            "stats": dict(_stats),
            "avg_entropy": round(avg_entropy, 2),
            "entropy_history": {
                "labels": [t[0] for t in timed],
                "values": [t[1] for t in timed],
            },
        }

# backward compat alias
check_dga_domain = is_dga_domain

