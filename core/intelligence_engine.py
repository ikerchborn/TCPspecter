"""
Threat intelligence feed loader and matcher.

Loads local CSV/text feeds from data/feeds/, indexes them for fast lookups,
and publishes normalized SecurityAlert events through the Alert Bus when
matches occur during connection or DNS analysis.
"""
from __future__ import annotations

import csv
import ipaddress
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from core.alerts import SecurityAlert, publish

log = logging.getLogger(__name__)

_BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent
_DEFAULT_FEED_DIR: Final[Path] = _BASE_DIR / "data" / "feeds"

Confidence = Literal["high", "medium", "low", "info"]

_CONFIDENCE_TO_SEVERITY: Final[dict[str, str]] = {
    "high": "CRITICAL",
    "medium": "HIGH",
    "low": "MEDIUM",
    "info": "LOW",
}

_MITRE_BY_CATEGORY: Final[dict[str, tuple[str, str, str]]] = {
    "C2": ("T1071", "Application Layer Protocol", "Command and Control"),
    "malware": ("T1071", "Application Layer Protocol", "Command and Control"),
    "RAT": ("T1219", "Remote Access Software", "Command and Control"),
    "miner": ("T1496", "Resource Hijacking", "Impact"),
    "anonymity": ("T1090", "Proxy", "Command and Control"),
    "sinkhole": ("T1071", "Application Layer Protocol", "Command and Control"),
    "dyndns": ("T1568", "Dynamic Resolution", "Command and Control"),
    "tld": ("T1568.002", "Domain Generation Algorithms", "Command and Control"),
    "blacklist": ("T1071", "Application Layer Protocol", "Command and Control"),
    "tor": ("T1090.003", "Multi-hop Proxy", "Command and Control"),
}


@dataclass(frozen=True, slots=True)
class PortIntel:
    port: int
    label: str
    category: str
    confidence: Confidence
    description: str


@dataclass(frozen=True, slots=True)
class ThreatMatch:
    feed: str
    match_type: str
    value: str
    label: str
    category: str
    confidence: Confidence
    description: str
    severity: str


@dataclass
class FeedStatus:
    name: str
    path: str
    loaded: bool
    entry_count: int
    last_loaded: str
    error: str = ""


@dataclass
class IntelligenceStats:
    enabled: bool = True
    feed_dir: str = ""
    feeds: list[FeedStatus] = field(default_factory=list)
    total_entries: int = 0
    match_count: int = 0
    recent_matches: list[dict] = field(default_factory=list)
    last_reload: str = ""


class IntelligenceEngine:
    """Thread-safe threat intelligence matcher backed by local feed files."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._enabled = True
        self._feed_dir = _DEFAULT_FEED_DIR
        self._ports: dict[int, PortIntel] = {}
        self._ip_networks: list[tuple[ipaddress._BaseNetwork, str, str, Confidence, str]] = []
        self._exact_ips: dict[str, tuple[str, str, Confidence, str]] = {}
        self._domain_suffixes: list[tuple[str, str, str, Confidence, str]] = []
        self._sinkhole_domains: set[str] = set()
        self._suspicious_tlds: set[str] = set()
        self._feed_status: list[FeedStatus] = []
        self._match_count = 0
        self._recent_matches: list[dict] = []
        self._dedup: set[str] = set()
        self._last_reload = ""

    # ── Configuration ─────────────────────────────────────────────────────

    def configure(self, config: dict) -> None:
        enabled = config.get("INTELLIGENCE_ENABLED", True)
        feed_dir = config.get("INTELLIGENCE_FEED_DIR", "data/feeds")
        path = Path(feed_dir)
        if not path.is_absolute():
            path = _BASE_DIR / path
        with self._lock:
            self._enabled = bool(enabled)
            self._feed_dir = path
        self.reload()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, value: bool) -> None:
        with self._lock:
            self._enabled = value

    # ── Feed loading ────────────────────────────────────────────────────────

    def reload(self) -> IntelligenceStats:
        with self._lock:
            self._ports.clear()
            self._ip_networks.clear()
            self._exact_ips.clear()
            self._domain_suffixes.clear()
            self._sinkhole_domains.clear()
            self._suspicious_tlds.clear()
            self._feed_status.clear()
            self._dedup.clear()

            feed_dir = self._feed_dir
            if not feed_dir.is_dir():
                log.warning("Intelligence feed directory missing: %s", feed_dir)
                self._last_reload = _utc_now()
                return self.get_stats()

            loaders = (
                ("suspicious_ports", feed_dir / "suspicious_ports.csv", self._load_ports_csv),
                ("tor_exit_nodes", feed_dir / "tor_exit_nodes.txt", self._load_tor_ips),
                ("sinkholed_ips", feed_dir / "sinkholed_ips.txt", self._load_ip_list_file),
                ("sinkholed_domains", feed_dir / "sinkholed_domains.txt", self._load_domain_file),
                ("dyndns_domains", feed_dir / "dyndns_domains.txt", self._load_dyndns_file),
                ("suspicious_tlds", feed_dir / "suspicious_tlds.txt", self._load_tld_file),
                ("custom_blacklist", feed_dir / "custom_blacklist.txt", self._load_blacklist_file),
            )

            for name, path, loader in loaders:
                status = FeedStatus(
                    name=name,
                    path=str(path),
                    loaded=False,
                    entry_count=0,
                    last_loaded=_utc_now(),
                )
                if not path.exists():
                    status.error = "file not found"
                    self._feed_status.append(status)
                    continue
                try:
                    count = loader(path)
                    status.loaded = True
                    status.entry_count = count
                except OSError as exc:
                    status.error = str(exc)
                    log.error("Failed loading feed %s: %s", name, exc)
                self._feed_status.append(status)

            self._last_reload = _utc_now()
            total = (
                len(self._ports)
                + len(self._exact_ips)
                + len(self._ip_networks)
                + len(self._domain_suffixes)
                + len(self._sinkhole_domains)
                + len(self._suspicious_tlds)
            )
            log.info(
                "Intelligence feeds loaded from %s (%d indexed entries)",
                feed_dir,
                total,
            )
            return self.get_stats()

    def _load_ports_csv(self, path: Path) -> int:
        count = 0
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    port = int(row.get("port", "").strip())
                except (TypeError, ValueError):
                    continue
                confidence = _normalize_confidence(row.get("confidence", "medium"))
                intel = PortIntel(
                    port=port,
                    label=(row.get("label") or f"Port {port}").strip(),
                    category=(row.get("category") or "malware").strip().lower(),
                    confidence=confidence,
                    description=(row.get("description") or "").strip(),
                )
                self._ports[port] = intel
                count += 1
        return count

    def _load_tor_ips(self, path: Path) -> int:
        count = 0
        for line in _iter_lines(path):
            try:
                ipaddress.ip_address(line)
            except ValueError:
                continue
            self._exact_ips[line] = (
                "Tor Exit Node",
                "tor",
                "high",
                f"Remote IP {line} matches a known Tor exit node",
            )
            count += 1
        return count

    def _load_ip_list_file(self, path: Path) -> int:
        count = 0
        for line in _iter_lines(path):
            try:
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    self._ip_networks.append(
                        (net, "Sinkholed Network", "sinkhole", "high", line)
                    )
                else:
                    ipaddress.ip_address(line)
                    self._exact_ips[line] = (
                        "Sinkholed IP",
                        "sinkhole",
                        "high",
                        f"Remote IP {line} matches a sinkholed address",
                    )
                count += 1
            except ValueError:
                continue
        return count

    def _load_domain_file(self, path: Path) -> int:
        count = 0
        for line in _iter_lines(path):
            domain = line.lower().strip(".")
            self._sinkhole_domains.add(domain)
            count += 1
        return count

    def _load_dyndns_file(self, path: Path) -> int:
        count = 0
        for line in _iter_lines(path):
            suffix = line.lower().strip(".")
            self._domain_suffixes.append(
                (suffix, "Dynamic DNS Provider", "dyndns", "medium", suffix)
            )
            count += 1
        return count

    def _load_tld_file(self, path: Path) -> int:
        count = 0
        for line in _iter_lines(path):
            tld = line.lower().strip(".")
            self._suspicious_tlds.add(tld)
            count += 1
        return count

    def _load_blacklist_file(self, path: Path) -> int:
        count = 0
        for line in _iter_lines(path):
            try:
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    self._ip_networks.append(
                        (net, "Custom Blacklist", "blacklist", "high", line)
                    )
                else:
                    ipaddress.ip_address(line)
                    self._exact_ips[line] = (
                        "Custom Blacklist",
                        "blacklist",
                        "high",
                        f"Remote IP {line} matches operator blacklist",
                    )
                count += 1
            except ValueError:
                continue
        return count

    # ── Matchers ────────────────────────────────────────────────────────────

    def match_port(self, port: int) -> PortIntel | None:
        if not self._enabled:
            return None
        with self._lock:
            return self._ports.get(port)

    def match_ip(self, ip_str: str) -> ThreatMatch | None:
        if not self._enabled or not ip_str or ip_str in ("-", "*"):
            return None
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        with self._lock:
            if ip_str in self._exact_ips:
                label, category, confidence, description = self._exact_ips[ip_str]
                return ThreatMatch(
                    feed="ip_feed",
                    match_type="ip",
                    value=ip_str,
                    label=label,
                    category=category,
                    confidence=confidence,
                    description=description,
                    severity=_CONFIDENCE_TO_SEVERITY.get(confidence, "HIGH"),
                )

            for net, label, category, confidence, raw in self._ip_networks:
                if ip in net:
                    return ThreatMatch(
                        feed="ip_network_feed",
                        match_type="ip",
                        value=ip_str,
                        label=label,
                        category=category,
                        confidence=confidence,
                        description=f"Remote IP {ip_str} falls within flagged network {raw}",
                        severity=_CONFIDENCE_TO_SEVERITY.get(confidence, "HIGH"),
                    )
        return None

    def match_domain(self, fqdn: str) -> ThreatMatch | None:
        if not self._enabled or not fqdn:
            return None

        domain = fqdn.lower().rstrip(".")
        if domain.endswith("."):
            domain = domain[:-1]

        with self._lock:
            for sink in self._sinkhole_domains:
                if domain == sink or domain.endswith("." + sink):
                    return ThreatMatch(
                        feed="sinkholed_domains",
                        match_type="domain",
                        value=domain,
                        label="Sinkholed Domain",
                        category="sinkhole",
                        confidence="high",
                        description=f"DNS query targets sinkholed domain: {domain}",
                        severity="CRITICAL",
                    )

            for suffix, label, category, confidence, _raw in self._domain_suffixes:
                if domain == suffix or domain.endswith("." + suffix):
                    return ThreatMatch(
                        feed="dyndns_domains",
                        match_type="domain",
                        value=domain,
                        label=label,
                        category=category,
                        confidence=confidence,
                        description=f"DNS query uses dynamic DNS provider: {domain}",
                        severity=_CONFIDENCE_TO_SEVERITY.get(confidence, "MEDIUM"),
                    )

            tld = _extract_tld(domain)
            if tld and tld in self._suspicious_tlds:
                return ThreatMatch(
                    feed="suspicious_tlds",
                    match_type="tld",
                    value=tld,
                    label="Suspicious TLD",
                    category="tld",
                    confidence="medium",
                    description=f"DNS query uses high-abuse TLD .{tld}: {domain}",
                    severity="MEDIUM",
                )
        return None

    def get_port_label(self, port: int) -> str | None:
        intel = self.match_port(port)
        return intel.label if intel else None

    def get_all_ports(self) -> dict[int, PortIntel]:
        with self._lock:
            return dict(self._ports)

    # ── Alert publishing ────────────────────────────────────────────────────

    def publish_port_match(
        self,
        port: int,
        remote_ip: str,
        pid: int | None = None,
        proc_name: str = "",
    ) -> bool:
        intel = self.match_port(port)
        if not intel:
            return False
        severity = _CONFIDENCE_TO_SEVERITY.get(intel.confidence, "HIGH")
        desc = (
            f"Connection to flagged port {port} ({intel.label}) "
            f"on {remote_ip}"
        )
        if intel.description:
            desc = f"{desc} — {intel.description}"
        return self._publish_match(
            category="Threat Port Match",
            severity=severity,
            description=desc,
            source_ip=remote_ip,
            dest_ip=f"port/{port}",
            pid=pid,
            proc_name=proc_name,
            intel_category=intel.category,
            dedup_key=f"port:{port}:{remote_ip}:{pid}",
        )

    def publish_threat_match(
        self,
        match: ThreatMatch,
        pid: int | None = None,
        proc_name: str = "",
        source_ip: str = "",
        dest_ip: str = "",
    ) -> bool:
        category_map = {
            "tor": "Tor Exit Node",
            "sinkhole": "Sinkholed Infrastructure",
            "dyndns": "Dynamic DNS Provider",
            "tld": "Suspicious TLD",
            "blacklist": "Custom Blacklist Hit",
        }
        category = category_map.get(match.category, match.label)
        return self._publish_match(
            category=category,
            severity=match.severity,
            description=match.description,
            source_ip=source_ip or match.value,
            dest_ip=dest_ip,
            pid=pid,
            proc_name=proc_name,
            intel_category=match.category,
            dedup_key=f"{match.match_type}:{match.value}:{pid}:{proc_name}",
        )

    def _publish_match(
        self,
        category: str,
        severity: str,
        description: str,
        source_ip: str,
        dest_ip: str,
        pid: int | None,
        proc_name: str,
        intel_category: str,
        dedup_key: str,
    ) -> bool:
        with self._lock:
            if dedup_key in self._dedup:
                return False
            self._dedup.add(dedup_key)
            if len(self._dedup) > 5000:
                self._dedup.clear()

        mitre = _MITRE_BY_CATEGORY.get(intel_category, _MITRE_BY_CATEGORY["malware"])
        publish(SecurityAlert.now(
            engine="intelligence",
            category=category,
            severity=severity,  # type: ignore[arg-type]
            description=description,
            source_ip=source_ip,
            dest_ip=dest_ip,
            pid=pid,
            proc_name=proc_name,
            mitre_technique_id=mitre[0],
            mitre_technique_name=mitre[1],
            mitre_tactic=mitre[2],
            nist_controls=("DE.AE-2",),
            iso_controls=("A.13.1.1",),
        ))

        record = {
            "timestamp": _utc_now(),
            "category": category,
            "severity": severity,
            "description": description,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "proc_name": proc_name,
            "pid": pid,
        }
        with self._lock:
            self._match_count += 1
            self._recent_matches.append(record)
            if len(self._recent_matches) > 100:
                self._recent_matches.pop(0)
        return True

    # ── Status API ────────────────────────────────────────────────────────

    def get_stats(self) -> IntelligenceStats:
        with self._lock:
            total = (
                len(self._ports)
                + len(self._exact_ips)
                + len(self._ip_networks)
                + len(self._domain_suffixes)
                + len(self._sinkhole_domains)
                + len(self._suspicious_tlds)
            )
            return IntelligenceStats(
                enabled=self._enabled,
                feed_dir=str(self._feed_dir),
                feeds=[FeedStatus(
                    name=f.name,
                    path=f.path,
                    loaded=f.loaded,
                    entry_count=f.entry_count,
                    last_loaded=f.last_loaded,
                    error=f.error,
                ) for f in self._feed_status],
                total_entries=total,
                match_count=self._match_count,
                recent_matches=list(reversed(self._recent_matches[-20:])),
                last_reload=self._last_reload,
            )


# ── Module singleton ────────────────────────────────────────────────────────

_engine: IntelligenceEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> IntelligenceEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = IntelligenceEngine()
        return _engine


def initialize_intelligence(config: dict | None = None) -> IntelligenceStats:
    """Load configuration and reload all feeds. Safe to call multiple times."""
    engine = get_engine()
    if config is None:
        config = _load_config()
    engine.configure(config)
    return engine.get_stats()


def _load_config() -> dict:
    config_path = _BASE_DIR / "config.json"
    if not config_path.exists():
        return {"INTELLIGENCE_ENABLED": True, "INTELLIGENCE_FEED_DIR": "data/feeds"}
    try:
        import json
        with config_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"INTELLIGENCE_ENABLED": True, "INTELLIGENCE_FEED_DIR": "data/feeds"}


def _utc_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_confidence(value: str | None) -> Confidence:
    val = (value or "medium").strip().lower()
    if val in ("high", "medium", "low", "info"):
        return val  # type: ignore[return-value]
    return "medium"


def _extract_tld(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) < 2:
        return ""
    return parts[-1]


def _iter_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            yield line
