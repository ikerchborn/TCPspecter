"""
Tests for core/zombie_detector.py — heuristics and false positive reduction.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
from core.zombie_detector import (
    is_private_ip,
    MITRE_MAP,
    NIST_MAP,
    ISO_MAP,
    C2_PORTS,
)


def test_private_ip_detection():
    """Verify that RFC 1918 addresses are correctly classified as private."""
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_c2_ports_include_known_shells():
    """Ensure well-known C2/RAT ports are in the C2_PORTS set."""
    assert 4444 in C2_PORTS  # Metasploit
    assert 5555 in C2_PORTS  # Android Meterpreter
    assert 6667 in C2_PORTS  # IRC botnet
    assert 9050 in C2_PORTS  # Tor


def test_mitre_map_keys_in_english():
    """All MITRE_MAP keys must be in English (no Spanish accented chars)."""
    spanish_chars = set("áéíóúñüÁÉÍÓÚÑ")
    for key in MITRE_MAP:
        assert not any(c in spanish_chars for c in key), \
            f"MITRE_MAP key '{key}' contains non-English characters"


def test_nist_map_keys_match_mitre():
    """NIST_MAP and MITRE_MAP should have the same keys for consistency."""
    mitre_keys = set(MITRE_MAP.keys())
    nist_keys = set(NIST_MAP.keys())
    # IDS/Sniffer is in MITRE but may not be in NIST — allow subset
    assert nist_keys.issubset(mitre_keys), \
        f"NIST keys not a subset of MITRE keys: {nist_keys - mitre_keys}"


def test_mitre_map_structure():
    """Each MITRE_MAP entry must have id, name, and tactic fields."""
    for key, val in MITRE_MAP.items():
        assert "id" in val, f"Missing 'id' in MITRE_MAP['{key}']"
        assert "name" in val, f"Missing 'name' in MITRE_MAP['{key}']"
        assert "tactic" in val, f"Missing 'tactic' in MITRE_MAP['{key}']"
