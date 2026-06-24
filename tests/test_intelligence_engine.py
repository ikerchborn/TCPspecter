"""Tests for the threat intelligence engine."""
import os
import tempfile
import unittest
from pathlib import Path

from core.intelligence_engine import IntelligenceEngine
from core.service_catalog import lookup_service, describe_port


class TestIntelligenceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = IntelligenceEngine()
        self.feed_dir = Path(__file__).resolve().parent.parent / "data" / "feeds"
        self.engine.configure({
            "INTELLIGENCE_ENABLED": True,
            "INTELLIGENCE_FEED_DIR": str(self.feed_dir),
        })

    def test_loads_port_feed(self):
        intel = self.engine.match_port(4444)
        self.assertIsNotNone(intel)
        self.assertEqual(intel.label, "Metasploit handler")

    def test_match_tor_ip_from_feed(self):
        tor_file = self.feed_dir / "tor_exit_nodes.txt"
        if not tor_file.exists():
            self.skipTest("tor_exit_nodes.txt not present")
        first_ip = next(
            line.strip()
            for line in tor_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        )
        match = self.engine.match_ip(first_ip)
        self.assertIsNotNone(match)
        self.assertEqual(match.category, "tor")

    def test_match_dyndns_domain(self):
        match = self.engine.match_domain("malware-bot.no-ip.org")
        self.assertIsNotNone(match)
        self.assertEqual(match.category, "dyndns")

    def test_match_suspicious_tld(self):
        match = self.engine.match_domain("login-update.xyz")
        self.assertIsNotNone(match)
        self.assertEqual(match.category, "tld")

    def test_custom_blacklist_cidr(self):
        with tempfile.TemporaryDirectory() as tmp:
            bl_path = Path(tmp) / "custom_blacklist.txt"
            bl_path.write_text("203.0.113.0/24\n")
            engine = IntelligenceEngine()
            engine.configure({
                "INTELLIGENCE_ENABLED": True,
                "INTELLIGENCE_FEED_DIR": tmp,
            })
            match = engine.match_ip("203.0.113.55")
            self.assertIsNotNone(match)
            self.assertEqual(match.category, "blacklist")

    def test_stats_report_feeds(self):
        stats = self.engine.get_stats()
        self.assertTrue(stats.enabled)
        self.assertGreater(stats.total_entries, 0)
        self.assertGreater(len(stats.feeds), 0)


class TestServiceCatalog(unittest.TestCase):
    def test_builtin_port(self):
        self.assertEqual(lookup_service(443, "TCP"), "HTTPS")

    def test_intel_port_overrides_builtin(self):
        from core.intelligence_engine import initialize_intelligence
        initialize_intelligence()
        label = lookup_service(4444, "TCP")
        self.assertEqual(label, "Metasploit handler")

    def test_describe_port_includes_context(self):
        from core.intelligence_engine import initialize_intelligence
        initialize_intelligence()
        desc = describe_port(4444, "TCP", "en")
        self.assertIsNotNone(desc)
        self.assertIn("4444", desc)


if __name__ == "__main__":
    unittest.main()
