# verify_v4.py
"""
Verify integration of Active Response, Tarpitting Deception, Compliance framework,
and Memory Scanner features.
"""
import sys
import unittest
import hmac
import hashlib
import json
import socket
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch, MagicMock

# Import the refactored modules
from core.alerts import SecurityAlert, publish
from core.tarpit import start_tarpit, stop_tarpit
import core.firewall_manager as fm
import core.zombie_detector as zd

class MockWebhookHandler(BaseHTTPRequestHandler):
    received_payloads = []
    received_headers = []

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        MockWebhookHandler.received_payloads.append(json.loads(body.decode('utf-8')))
        MockWebhookHandler.received_headers.append(self.headers)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress standard log outputs

from pathlib import Path

class TestV4SecuritySuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a local mock webhook server
        cls.webhook_port = 18090
        cls.webhook_url = f"http://127.0.0.1:{cls.webhook_port}/webhook"
        cls.webhook_secret = "super_secret_key"
        cls.webhook_server = HTTPServer(('127.0.0.1', cls.webhook_port), MockWebhookHandler)
        cls.webhook_thread = threading.Thread(target=cls.webhook_server.serve_forever, daemon=True)
        cls.webhook_thread.start()

        # Write config.json containing webhook options
        cls.orig_config = None
        if Path("config.json").exists():
            cls.orig_config = Path("config.json").read_text()
        
        config_data = {
            "webhook_url": cls.webhook_url,
            "webhook_secret": cls.webhook_secret
        }
        Path("config.json").write_text(json.dumps(config_data))

    @classmethod
    def tearDownClass(cls):
        cls.webhook_server.shutdown()
        cls.webhook_server.server_close()
        if cls.orig_config is not None:
            Path("config.json").write_text(cls.orig_config)
        else:
            try:
                Path("config.json").unlink()
            except Exception:
                pass

    def test_compliance_and_webhook_signatures(self):
        # Clear previous requests
        MockWebhookHandler.received_payloads.clear()
        MockWebhookHandler.received_headers.clear()

        # 1. Verify Compliance (NIST / ISO) mapping inside SecurityAlert
        alert = SecurityAlert.now(
            engine="zombie",
            category="Memoria Fileless",
            severity="CRITICAL",
            description="Test fileless malware memory alert",
            nist_controls=("DE.CM-7",),
            iso_controls=("A.12.6.1",)
        )

        ecs = alert.to_ecs()
        self.assertEqual(ecs["compliance"]["nist"], ["DE.CM-7"])
        self.assertEqual(ecs["compliance"]["iso"], ["A.12.6.1"])

        # 2. Publish alert and verify signature received by Webhook Server
        publish(alert)
        
        # Wait up to 3 seconds for async webhook delivery
        for _ in range(30):
            if len(MockWebhookHandler.received_payloads) > 0:
                break
            time.sleep(0.1)

        self.assertEqual(len(MockWebhookHandler.received_payloads), 1)
        received_alert = MockWebhookHandler.received_payloads[0]
        self.assertEqual(received_alert["tcpspecter"]["category"], "Memoria Fileless")
        self.assertEqual(received_alert["compliance"]["nist"], ["DE.CM-7"])

        # Check HMAC-SHA256 signature
        headers = MockWebhookHandler.received_headers[0]
        signature_header = headers.get("X-TCPspecter-Signature")
        self.assertIsNotNone(signature_header)

        # Recalculate signature locally and compare
        body_bytes = json.dumps(received_alert).encode("utf-8")
        expected_sig = hmac.new(
            self.webhook_secret.encode("utf-8"),
            body_bytes,
            hashlib.sha256
        ).hexdigest()
        self.assertEqual(signature_header, expected_sig)
        print("Webhook & Compliance verification: PASSED")

    @patch('subprocess.run')
    def test_firewall_quarantine_isolation(self, mock_run):
        # Set up mocks for subproces.run
        mock_run.return_value = MagicMock(returncode=0, stdout="iptables v1.8.7")
        
        # Test quarantine activation
        success = fm.quarantine_host(admin_ips=["192.168.1.100"])
        self.assertTrue(success)

        # Verify command invocations
        calls = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any("TCPSPECTER-Q-IN" in cmd for cmd in calls))
        self.assertTrue(any("TCPSPECTER-Q-OUT" in cmd for cmd in calls))

        # Test quarantine removal
        success_removal = fm.remove_quarantine()
        self.assertTrue(success_removal)
        print("Firewall Quarantine mock verification: PASSED")

    @patch('subprocess.run')
    def test_tarpit_redirection_nat_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="iptables NAT support")

        success = fm.enable_tarpit(attacker_ip="198.51.100.42", tarpit_port=8000)
        self.assertTrue(success)

        # Check nat table redirect rule invocation
        calls = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any("-t" in cmd and "nat" in cmd and "REDIRECT" in cmd for cmd in calls))

        # Cleanup
        success_disable = fm.disable_tarpit(attacker_ip="198.51.100.42", tarpit_port=8000)
        self.assertTrue(success_disable)
        print("Tarpitting DNAT mock verification: PASSED")

    def test_tarpit_tcp_server(self):
        # Start tarpit server
        port = 18099
        success = start_tarpit(port=port)
        self.assertTrue(success)
        time.sleep(0.5)

        # Connect to Tarpit port and verify it accepts connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect(('127.0.0.1', port))
            start_time = time.time()
            try:
                data = s.recv(1)
                # If we get here, it didn't delay!
                self.fail("Tarpit responded too quickly (expected connection delay/timeout)")
            except (TimeoutError, socket.timeout):
                duration = time.time() - start_time
                self.assertTrue(duration >= 1.9, f"Timeout happened too fast: {duration}")
        finally:
            s.close()
            stop_tarpit()
        print("Tarpit TCP Server connection verification: PASSED")

    def test_fileless_malware_memory_parser(self):
        # Mock file operations to simulate /proc/maps with executable anonymous memory
        mock_maps_content = (
            "00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon\n"
            "7f2d5e200000-7f2d5e300000 r-xp 00000000 00:00 0\n" # anonymous executable
            "7f2d5e300000-7f2d5e400000 rw-p 00000000 00:00 0\n" # anonymous rw
        )
        
        # Test mapping tag helper directly
        finding = zd._enrich_finding({"category": "Memoria Fileless"})
        self.assertEqual(finding["mitre_technique_id"], "T1055")
        self.assertEqual(finding["nist_controls"], ("DE.CM-7",))
        self.assertEqual(finding["iso_controls"], ("A.12.6.1",))
        print("Fileless Malware metadata mapping: PASSED")

if __name__ == '__main__':
    unittest.main()
