"""
test_checks.py

Automated unit and integration tests using Python's standard library (unittest).
Runs rapidly without external dependencies or live hardware.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import unittest

from iotsploit.core.device_profile import DeviceProfile, HttpEndpoint
from iotsploit.core.scoring import Finding
from iotsploit.checks.capability_checks import (
    check_http_auth,
    skipped_finding,
)
from iotsploit.checks.firmware_audit import (
    scan_for_secrets,
    calculate_shannon_entropy,
)
from tests.mock_devices import MockHTTPServer


class TestCapabilityChecks(unittest.TestCase):

    def setUp(self):
        self.profile = DeviceProfile(
            device_id="test_plug",
            vendor="TestVendor",
            model="PlugGen1",
            protocols=["http", "mqtt", "ble"],
            http_base_url="http://{ip}:8888",
            http_endpoints=[
                HttpEndpoint(path="/relay/0", method="GET", expect_auth=True, description="Relay 0 state"),
                HttpEndpoint(path="/secure/settings", method="GET", expect_auth=True, description="Settings"),
            ],
            mqtt_topic_prefix="test/plug",
            mqtt_expected_tls=False,
            ble_name_pattern="TestPlug",
            known_cves=[],
            flagged_ports=[],
            coap_endpoints=[],
            authorized=False,
        )

    def test_skipped_finding_when_unauthorized(self):
        # By default, state-changing check without authorization skips and returns skipped findings
        findings = check_http_auth(self.profile, "127.0.0.1", allow_state_changes=False)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("Skipped" in f.description for f in findings))
        self.assertTrue(all(f.cvss is None for f in findings))

    def test_http_auth_against_mock_server(self):
        with MockHTTPServer(host="127.0.0.1", port=8888):
            findings = check_http_auth(self.profile, "127.0.0.1", allow_state_changes=True)
            self.assertEqual(len(findings), 2)

            # /relay/0 returned 200 unauthenticated -> flagged
            relay_finding = next(f for f in findings if "/relay/0" in f.description)
            self.assertIn("accepted WITHOUT authentication", relay_finding.description)
            self.assertEqual(relay_finding.damage.get("physical_safety"), 2)

            # /secure/settings returned 401 -> properly required auth
            secure_finding = next(f for f in findings if "/secure/settings" in f.description)
            self.assertIn("correctly required authentication", secure_finding.description)


class TestFirmwareAudit(unittest.TestCase):

    def test_entropy_calculation(self):
        # Uniform string has low entropy
        self.assertAlmostEqual(calculate_shannon_entropy("aaaaaaaaaa"), 0.0, places=2)
        # Random string has higher entropy (>4.0)
        random_str = "k9J2mZ0qW8xV3bL1nC5aD7fG"
        self.assertGreater(calculate_shannon_entropy(random_str), 4.0)

    def test_scan_for_secrets_detection_and_masking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sample_conf = tmp_path / "system.conf"
            sample_conf.write_text(
                'aws_key = "AKIA1234567890ABCDEF"\n'
                'bearer = "Bearer secrettoken1234567890abcdef"\n'
            )

            hits = scan_for_secrets(tmp_path)
            self.assertGreaterEqual(len(hits), 2)

            # Check that secrets are masked (only first 4 chars visible)
            aws_hit = next(h for h in hits if h["type"] == "aws_access_key")
            self.assertTrue(aws_hit["masked_value"].startswith("AKIA"))
            self.assertTrue("*" in aws_hit["masked_value"])
            self.assertNotIn("AKIA1234567890ABCDEF", aws_hit["masked_value"])

    def test_map_firmware_services(self):
        from iotsploit.checks.firmware_audit import map_firmware_services
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            cfg_dir = tmp_path / "etc" / "config"
            cfg_dir.mkdir(parents=True)
            (cfg_dir / "dropbear").write_text("config dropbear\n\toption Port '22'\n")
            (cfg_dir / "wireless").write_text("config wifi-iface\n\toption key 'SuperSecretWPAKey123'\n")

            services = map_firmware_services(tmp_path)
            self.assertEqual(len(services), 2)
            ssh_service = next(s for s in services if "SSH" in s["service"])
            self.assertEqual(ssh_service["default_port"], 22)
            wifi_service = next(s for s in services if "Wi-Fi" in s["service"])
            self.assertTrue(wifi_service["masked_value"].startswith("Supe"))
            self.assertTrue("*" in wifi_service["masked_value"])

    def test_write_reports_markdown(self):
        from iotsploit.core.report import write_reports
        from iotsploit.core.scoring import DEFAULT_WEIGHTS
        test_finding = Finding(
            finding_id="test_find_1",
            device_id="test_device",
            check_name="firmware_shadow",
            description="Account 'root' has a crackable DES hash in /etc/shadow",
            cvss=9.8,
            damage={"privacy": 2, "chaining_depth": 1},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = write_reports([test_finding], DEFAULT_WEIGHTS, tmpdir)
            self.assertTrue(Path(paths["md"]).exists())
            content = Path(paths["md"]).read_text(encoding="utf-8")
            self.assertIn("# IoT Security & Damage Assessment Report", content)
            self.assertIn("Account 'root' has a crackable DES hash", content)
            self.assertIn("CRITICAL", content)


if __name__ == "__main__":
    unittest.main()
