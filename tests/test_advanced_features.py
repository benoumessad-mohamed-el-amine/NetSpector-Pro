"""Unit tests for JA3/JA4 fingerprinting, Exfiltration module, STIX 2.1 exporter, and PCAPNG comments."""

import os
import tempfile
import unittest
from netshark.carve import build_pcapng_epb_with_comment
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netshark.modules.exfil import ExfiltrationModule
from netshark.modules.ja3_fingerprint import Ja3FingerprintModule, calculate_ja3_fingerprint, calculate_ja4_fingerprint
from netshark.report.stix_export import export_stix21_bundle


class TestAdvancedFeatures(unittest.TestCase):
    def test_ja3_ja4_fingerprinting(self):
        tls_info = {
            "version": 0x0303,
            "ciphers": [4865, 4866, 4867],
            "extensions": [0, 23, 65281],
            "supported_groups": [29, 23],
            "ec_point_formats": [0],
            "sni": "malicious.test",
        }
        ja3_str, ja3_hash = calculate_ja3_fingerprint(tls_info)
        ja4_fingerprint = calculate_ja4_fingerprint(tls_info)

        self.assertEqual(ja3_str, "771,4865-4866-4867,0-23-65281,29-23,0")
        self.assertEqual(len(ja3_hash), 32)
        self.assertTrue(ja4_fingerprint.startswith("t12d030300_"))

    def test_ja3_module_threat_intel_match(self):
        mod = Ja3FingerprintModule()
        pkt = PacketRef(100, 0, 60, 60, "flow_tls", "10.0.0.1", "1.2.3.4", 12345, 443, 6)
        setattr(pkt, "tls_info", {
            "version": 771,
            "ciphers": [49195, 49199, 52393, 49196, 49200, 52392, 49171, 49172, 156, 157, 47, 53],
            "extensions": [0, 11, 10, 35, 22, 23, 13],
            "supported_groups": [23, 24, 25],
            "ec_point_formats": [0],
            "sni": "cobaltstrike.test",
        })

        flow = Flow("flow_tls", "10.0.0.1", 12345, "1.2.3.4", 443, 6)
        flow.add_packet(pkt)

        # Force match test
        ja3_str, ja3_hash = calculate_ja3_fingerprint(pkt.tls_info)
        from netshark.modules.ja3_fingerprint import KNOWN_SUSPICIOUS_JA3
        KNOWN_SUSPICIOUS_JA3[ja3_hash] = "Test Cobalt Strike Sign"

        alerts = mod.on_packet(pkt, flow)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_stix21_export(self):
        alert = Alert(
            "ALT-STIX-01", "RULE-01", "Test Title", "Test Desc", Severity.HIGH,
            KillChainStage.EXFILTRATION, "10.0.0.1", "1.1.1.1", 1234, 80, "TCP", 1600000000000000
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            stix_path = os.path.join(tmp_dir, "stix_bundle.json")
            res = export_stix21_bundle([alert], stix_path)
            self.assertTrue(res)
            self.assertTrue(os.path.exists(stix_path))

    def test_pcapng_epb_comment_builder(self):
        pkt_bytes = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        epb_bytes = build_pcapng_epb_with_comment(pkt_bytes, 1600000000000000, 0, "[NetSpector Alert: TEST]")
        self.assertTrue(epb_bytes.startswith(b"\x00\x00\x00\x06"))
        self.assertIn(b"[NetSpector Alert: TEST]", epb_bytes)


if __name__ == "__main__":
    unittest.main()
