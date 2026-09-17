"""Unit tests for NetSpector Pro 12-module expansion, noise scrubbing, and DNS/Payload telemetry."""

import unittest
from netshark.correlate import AttackChainStitcher, extract_dns_telemetry, extract_suspicious_payloads
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netshark.modules.beacon import C2BeaconModule
from netshark.modules.dns_tunnel import DnsTunnelModule
from netshark.modules.entropy import DnsEntropyModule, is_ad_enterprise_noise
from netshark.modules.file_carver import FileCarverModule
from netshark.modules.smb_audit import SmbAuditModule


class TestNewModulesAndScrubbing(unittest.TestCase):
    def test_telemetry_domain_whitelisting(self):
        """Tests mandatory telemetry and AD domain noise scrubbing."""
        self.assertTrue(is_ad_enterprise_noise("_ldap._tcp.dc._msdcs.corp.local"))
        self.assertTrue(is_ad_enterprise_noise("telemetry.microsoft.com"))
        self.assertTrue(is_ad_enterprise_noise("www.msftncsi.com"))
        self.assertTrue(is_ad_enterprise_noise("clients6.google.com"))
        self.assertFalse(is_ad_enterprise_noise("x89q2k4l91m.malicious-c2.net"))

    def test_file_carver_module(self):
        """Tests binary magic byte identification over cleartext stream."""
        module = FileCarverModule()
        flow = Flow("6:10.0.0.1:1234<->10.0.0.2:80", "10.0.0.1", 1234, "10.0.0.2", 80, 6)

        # Simulate packet carrying Windows PE executable header (MZ)
        pkt = PacketRef(
            ts_us=1000, file_offset=0, caplen=100, wirelen=100, flow_id=flow.flow_id,
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80, protocol=6,
            _raw_payload=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"
        )
        flow.add_packet(pkt)

        alerts = module.on_packet(pkt, flow)
        self.assertEqual(len(alerts), 1)
        self.assertIn("Binary File Signature Detected", alerts[0].title)
        self.assertEqual(alerts[0].severity, Severity.HIGH)

    def test_smb_audit_module(self):
        """Tests SMB named pipe and administrative share auditing."""
        module = SmbAuditModule()
        flow = Flow("6:10.0.0.1:4455<->10.0.0.5:445", "10.0.0.1", 4455, "10.0.0.5", 445, 6)

        # Simulate SMB packet requesting \pipe\svcctl
        pkt = PacketRef(
            ts_us=1000, file_offset=0, caplen=100, wirelen=100, flow_id=flow.flow_id,
            src_ip="10.0.0.1", dst_ip="10.0.0.5", src_port=4455, dst_port=445, protocol=6,
            _raw_payload=b"\x00\x00\x00\x40\xfeSMB\\pipe\\svcctl\x00"
        )
        flow.add_packet(pkt)

        alerts = module.on_packet(pkt, flow)
        self.assertEqual(len(alerts), 1)
        self.assertIn("svcctl", alerts[0].title)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_dns_tunnel_module(self):
        """Tests DNS tunneling repetitive TXT/CNAME query threshold detection."""
        module = DnsTunnelModule()
        flow = Flow("17:10.0.0.1:5353<->8.8.8.8:53", "10.0.0.1", 5353, "8.8.8.8", 53, 17)

        alerts = []
        for i in range(10):
            qname = f"sub{i}.verylongencodedpayloadchunk{i*1000}.covert-tunnel.org"
            pkt = PacketRef(
                ts_us=1000 + i * 10, file_offset=0, caplen=100, wirelen=100, flow_id=flow.flow_id,
                src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=5353, dst_port=53, protocol=17,
                dns_qname=qname, dns_qtype=16
            )
            res = module.on_packet(pkt, flow)
            if res:
                alerts.extend(res)

        self.assertGreaterEqual(len(alerts), 1)
        self.assertIn("Covert DNS Tunneling", alerts[0].title)

    def test_dns_and_payload_telemetry_extraction(self):
        """Tests extraction of DNS queries and suspicious links for reports."""
        alert = Alert(
            "ALT-TEST-01", "RULE-FILE-MAGIC-01", "Binary File Signature Detected",
            "PE file downloaded", Severity.HIGH, KillChainStage.EXECUTION,
            "10.0.0.1", "192.168.1.100", 1234, 80, "TCP", 1000,
            arithmetic_proof={
                "payload_offset": 0,
                "magic_bytes_ascii": "MZ",
                "magic_bytes_hex": "4d5a",
                "detected_file_type": "Windows PE Executable (.exe)",
            }
        )
        stitcher = AttackChainStitcher([alert])
        res = stitcher.correlate()

        self.assertIn("dns_report", res)
        self.assertIn("suspicious_payloads", res)
        self.assertEqual(len(res["suspicious_payloads"]), 1)
        self.assertIn("10.0.0.1", res["suspicious_payloads"][0]["source_ip"])


if __name__ == "__main__":
    unittest.main()
