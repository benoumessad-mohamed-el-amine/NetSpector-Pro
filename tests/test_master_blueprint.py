"""Unit tests for Master Architectural Specification detection engines."""

import unittest
from netspector.model import Flow, PacketRef
from netspector.modules.credentials import CleartextCredentialsModule
from netspector.modules.exfil import ExfiltrationModule
from netspector.modules.http_audit import HttpAuditModule
from netspector.modules.sweep import SubnetSweepModule


class TestMasterBlueprintModules(unittest.TestCase):
    def test_cleartext_credentials_extraction(self):
        mod = CleartextCredentialsModule()
        pkt = PacketRef(100, 0, 60, 60, "flow_cred", "10.0.0.1", "10.0.0.2", 1234, 80, 6, payload_len=50)
        setattr(pkt, "_raw_payload", b"POST /login HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzMTIz\r\n\r\n")

        flow = Flow("flow_cred", "10.0.0.1", 1234, "10.0.0.2", 80, 6)
        flow.add_packet(pkt)

        alerts = mod.on_packet(pkt, flow)
        self.assertEqual(len(alerts), 1)
        self.assertIn("user", alerts[0].arithmetic_proof.get("extracted_user", ""))

    def test_subnet_sweep_detection(self):
        mod = SubnetSweepModule()
        mod.configure({"sweep": {"sweep_threshold": 3}})

        alerts = []
        for i in range(1, 6):
            target_ip = f"10.0.0.{i}"
            fid = f"sweep_{i}"
            pkt = PacketRef(100, 0, 60, 60, fid, "10.0.0.100", target_ip, 1234, 80, 6, tcp_flags=0x02)
            flow = Flow(fid, "10.0.0.100", 1234, target_ip, 80, 6)
            alts = mod.on_packet(pkt, flow)
            alerts.extend(alts)

        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0].rule_id, "RULE-RECON-SWEEP-01")

    def test_http_audit_script_user_agent_and_webshell(self):
        mod = HttpAuditModule()

        # Test script user-agent
        pkt1 = PacketRef(100, 0, 60, 60, "f_http1", "10.0.0.1", "10.0.0.2", 1234, 80, 6)
        setattr(pkt1, "_raw_payload", b"GET /index.php HTTP/1.1\r\nUser-Agent: python-requests/2.28.1\r\n\r\n")
        flow1 = Flow("f_http1", "10.0.0.1", 1234, "10.0.0.2", 80, 6)

        alerts1 = mod.on_packet(pkt1, flow1)
        self.assertTrue(any(a.rule_id == "RULE-HTTP-USERAGENT-01" for a in alerts1))

        # Test webshell query string
        pkt2 = PacketRef(101, 0, 60, 60, "f_http2", "10.0.0.1", "10.0.0.2", 1234, 80, 6)
        setattr(pkt2, "_raw_payload", b"GET /uploads/c99.php?cmd=id HTTP/1.1\r\nHost: target.com\r\n\r\n")
        flow2 = Flow("f_http2", "10.0.0.1", 1234, "10.0.0.2", 80, 6)

        alerts2 = mod.on_packet(pkt2, flow2)
        self.assertTrue(any(a.rule_id == "RULE-HTTP-WEBSHELL-01" for a in alerts2))

    def test_exfil_volume_skew(self):
        mod = ExfiltrationModule()
        mod.configure({"exfil": {"min_exfil_bytes": 1000}})

        flow = Flow("f_exfil", "10.0.0.1", 1234, "1.1.1.1", 443, 6)
        flow.byte_count = 5000

        alerts = mod.on_flow_close(flow)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "RULE-EXFIL-VOL-01")


if __name__ == "__main__":
    unittest.main()
