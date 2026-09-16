"""Unit tests for all 4 forensic detection modules."""

import unittest
from netspector.model import Flow, PacketRef
from netspector.modules.beacon import C2BeaconModule
from netspector.modules.entropy import DnsEntropyModule, calculate_shannon_entropy
from netspector.modules.lateral import LateralMovementModule
from netspector.modules.tcpstate import TcpStateModule


class TestDetectionModules(unittest.TestCase):
    def test_c2_beaconing_module(self):
        mod = C2BeaconModule()
        mod.configure({"beacon": {"min_samples": 5, "max_cov": 0.20, "min_duration_sec": 1.0}})

        flow = Flow("test_beacon", "10.0.0.1", 1234, "10.0.0.2", 80, 6)
        alerts = []

        # Generate 10 packets spaced exactly 1.0 second apart (0.0000 CoV)
        for i in range(10):
            ts_us = (1600000000 + i) * 1_000_000
            pkt = PacketRef(ts_us, i * 60, 60, 60, "test_beacon", "10.0.0.1", "10.0.0.2", 1234, 80, 6)
            flow.add_packet(pkt)
            alts = mod.on_packet(pkt, flow)
            alerts.extend(alts)

        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0].rule_id, "RULE-C2-BEACON-01")
        self.assertIn("cov_calculated", alerts[0].arithmetic_proof)

    def test_dns_shannon_entropy(self):
        entropy, _ = calculate_shannon_entropy("cxz98a7sdf6qwerty")
        self.assertGreater(entropy, 3.5)

        mod = DnsEntropyModule()
        mod.configure({"entropy": {"entropy_threshold": 3.0, "min_subdomain_len": 5}})

        pkt = PacketRef(
            1600000000000000, 0, 60, 60, "dns_flow",
            "10.0.0.1", "8.8.8.8", 12345, 53, 17,
            dns_qname="cxz98a7sdf6.eval.example.com"
        )
        flow = Flow("dns_flow", "10.0.0.1", 12345, "8.8.8.8", 53, 17)
        flow.add_packet(pkt)

        alerts = mod.on_packet(pkt, flow)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "RULE-DNS-DGA-01")

    def test_active_directory_noise_suppression(self):
        mod = DnsEntropyModule()
        mod.configure({"entropy": {"entropy_threshold": 3.0, "min_subdomain_len": 5}})

        ad_queries = [
            "_ldap._tcp.dc._msdcs.corp.internal",
            "_kerberos._tcp.dc._msdcs.domain.local",
            "_kpasswd._udp.dc.site._sites.corp.lan",
            "1.0.0.10.in-addr.arpa",
        ]

        for q in ad_queries:
            pkt = PacketRef(1600000000000000, 0, 60, 60, f"flow_{q}", "10.0.0.1", "10.0.0.2", 1234, 53, 17, dns_qname=q)
            flow = Flow(f"flow_{q}", "10.0.0.1", 1234, "10.0.0.2", 53, 17)
            alerts = mod.on_packet(pkt, flow)
            self.assertEqual(len(alerts), 0, f"Expected zero alerts for AD noise query '{q}'")

    def test_tcp_state_scans(self):
        mod = TcpStateModule()
        mod.configure({"tcpstate": {"syn_scan_threshold": 3}})

        # NULL Scan test
        pkt_null = PacketRef(100, 0, 60, 60, "f1", "10.0.0.1", "10.0.0.2", 100, 80, 6, tcp_flags=0)
        flow1 = Flow("f1", "10.0.0.1", 100, "10.0.0.2", 80, 6)
        alerts = mod.on_packet(pkt_null, flow1)
        self.assertTrue(any(a.rule_id == "RULE-TCP-FLAGS-01" for a in alerts))

        # SYN Scan threshold test
        syn_alerts = []
        for port in range(1000, 1005):
            fid = f"syn_{port}"
            pkt_syn = PacketRef(100, 0, 60, 60, fid, "10.0.0.100", "10.0.0.2", 1234, port, 6, tcp_flags=0x02)
            flow_syn = Flow(fid, "10.0.0.100", 1234, "10.0.0.2", port, 6)
            alts = mod.on_packet(pkt_syn, flow_syn)
            syn_alerts.extend(alts)

        self.assertTrue(any(a.rule_id == "RULE-TCP-SCAN-01" for a in syn_alerts))

    def test_lateral_movement_fanout(self):
        mod = LateralMovementModule()
        mod.configure({"lateral": {"fanout_threshold": 3}})

        lat_alerts = []
        for i in range(1, 6):
            target_ip = f"10.0.0.{i}"
            fid = f"lat_{i}"
            pkt = PacketRef(100, 0, 60, 60, fid, "10.0.0.100", target_ip, 1234, 445, 6)
            flow = Flow(fid, "10.0.0.100", 1234, target_ip, 445, 6)
            alts = mod.on_packet(pkt, flow)
            lat_alerts.extend(alts)

        self.assertTrue(any(a.rule_id == "RULE-LATERAL-MOVE-01" for a in lat_alerts))


if __name__ == "__main__":
    unittest.main()
