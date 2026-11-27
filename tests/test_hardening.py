"""Regression tests for correctness and security fixes.

Each test names the bug it pins down, so a failure points at a known class of
mistake rather than a vague "something broke".
"""

import http.client
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer

from netshark.capture.decode import decode_packet
from netshark.capture.pcap import PcapReader
from netshark.capture.pcapng import PcapngReader
from netshark.carve import PcapCarver
from netshark.flows import FlowTable
from netshark.model import Flow, PacketRef, stable_id
from netshark.modules.beacon import C2BeaconModule
from netshark.pipeline import run_triage, triage_file
from netshark.report import html_rep
from netshark.report.history import HistoryManager
from tests.test_pcap_readers import create_synthetic_pcap_file

ETH = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"


def ipv4_udp_frame(payload: bytes = b"test", sport: int = 1234, dport: int = 8080, frag_off: int = 0) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, frag_off, 64, 17, 0,
                     b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    return ETH + ip + udp


def pcapng_bytes(frames, tsresol=None, ts_units=None):
    """Minimal little-endian PCAPNG: SHB, one IDB (optional if_tsresol), EPBs."""
    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = struct.pack("<HHI", 1, 0, 0)
    if tsresol is not None:
        idb += struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)
    out += block(1, idb)
    for i, frame in enumerate(frames):
        ts = ts_units[i] if ts_units else 1_600_000_000_000_000 + i
        epb = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame
        out += block(6, epb)
    return out


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name):
        return os.path.join(self.tmp, name)


class TestCarverOutput(TempDirCase):
    def test_carve_from_pcapng_source_yields_same_packets(self):
        """Bug: carver assumed PCAP record headers and corrupted PCAPNG-sourced evidence."""
        src = self.path("src.pcapng")
        with open(src, "wb") as f:
            f.write(pcapng_bytes([ipv4_udp_frame(b"one", 1111), ipv4_udp_frame(b"two", 2222)]))
        with PcapngReader(src) as r:
            pkts = list(r.packets())
        out = self.path("ev.pcapng")
        self.assertTrue(PcapCarver(src).carve_packets([pkts[1]], out, comment="hello"))
        with PcapngReader(out) as r:
            carved = list(r.packets())
        self.assertEqual(len(carved), 1)
        self.assertEqual(carved[0].src_port, 2222)
        self.assertEqual(carved[0].ts_us, pkts[1].ts_us)

    def test_carve_writes_comment(self):
        """Bug: the comment argument was accepted and silently ignored."""
        src = self.path("src.pcap")
        create_synthetic_pcap_file(src)
        with PcapReader(src) as r:
            pkts = list(r.packets())
        out = self.path("ev.pcapng")
        PcapCarver(src).carve_packets(pkts, out, comment="[NetShark ALT-X] RULE-Y")
        with open(out, "rb") as f:
            self.assertIn(b"[NetShark ALT-X] RULE-Y", f.read())


class TestPcapngTimestamps(TempDirCase):
    def test_nanosecond_if_tsresol_is_honoured(self):
        """Bug: if_tsresol was ignored, so ns captures had timestamps 1000x too large."""
        src = self.path("ns.pcapng")
        ns = 1_600_000_000_123_456_789
        with open(src, "wb") as f:
            f.write(pcapng_bytes([ipv4_udp_frame()], tsresol=9, ts_units=[ns]))
        with PcapngReader(src) as r:
            (pkt,) = list(r.packets())
        self.assertEqual(pkt.ts_us, ns // 1000)


class TestDecoder(unittest.TestCase):
    def test_ethernet_padding_not_counted_as_payload(self):
        """Bug: a bare TCP ACK padded to 60 bytes reported 6 bytes of payload."""
        tcp = struct.pack("!HHIIHHHH", 5555, 80, 1, 1, (5 << 12) | 0x10, 1024, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
        frame = (ETH + ip + tcp).ljust(60, b"\x00")
        self.assertEqual(decode_packet(frame)["payload_len"], 0)

    def test_non_first_fragment_has_no_ports(self):
        """Bug: fragment payload was parsed as a UDP header, inventing ports and flows."""
        frame = ipv4_udp_frame(b"xxxxxxxx", frag_off=0x0010)  # offset 16*8 bytes
        d = decode_packet(frame)
        self.assertEqual((d["src_port"], d["dst_port"], d["protocol"]), (0, 0, 0))


class TestDeterminism(unittest.TestCase):
    def test_stable_id_independent_of_hash_seed(self):
        """Bug: alert IDs used hash(), which is salted per process."""
        code = "from netshark.model import stable_id; print(stable_id('6:10.0.0.1:1<->10.0.0.2:2'))"
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        outs = set()
        for seed in ("1", "2", "3"):
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=root)
            outs.add(subprocess.check_output([sys.executable, "-c", code], env=env, text=True).strip())
        self.assertEqual(len(outs), 1)
        self.assertEqual(int(outs.pop()), stable_id("6:10.0.0.1:1<->10.0.0.2:2"))


class TestResourceBounds(unittest.TestCase):
    def test_flow_table_does_not_retain_evicted_flows(self):
        """Bug: evicted flows were kept in closed_flows forever, unbounding memory."""
        table = FlowTable(max_capacity=10)
        for port in range(1000):
            table.touch_or_create(PacketRef(port, 0, 60, 60, "", "10.0.0.1", "10.0.0.2", port, 80, 6))
        self.assertEqual(len(table), 10)
        self.assertEqual(table.total_flows, 1000)
        self.assertFalse(hasattr(table, "closed_flows"))

    def test_pipeline_drops_payload_after_dispatch(self):
        pkts = [PacketRef(i, 0, 60, 60, "", "10.0.0.1", "10.0.0.2", 1, 80, 6, payload_len=4, _raw_payload=b"abcd")
                for i in range(5)]
        run_triage(pkts, rules={})
        self.assertTrue(all(p._raw_payload is None for p in pkts))

    def test_beacon_analysis_is_not_quadratic(self):
        """Bug: _analyze_flow (O(n)) ran on every packet past the gate -> O(n^2)."""
        mod = C2BeaconModule()
        mod.configure({})
        calls = 0
        original = mod._analyze_flow

        def counting(flow):
            nonlocal calls
            calls += 1
            return original(flow)

        mod._analyze_flow = counting
        flow = Flow("f", "10.0.0.1", 1, "10.0.0.2", 2, 6)
        import random
        rnd = random.Random(0)
        ts = 0
        for _ in range(4096):
            ts += rnd.randint(1, 5_000_000)  # irregular: never alerts
            pkt = PacketRef(ts, 0, 60, 60, "f", "10.0.0.1", "10.0.0.2", 1, 2, 6, payload_len=10)
            flow.add_packet(pkt)
            mod.on_packet(pkt, flow)
        self.assertLessEqual(calls, 12)  # powers of two from 16 to 4096


class TestHistoryTraversal(TempDirCase):
    def test_profile_id_cannot_escape_history_dir(self):
        """Bug: ?profile_id=../x read/deleted arbitrary .json files."""
        victim = self.path("victim.json")
        with open(victim, "w") as f:
            json.dump({"triage_data": {"secret": 1}}, f)
        hist = HistoryManager(history_dir=self.path("history"))
        self.assertIsNone(hist.get_profile("../victim"))
        self.assertFalse(hist.delete_profile("../victim"))
        self.assertTrue(os.path.exists(victim))


class TestDashboardServer(TempDirCase):
    def setUp(self):
        super().setUp()
        self.cwd = os.getcwd()
        os.chdir(self.tmp)  # history is written relative to cwd
        self.server = HTTPServer(("127.0.0.1", 0), html_rep.DashboardRequestHandler)
        self.port = self.server.server_address[1]
        H = html_rep.DashboardRequestHandler
        H.alerts, H.summary_stats, H.correlation_data = [], {}, {}
        H.source_pcap_path, H.source_is_upload = "", False
        H.allowed_hosts = html_rep.allowed_hosts_for(self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        os.chdir(self.cwd)
        super().tearDown()

    def request(self, method, path, body=None, host=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if origin:
            headers["Origin"] = origin
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_foreign_host_header_rejected(self):
        """DNS-rebinding guard: a page on evil.example resolving to 127.0.0.1 is refused."""
        status, _ = self.request("GET", "/api/history", host=f"evil.example:{self.port}")
        self.assertEqual(status, 403)
        self.assertEqual(self.request("GET", "/api/history")[0], 200)

    def test_cross_site_post_rejected(self):
        """Bug: a text/plain POST from any website skips preflight and reached /api/upload."""
        status, _ = self.request("POST", "/api/upload", body=b"x", origin="https://evil.example")
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/upload", body=b"", origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(status, 400)  # same-origin passes the guard (then fails on empty body)

    def test_capture_content_cannot_break_out_of_script(self):
        """Bug: report JSON was embedded raw, so '</script>' in a DNS name injected HTML."""
        html_rep.DashboardRequestHandler.summary_stats = {"note": "</script><script>alert(1)</script>"}
        _, body = self.request("GET", "/")
        self.assertNotIn(b"</script><script>alert(1)", body)

    def test_upload_replaces_alerts_used_for_carving(self):
        """Bug: upload refreshed summary but not `alerts`, so carving used stale offsets."""
        html_rep.DashboardRequestHandler.alerts = ["stale"]
        src = self.path("up.pcap")
        create_synthetic_pcap_file(src)
        with open(src, "rb") as f:
            status, body = self.request("POST", "/api/upload", body=f.read())
        self.assertEqual(status, 200, body)
        self.assertNotEqual(html_rep.DashboardRequestHandler.alerts, ["stale"])
        profiles = HistoryManager().list_profiles()
        self.assertEqual(len(profiles), 1, "upload must archive exactly one profile")


class TestExfilDirection(unittest.TestCase):
    def _flow(self, up: int, down: int) -> Flow:
        flow = Flow("f", "10.0.0.5", 50000, "203.0.113.7", 443, 6)
        flow.add_packet(PacketRef(0, 0, 60, up, "f", "10.0.0.5", "203.0.113.7", 50000, 443, 6))
        flow.add_packet(PacketRef(1, 0, 60, down, "f", "203.0.113.7", "10.0.0.5", 443, 50000, 6))
        return flow

    def _run(self, flow):
        from netshark.modules.exfil import ExfiltrationModule
        mod = ExfiltrationModule()
        mod.configure({})
        return mod.on_flow_close(flow)

    def test_large_download_is_not_exfiltration(self):
        """Bug: exfil used total bytes, so any big download raised an Exfiltration alert."""
        self.assertEqual(self._run(self._flow(up=2_000, down=50_000_000)), [])

    def test_upload_heavy_flow_alerts_with_internal_source(self):
        (alert,) = self._run(self._flow(up=50_000_000, down=2_000))
        self.assertEqual(alert.source_ip, "10.0.0.5")
        self.assertGreaterEqual(alert.arithmetic_proof["out_in_ratio"], 10)


class TestRulesEnabledFlag(unittest.TestCase):
    def test_disabled_module_is_not_run(self):
        """Bug: `enabled: false` was documented in defaults.yaml but ignored."""
        from netshark.pipeline import build_modules
        names = {m.name for m in build_modules({"beacon": {"enabled": False}})}
        self.assertNotIn("c2_beacon", names)
        self.assertIn("dns_entropy", names)


class TestPipelineParity(TempDirCase):
    def test_cli_and_web_share_one_pipeline(self):
        src = self.path("a.pcap")
        create_synthetic_pcap_file(src)
        result = triage_file(src, rules={})
        self.assertEqual(result.summary["total_packets"], 2)
        self.assertEqual(result.summary["total_flows"], 1)


if __name__ == "__main__":
    unittest.main()


class TestThreatIntelExport(unittest.TestCase):
    def _alert(self, src="10.0.0.5", dst="2001:db8::7"):
        from netshark.model import Alert, KillChainStage, Severity
        return Alert("ALT-X-000001", "RULE-X", "t", "d", Severity.HIGH, KillChainStage.COMMAND_AND_CONTROL,
                     src, dst, 50000, 443, "6", 1_700_000_000_000_000)

    def test_bundle_is_spec_shaped_and_deterministic(self):
        """Bugs: nested custom_properties, 'indicates' to observed-data, IPv6 typed as ipv4-addr, random IDs."""
        from netshark.report.stix_export import build_stix21_bundle
        a, b = build_stix21_bundle([self._alert()]), build_stix21_bundle([self._alert()])
        self.assertEqual([o["id"] for o in a["objects"]], [o["id"] for o in b["objects"]])
        by_type = {}
        for o in a["objects"]:
            by_type.setdefault(o["type"], []).append(o)
        ind = by_type["indicator"][0]
        self.assertNotIn("custom_properties", ind)
        self.assertEqual(ind["x_netshark_rule_id"], "RULE-X")
        self.assertEqual(by_type["relationship"][0]["relationship_type"], "based-on")
        self.assertIn("ipv6-addr", by_type)
        self.assertEqual(by_type["network-traffic"][0]["protocols"], ["tcp"])
        self.assertTrue(ind["pattern"].startswith("[network-traffic:"))


class TestTlsFingerprints(unittest.TestCase):
    def test_grease_does_not_change_ja3(self):
        """Bug: GREASE values were hashed, so one browser produced a new JA3 per connection."""
        from netshark.modules.ja3_fingerprint import calculate_ja3_fingerprint, is_grease
        self.assertTrue(is_grease(0x2A2A) and not is_grease(0x2A2B))
        base = {"version": 771, "ciphers": [4865, 4866], "extensions": [0, 23], "supported_groups": [29], "ec_point_formats": [0]}
        greased = dict(base, ciphers=[0x3A3A] + base["ciphers"], extensions=[0xBABA] + base["extensions"])
        self.assertEqual(calculate_ja3_fingerprint(base)[1], calculate_ja3_fingerprint(greased)[1])
