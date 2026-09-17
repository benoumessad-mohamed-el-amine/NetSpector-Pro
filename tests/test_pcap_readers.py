"""Unit tests for PCAP and PCAPNG stream binary readers."""

import os
import struct
import tempfile
import unittest
from netshark.capture.pcap import PcapReader
from netshark.capture.pcapng import PcapngReader


def create_synthetic_pcap_file(filepath: str):
    """Writes a valid microsecond PCAP file containing 2 synthetic IPv4/UDP packets."""
    global_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Ethernet (14B) + IPv4 (20B) + UDP (8B) + payload (4B) = 46 bytes
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 32, 1, 0, 64, 17, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    udp = struct.pack("!HHHH", 1234, 8080, 12, 0) + b"test"
    pkt1_payload = eth + ip + udp

    rec1 = struct.pack(">IIII", 1600000000, 500000, len(pkt1_payload), len(pkt1_payload)) + pkt1_payload
    rec2 = struct.pack(">IIII", 1600000001, 500000, len(pkt1_payload), len(pkt1_payload)) + pkt1_payload

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        f.write(rec1)
        f.write(rec2)


class TestPcapReaders(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.temp_dir.name, "test.pcap")
        create_synthetic_pcap_file(self.pcap_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pcap_reader_parsing(self):
        with PcapReader(self.pcap_path) as reader:
            pkts = list(reader.packets())
            self.assertEqual(len(pkts), 2)
            self.assertEqual(pkts[0].src_ip, "10.0.0.1")
            self.assertEqual(pkts[0].dst_ip, "10.0.0.2")
            self.assertEqual(pkts[0].src_port, 1234)
            self.assertEqual(pkts[0].dst_port, 8080)
            self.assertEqual(pkts[0].protocol, 17)


if __name__ == "__main__":
    unittest.main()
