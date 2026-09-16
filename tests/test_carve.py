"""Unit tests for PCAP packet carver."""

import os
import tempfile
import unittest
from netspector.capture.pcap import PcapReader
from netspector.carve import PcapCarver
from tests.test_pcap_readers import create_synthetic_pcap_file


class TestCarve(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.source_pcap = os.path.join(self.temp_dir.name, "source.pcap")
        self.output_pcap = os.path.join(self.temp_dir.name, "carved.pcap")
        create_synthetic_pcap_file(self.source_pcap)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pcap_carving(self):
        with PcapReader(self.source_pcap) as reader:
            pkts = list(reader.packets())

        self.assertTrue(len(pkts) >= 1)
        carver = PcapCarver(self.source_pcap)
        success = carver.carve_packets([pkts[0]], self.output_pcap)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.output_pcap))

        with PcapReader(self.output_pcap) as carved_reader:
            carved_pkts = list(carved_reader.packets())
            self.assertEqual(len(carved_pkts), 1)
            self.assertEqual(carved_pkts[0].src_ip, pkts[0].src_ip)


if __name__ == "__main__":
    unittest.main()
