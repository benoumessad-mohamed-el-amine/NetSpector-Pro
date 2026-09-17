"""Unit tests for FlowTable LRU eviction and canonical 5-tuple keys."""

import unittest
from netshark.flows import FlowTable, canonical_flow_key, flow_key_to_str
from netshark.model import PacketRef


class TestFlowTable(unittest.TestCase):
    def test_canonical_5tuple_symmetry(self):
        k1 = canonical_flow_key("10.0.0.1", 1234, "10.0.0.2", 80, 6)
        k2 = canonical_flow_key("10.0.0.2", 80, "10.0.0.1", 1234, 6)
        self.assertEqual(k1, k2)
        self.assertEqual(flow_key_to_str(k1), flow_key_to_str(k2))

    def test_lru_bounded_capacity(self):
        table = FlowTable(max_capacity=2)
        evicted = []
        table.register_evict_callback(lambda f: evicted.append(f.flow_id))

        pkt1 = PacketRef(100, 0, 60, 60, "flow1", "10.0.0.1", "10.0.0.2", 100, 80, 6)
        pkt2 = PacketRef(101, 60, 60, 60, "flow2", "10.0.0.1", "10.0.0.3", 101, 80, 6)
        pkt3 = PacketRef(102, 120, 60, 60, "flow3", "10.0.0.1", "10.0.0.4", 102, 80, 6)

        table.touch_or_create(pkt1)
        table.touch_or_create(pkt2)
        self.assertEqual(len(table), 2)

        # Inserting 3rd flow must evict LRU (flow1)
        table.touch_or_create(pkt3)
        self.assertEqual(len(table), 2)
        self.assertEqual(len(evicted), 1)


if __name__ == "__main__":
    unittest.main()
