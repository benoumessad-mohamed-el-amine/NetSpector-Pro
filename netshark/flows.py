"""Canonical 5-tuple Flow Table with bounded LRU eviction."""

from collections import OrderedDict
from typing import Callable, Dict, Optional, Tuple
from netshark.model import Flow, PacketRef


def canonical_flow_key(
    ip1: str, port1: int, ip2: str, port2: int, protocol: int
) -> Tuple[str, int, str, int, int]:
    """Generates a canonical 5-tuple where the lower IP/port endpoint comes first.
    
    Guarantees both directions of a bi-directional connection map to the exact same flow key.
    """
    ep1 = (ip1, port1)
    ep2 = (ip2, port2)
    if ep1 <= ep2:
        return (ip1, port1, ip2, port2, protocol)
    else:
        return (ip2, port2, ip1, port1, protocol)


def flow_key_to_str(key: Tuple[str, int, str, int, int]) -> str:
    """Formats a canonical 5-tuple into a string key."""
    return f"{key[4]}:{key[0]}:{key[1]}<->{key[2]}:{key[3]}"


class FlowTable:
    """Bounded LRU Flow Table maintaining active connection state up to capacity (default 200k)."""

    def __init__(self, max_capacity: int = 200_000):
        self.max_capacity = max_capacity
        self._table: OrderedDict[str, Flow] = OrderedDict()
        self.closed_flows: Dict[str, Flow] = {}
        self.on_flow_evict_callbacks: list[Callable[[Flow], None]] = []

    def register_evict_callback(self, callback: Callable[[Flow], None]):
        self.on_flow_evict_callbacks.append(callback)

    def touch_or_create(self, pkt: PacketRef) -> Flow:
        """Retrieves or creates a flow for the given packet, updating LRU order."""
        key_tuple = canonical_flow_key(
            pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol
        )
        flow_id = flow_key_to_str(key_tuple)

        if flow_id in self._table:
            flow = self._table[flow_id]
            self._table.move_to_end(flow_id)
        else:
            # Check capacity and evict LRU item if needed
            if len(self._table) >= self.max_capacity:
                self._evict_lru()

            flow = Flow(
                flow_id=flow_id,
                endpoint_a_ip=key_tuple[0],
                endpoint_a_port=key_tuple[1],
                endpoint_b_ip=key_tuple[2],
                endpoint_b_port=key_tuple[3],
                protocol=key_tuple[4],
            )
            self._table[flow_id] = flow

        flow.add_packet(pkt)
        return flow

    def get_flow(self, flow_id: str) -> Optional[Flow]:
        return self._table.get(flow_id)

    def close_flow(self, flow_id: str) -> Optional[Flow]:
        """Explicitly closes and removes a flow from active LRU table."""
        flow = self._table.pop(flow_id, None)
        if flow:
            flow.closed = True
            self.closed_flows[flow_id] = flow
            for cb in self.on_flow_evict_callbacks:
                cb(flow)
        return flow

    def _evict_lru(self):
        """Evicts the least recently used flow from the active flow table."""
        if not self._table:
            return
        _, evicted_flow = self._table.popitem(last=False)
        evicted_flow.closed = True
        self.closed_flows[evicted_flow.flow_id] = evicted_flow
        for cb in self.on_flow_evict_callbacks:
            cb(evicted_flow)

    def flush_all(self):
        """Flushes all remaining flows in table when capture processing completes."""
        while self._table:
            self._evict_lru()

    def __len__(self) -> int:
        return len(self._table)
