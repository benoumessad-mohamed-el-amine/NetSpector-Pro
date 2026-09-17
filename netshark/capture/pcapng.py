"""Stream-based PCAPNG reader supporting SHB, IDB, and EPB block parsing."""

import struct
from typing import Dict, Generator, List, Optional, Tuple
from netshark.capture.decode import decode_packet
from netshark.flows import canonical_flow_key, flow_key_to_str
from netshark.model import PacketRef


SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006
SPB_TYPE = 0x00000003
BYTE_ORDER_MAGIC = 0x1A2B3C4D


class PcapngReader:
    """Stream-based PCAPNG binary reader supporting block decoding and stream iteration."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file_handle = None
        self.endian: str = ">"
        self.interfaces: List[Dict[str, int]] = []  # Index maps to dict with 'linktype', 'tsresol'

    def open(self):
        self.file_handle = open(self.filepath, "rb")
        # Read initial Section Header Block (SHB)
        shb_hdr = self.file_handle.read(12)
        if len(shb_hdr) < 12:
            raise ValueError(f"Invalid PCAPNG file '{self.filepath}': File too short.")

        block_type, block_len, magic = struct.unpack(">III", shb_hdr)
        if block_type != SHB_TYPE:
            raise ValueError(f"Not a valid PCAPNG file. Header block type 0x{block_type:08x}")

        if magic == BYTE_ORDER_MAGIC:
            self.endian = ">"
        elif magic == 0x4D3C2B1A:
            self.endian = "<"
        else:
            raise ValueError(f"Invalid PCAPNG byte order magic 0x{magic:08x}")

        # Seek back to beginning of file so iterator can read sequentially
        self.file_handle.seek(0)

    def close(self):
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def packets(self) -> Generator[PacketRef, None, None]:
        """Iterates over PCAPNG blocks and yields PacketRef objects for all Enhanced Packet Blocks."""
        if not self.file_handle:
            self.open()

        while True:
            offset = self.file_handle.tell()
            header = self.file_handle.read(8)
            if not header or len(header) < 8:
                break

            block_type, block_len = struct.unpack(f"{self.endian}II", header)
            if block_len < 12:
                break

            body_len = block_len - 12
            body_bytes = self.file_handle.read(body_len)
            trailing_len_bytes = self.file_handle.read(4)

            if len(body_bytes) < body_len or len(trailing_len_bytes) < 4:
                break

            if block_type == IDB_TYPE:
                if len(body_bytes) >= 8:
                    linktype, reserved, snaplen = struct.unpack(f"{self.endian}HHI", body_bytes[:8])
                    # Parse IDB options for timestamp resolution if present
                    tsresol = 6  # Default 10^-6 s (microseconds)
                    self.interfaces.append({"linktype": linktype, "tsresol": tsresol})

            elif block_type == EPB_TYPE:
                if len(body_bytes) >= 20:
                    iface_id, ts_high, ts_low, caplen, wirelen = struct.unpack(
                        f"{self.endian}IIIII", body_bytes[:20]
                    )

                    linktype = 1
                    if iface_id < len(self.interfaces):
                        linktype = self.interfaces[iface_id]["linktype"]

                    ts_raw = (ts_high << 32) | ts_low
                    ts_us = ts_raw  # Default 10^-6 s timestamp

                    packet_bytes = body_bytes[20:20 + caplen]
                    decoded = decode_packet(packet_bytes, linktype)
                    if not decoded:
                        continue

                    flow_key = canonical_flow_key(
                        decoded["src_ip"], decoded["src_port"],
                        decoded["dst_ip"], decoded["dst_port"],
                        decoded["protocol"]
                    )
                    flow_id = flow_key_to_str(flow_key)

                    pkt_ref = PacketRef(
                        ts_us=ts_us,
                        file_offset=offset,
                        caplen=caplen,
                        wirelen=wirelen,
                        flow_id=flow_id,
                        src_ip=decoded["src_ip"],
                        dst_ip=decoded["dst_ip"],
                        src_port=decoded["src_port"],
                        dst_port=decoded["dst_port"],
                        protocol=decoded["protocol"],
                        tcp_seq=decoded.get("tcp_seq", 0),
                        tcp_ack=decoded.get("tcp_ack", 0),
                        tcp_flags=decoded.get("tcp_flags", 0),
                        dns_qname=decoded.get("dns_qname"),
                        dns_qtype=decoded.get("dns_qtype"),
                        tls_info=decoded.get("tls_info"),
                        payload_len=decoded.get("payload_len", 0),
                    )
                    pkt_ref._raw_payload = decoded.get("raw_payload")
                    yield pkt_ref
