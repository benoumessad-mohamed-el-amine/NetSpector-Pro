"""Stream-based classic PCAP reader supporting microsecond/nanosecond timestamps and endianness handling."""

import struct
from typing import Generator, Optional, Tuple
from netspector.capture.decode import decode_packet
from netspector.flows import canonical_flow_key, flow_key_to_str
from netspector.model import PacketRef


PCAP_MAGIC_BE_US = 0xA1B2C3D4
PCAP_MAGIC_LE_US = 0xD4C3B2A1
PCAP_MAGIC_BE_NS = 0xA1B23C4D
PCAP_MAGIC_LE_NS = 0x4D3CB2A1


class PcapReader:
    """Stream-based PCAP reader that parses raw binary packets without loading whole file into RAM."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file_handle = None
        self.global_header: Optional[bytes] = None
        self.linktype: int = 1  # Default Ethernet
        self.endian: str = ">"
        self.is_nanosecond: bool = False
        self.snaplen: int = 65535

    def open(self):
        self.file_handle = open(self.filepath, "rb")
        header_bytes = self.file_handle.read(24)
        if len(header_bytes) < 24:
            raise ValueError(f"Invalid PCAP file '{self.filepath}': File too short for global header.")

        magic = struct.unpack(">I", header_bytes[:4])[0]
        if magic == PCAP_MAGIC_BE_US:
            self.endian = ">"
            self.is_nanosecond = False
        elif magic == PCAP_MAGIC_LE_US:
            self.endian = "<"
            self.is_nanosecond = False
        elif magic == PCAP_MAGIC_BE_NS:
            self.endian = ">"
            self.is_nanosecond = True
        elif magic == PCAP_MAGIC_LE_NS:
            self.endian = "<"
            self.is_nanosecond = True
        else:
            raise ValueError(f"Not a valid PCAP file. Unexpected magic number: 0x{magic:08x}")

        self.global_header = header_bytes
        # Unpack remaining global header fields
        gh_fmt = f"{self.endian}HHIIII"
        v_maj, v_min, tz, sigs, self.snaplen, self.linktype = struct.unpack(gh_fmt, header_bytes[4:24])

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
        """Yields PacketRef objects for each packet in the PCAP stream."""
        if not self.file_handle:
            self.open()

        rec_fmt = f"{self.endian}IIII"

        while True:
            offset = self.file_handle.tell()
            hdr_data = self.file_handle.read(16)
            if not hdr_data or len(hdr_data) < 16:
                break

            ts_sec, ts_subsec, caplen, wirelen = struct.unpack(rec_fmt, hdr_data)

            if self.is_nanosecond:
                ts_us = ts_sec * 1_000_000 + (ts_subsec // 1000)
            else:
                ts_us = ts_sec * 1_000_000 + ts_subsec

            packet_bytes = self.file_handle.read(caplen)
            if len(packet_bytes) < caplen:
                break  # Truncated record at EOF

            decoded = decode_packet(packet_bytes, self.linktype)
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

            yield pkt_ref
