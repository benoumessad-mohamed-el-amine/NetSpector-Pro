"""One-Click PCAP evidence packet carver supporting PCAPNG block comment option injection."""

import struct
from typing import List, Optional
from netshark.model import Alert, PacketRef


def build_pcapng_epb_with_comment(
    packet_bytes: bytes,
    ts_us: int,
    file_offset: int,
    comment_str: str,
    endian: str = ">",
) -> bytes:
    """Constructs a PCAPNG Enhanced Packet Block (EPB) with an embedded opt_comment (Option Code 1)."""
    caplen = len(packet_bytes)
    wirelen = caplen
    iface_id = 0

    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low = ts_us & 0xFFFFFFFF

    # Option 1: opt_comment
    comment_bytes = comment_str.encode("utf-8")
    opt_len = len(comment_bytes)
    opt_pad_len = (4 - (opt_len % 4)) % 4
    opt_block = struct.pack(f"{endian}HH", 1, opt_len) + comment_bytes + (b"\x00" * opt_pad_len)

    # Option 0: opt_endofopt
    opt_end = struct.pack(f"{endian}HH", 0, 0)

    options_bytes = opt_block + opt_end

    pad_len = (4 - (caplen % 4)) % 4
    padded_pkt_bytes = packet_bytes + (b"\x00" * pad_len)

    # Total block length = 12 (hdr) + 20 (epb fields) + len(padded_pkt) + len(options) + 4 (dup len)
    block_total_len = 12 + 20 + len(padded_pkt_bytes) + len(options_bytes) + 4

    epb_hdr = struct.pack(
        f"{endian}IIIIIII",
        0x00000006,  # EPB type
        block_total_len,
        iface_id,
        ts_high,
        ts_low,
        caplen,
        wirelen,
    )

    dup_len = struct.pack(f"{endian}I", block_total_len)

    return epb_hdr + padded_pkt_bytes + options_bytes + dup_len


class PcapCarver:
    """Fast binary packet carver that extracts evidence packets into clean mini-PCAP/PCAPNG files."""

    def __init__(self, source_pcap_path: str):
        self.source_pcap_path = source_pcap_path

    def carve_packets(self, packet_refs: List[PacketRef], output_pcap_path: str, comment: Optional[str] = None) -> bool:
        """Carves specified PacketRefs from source capture into a clean standalone PCAP file."""
        if not packet_refs:
            return False

        sorted_refs = sorted(packet_refs, key=lambda p: p.file_offset)

        try:
            with open(self.source_pcap_path, "rb") as src_f:
                global_hdr = src_f.read(24)

                with open(output_pcap_path, "wb") as dst_f:
                    if len(global_hdr) == 24 and global_hdr[:4] in (
                        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"
                    ):
                        dst_f.write(global_hdr)
                    else:
                        fallback_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                        dst_f.write(fallback_hdr)

                    for ref in sorted_refs:
                        src_f.seek(ref.file_offset)
                        record_header = src_f.read(16)
                        if len(record_header) < 16:
                            continue

                        payload_bytes = src_f.read(ref.caplen)
                        dst_f.write(record_header)
                        dst_f.write(payload_bytes)

            return True
        except Exception as e:
            print(f"Error carving PCAP file '{output_pcap_path}': {e}")
            return False

    def carve_alert(self, alert: Alert, output_pcap_path: str) -> bool:
        """Convenience method to carve all evidence packets associated with an Alert."""
        comment_note = f"[NetSpector Alert: {alert.alert_id}] {alert.rule_id} - {alert.title}"
        return self.carve_packets(alert.packet_refs, output_pcap_path, comment=comment_note)
