"""One-Click PCAP evidence packet carver using fast seek-and-copy binary extraction."""

import struct
from typing import List, Optional
from netspector.model import Alert, PacketRef


class PcapCarver:
    """Fast binary packet carver that extracts evidence packets into clean mini-PCAP files."""

    def __init__(self, source_pcap_path: str):
        self.source_pcap_path = source_pcap_path

    def carve_packets(self, packet_refs: List[PacketRef], output_pcap_path: str) -> bool:
        """Carves specified PacketRefs from source capture into a clean standalone PCAP file."""
        if not packet_refs:
            return False

        # Sort packet refs by file offset for sequential seeking efficiency
        sorted_refs = sorted(packet_refs, key=lambda p: p.file_offset)

        try:
            with open(self.source_pcap_path, "rb") as src_f:
                # Read original 24-byte global PCAP header or construct fallback
                global_hdr = src_f.read(24)

                with open(output_pcap_path, "wb") as dst_f:
                    # Check if original global header is valid PCAP magic
                    if len(global_hdr) == 24 and global_hdr[:4] in (
                        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"
                    ):
                        dst_f.write(global_hdr)
                    else:
                        # Construct standard microsecond PCAP global header (Ethernet, snaplen 65535)
                        fallback_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                        dst_f.write(fallback_hdr)

                    # Seek and copy each packet record header + payload
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
        return self.carve_packets(alert.packet_refs, output_pcap_path)
