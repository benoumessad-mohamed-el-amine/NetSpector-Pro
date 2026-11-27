"""Evidence carver: copies an alert's packets out of the source capture.

Output is always PCAPNG, whatever the source format, because only PCAPNG can
carry a per-packet comment (opt_comment). Wireshark shows that comment in the
packet details pane, so the analyst opening the evidence file sees which alert
and rule produced it without cross-referencing the report.

Packet bytes are re-read from disk via PacketRef.file_offset; nothing from the
analysis pass is kept in memory for this.
"""

import struct
from typing import Dict, List, Optional, Tuple

from netshark.model import Alert, PacketRef

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\x3c\x4d": (">", True),
    b"\x4d\x3c\xb2\xa1": ("<", True),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006
OPT_COMMENT = 1
OPT_ENDOFOPT = 0


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _block(block_type: int, body: bytes, endian: str = ">") -> bytes:
    total = 12 + len(body)
    return struct.pack(f"{endian}II", block_type, total) + body + struct.pack(f"{endian}I", total)


def build_shb(endian: str = ">") -> bytes:
    # byte-order magic, version 1.0, section length unknown (-1)
    body = struct.pack(f"{endian}IHHq", 0x1A2B3C4D, 1, 0, -1)
    return _block(0x0A0D0D0A, body, endian)


def build_idb(linktype: int, snaplen: int = 0, endian: str = ">") -> bytes:
    # No if_tsresol option => default microsecond resolution, matching PacketRef.ts_us.
    return _block(IDB_TYPE, struct.pack(f"{endian}HHI", linktype, 0, snaplen), endian)


def build_pcapng_epb_with_comment(
    packet_bytes: bytes,
    ts_us: int,
    wirelen: Optional[int] = None,
    comment_str: Optional[str] = None,
    endian: str = ">",
) -> bytes:
    """Builds an Enhanced Packet Block, optionally carrying opt_comment."""
    caplen = len(packet_bytes)
    body = struct.pack(
        f"{endian}IIIII",
        0,  # interface id
        (ts_us >> 32) & 0xFFFFFFFF,
        ts_us & 0xFFFFFFFF,
        caplen,
        wirelen if wirelen is not None else caplen,
    ) + _pad4(packet_bytes)
    if comment_str:
        c = comment_str.encode("utf-8")
        body += struct.pack(f"{endian}HH", OPT_COMMENT, len(c)) + _pad4(c)
        body += struct.pack(f"{endian}HH", OPT_ENDOFOPT, 0)
    return _block(EPB_TYPE, body, endian)


class PcapCarver:
    """Extracts evidence packets from a PCAP or PCAPNG source into a PCAPNG file."""

    def __init__(self, source_pcap_path: str):
        self.source_pcap_path = source_pcap_path

    def _source_layout(self, f) -> Tuple[str, str, Dict[int, int]]:
        """Returns (format, endian, {interface_id: linktype}) for the source."""
        head = f.read(24)
        if head[:4] in PCAP_MAGICS:
            endian, _ = PCAP_MAGICS[head[:4]]
            linktype = struct.unpack(f"{endian}I", head[20:24])[0]
            return "pcap", endian, {0: linktype}
        if head[:4] == PCAPNG_MAGIC:
            endian = ">" if head[8:12] == b"\x1a\x2b\x3c\x4d" else "<"
            links: Dict[int, int] = {}
            f.seek(0)
            # IDBs precede the packets that reference them; scan until the first EPB.
            while True:
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                btype, blen = struct.unpack(f"{endian}II", hdr)
                if blen < 12:
                    break
                if btype == IDB_TYPE:
                    links[len(links)] = struct.unpack(f"{endian}H", f.read(2))[0]
                    f.seek(blen - 10, 1)
                elif btype == EPB_TYPE:
                    break
                else:
                    f.seek(blen - 8, 1)
            return "pcapng", endian, links or {0: 1}
        raise ValueError("Unrecognised capture format")

    def _read_frame(self, f, fmt: str, endian: str, ref: PacketRef) -> Optional[Tuple[bytes, int]]:
        """Returns (frame_bytes, interface_id) for the packet at ref.file_offset."""
        f.seek(ref.file_offset)
        if fmt == "pcap":
            hdr = f.read(16)
            if len(hdr) < 16:
                return None
            caplen = struct.unpack(f"{endian}I", hdr[8:12])[0]
            return f.read(caplen), 0
        hdr = f.read(28)  # block type, block len, iface, ts_hi, ts_lo, caplen, wirelen
        if len(hdr) < 28:
            return None
        btype, _, iface, _, _, caplen, _ = struct.unpack(f"{endian}IIIIIII", hdr)
        if btype != EPB_TYPE:
            return None
        return f.read(caplen), iface

    def carve_packets(self, packet_refs: List[PacketRef], output_path: str, comment: Optional[str] = None) -> bool:
        """Writes packet_refs to output_path as PCAPNG. Returns False if nothing was written."""
        if not packet_refs:
            return False
        try:
            with open(self.source_pcap_path, "rb") as src:
                fmt, endian, links = self._source_layout(src)
                frames = []
                for ref in sorted(packet_refs, key=lambda p: p.file_offset):
                    got = self._read_frame(src, fmt, endian, ref)
                    if got:
                        frames.append((ref, *got))
            if not frames:
                return False

            # Single output interface: use the linktype of the first frame's interface.
            linktype = links.get(frames[0][2], 1)
            with open(output_path, "wb") as dst:
                dst.write(build_shb())
                dst.write(build_idb(linktype))
                for ref, data, _ in frames:
                    dst.write(build_pcapng_epb_with_comment(data, ref.ts_us, ref.wirelen, comment))
            return True
        except (OSError, ValueError, struct.error) as e:
            print(f"Error carving evidence file '{output_path}': {e}")
            return False

    def carve_alert(self, alert: Alert, output_path: str) -> bool:
        comment = f"[NetShark {alert.alert_id}] {alert.rule_id} - {alert.title}"
        return self.carve_packets(alert.packet_refs, output_path, comment=comment)
