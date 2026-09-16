"""Live raw socket network sniffer for Linux network interfaces."""

import socket
import time
from typing import Generator
from netspector.capture.decode import decode_packet
from netspector.flows import canonical_flow_key, flow_key_to_str
from netspector.model import PacketRef


class LiveSocketReader:
    """Stream-based live network interface sniffer using Python stdlib raw sockets."""

    def __init__(self, interface: str = "eth0", max_snaplen: int = 65535):
        self.interface = interface
        self.max_snaplen = max_snaplen
        self.sock = None

    def open(self):
        try:
            # AF_PACKET, SOCK_RAW, ETH_P_ALL (0x0003 in network byte order)
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.sock.bind((self.interface, 0))
        except PermissionError:
            raise PermissionError(
                f"Permission denied to open raw socket on '{self.interface}'. "
                f"Please run with root/sudo or grant CAP_NET_RAW capability."
            )
        except Exception as e:
            raise RuntimeError(f"Failed to open live interface '{self.interface}': {e}")

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def packets(self, max_packets: int = 0) -> Generator[PacketRef, None, None]:
        """Iterates over live captured raw frames and yields PacketRef objects."""
        if not self.sock:
            self.open()

        pkt_count = 0
        file_offset = 0

        while True:
            if max_packets > 0 and pkt_count >= max_packets:
                break

            try:
                raw_bytes, addr = self.sock.recvfrom(self.max_snaplen)
                if not raw_bytes:
                    continue

                ts_us = time.time_ns() // 1000
                caplen = len(raw_bytes)
                wirelen = caplen

                decoded = decode_packet(raw_bytes, linktype=1)  # Ethernet
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
                    file_offset=file_offset,
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
                    payload_len=decoded.get("payload_len", 0),
                )
                setattr(pkt_ref, "tls_info", decoded.get("tls_info"))

                file_offset += caplen + 16
                pkt_count += 1
                yield pkt_ref

            except KeyboardInterrupt:
                break
            except Exception:
                continue
