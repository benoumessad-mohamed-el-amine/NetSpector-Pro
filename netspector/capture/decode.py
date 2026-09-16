"""Direct binary packet header decoding using Python stdlib struct and socket."""

import socket
import struct
from typing import Any, Dict, Optional, Tuple


# Common Link Layer Types (pcap linktypes)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

# EtherTypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_VLAN_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD

# IP Protocols
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


def format_mac(raw_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_bytes)


def format_ipv4(raw_bytes: bytes) -> str:
    return socket.inet_ntoa(raw_bytes)


def format_ipv6(raw_bytes: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw_bytes)
    except Exception:
        # Fallback manual IPv6 format
        hex_str = raw_bytes.hex()
        parts = [hex_str[i:i+4] for i in range(0, 32, 4)]
        return ":".join(parts)


def parse_dns_name(payload: bytes, offset: int = 0) -> Tuple[Optional[str], int]:
    """Parses DNS domain name (QNAME) from payload handling label length octets and pointers."""
    labels = []
    visited_offsets = set()
    curr = offset
    original_next_offset = None

    try:
        while curr < len(payload):
            if curr in visited_offsets:
                # Compression pointer loop protection
                break
            visited_offsets.add(curr)

            length = payload[curr]
            if length == 0:
                if original_next_offset is None:
                    original_next_offset = curr + 1
                break

            # Check if this is a compression pointer (top 2 bits set: 0xC0)
            if (length & 0xC0) == 0xC0:
                if curr + 1 >= len(payload):
                    break
                pointer = ((length & 0x3F) << 8) | payload[curr + 1]
                if original_next_offset is None:
                    original_next_offset = curr + 2
                curr = pointer
                continue

            # Standard label
            curr += 1
            if curr + length > len(payload):
                break
            labels.append(payload[curr:curr + length].decode("ascii", errors="replace"))
            curr += length

        dns_name = ".".join(labels) if labels else None
        next_offset = original_next_offset if original_next_offset is not None else curr
        return dns_name, next_offset
    except Exception:
        return None, offset


def decode_dns(payload: bytes) -> Dict[str, Any]:
    """Decodes DNS query header and QNAME/QTYPE."""
    dns_info: Dict[str, Any] = {"qname": None, "qtype": None, "qr": 0}
    if len(payload) < 12:
        return dns_info

    try:
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
        dns_info["tx_id"] = tx_id
        dns_info["qr"] = (flags >> 15) & 1

        if qdcount > 0:
            qname, next_off = parse_dns_name(payload, 12)
            dns_info["qname"] = qname
            if qname and next_off + 4 <= len(payload):
                qtype, qclass = struct.unpack("!HH", payload[next_off:next_off + 4])
                dns_info["qtype"] = qtype
    except Exception:
        pass

    return dns_info


def decode_packet(raw_data: bytes, linktype: int = LINKTYPE_ETHERNET) -> Optional[Dict[str, Any]]:
    """Decodes binary packet raw payload starting from link-layer header down to L7."""
    if not raw_data:
        return None

    offset = 0
    ethertype = 0
    src_mac, dst_mac = "", ""

    if linktype == LINKTYPE_ETHERNET:
        if len(raw_data) < 14:
            return None
        dst_mac = format_mac(raw_data[0:6])
        src_mac = format_mac(raw_data[6:12])
        ethertype = struct.unpack("!H", raw_data[12:14])[0]
        offset = 14

        # Handle 802.1Q VLAN Tags
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_VLAN_QINQ) and offset + 4 <= len(raw_data):
            # 2 bytes VLAN TCI, 2 bytes inner EtherType
            ethertype = struct.unpack("!H", raw_data[offset + 2:offset + 4])[0]
            offset += 4

    elif linktype == LINKTYPE_LINUX_SLL:
        if len(raw_data) < 16:
            return None
        packet_type, arphrd_type, addr_len = struct.unpack("!HHH", raw_data[0:6])
        ethertype = struct.unpack("!H", raw_data[14:16])[0]
        offset = 16

    elif linktype in (LINKTYPE_RAW, LINKTYPE_NULL):
        # Determine IP version directly from first nibble
        if len(raw_data) < 1:
            return None
        ip_ver = (raw_data[0] >> 4) & 0x0F
        ethertype = ETHERTYPE_IPV4 if ip_ver == 4 else (ETHERTYPE_IPV6 if ip_ver == 6 else 0)
        offset = 0 if linktype == LINKTYPE_RAW else 4

    else:
        # Unsupported linktype fallback: attempt IPv4/IPv6 heuristic check
        ip_ver = (raw_data[0] >> 4) & 0x0F
        if ip_ver == 4:
            ethertype = ETHERTYPE_IPV4
            offset = 0
        elif ip_ver == 6:
            ethertype = ETHERTYPE_IPV6
            offset = 0
        else:
            return None

    # Parse Layer 3
    src_ip, dst_ip = "", ""
    protocol = 0
    l4_data = b""

    if ethertype == ETHERTYPE_IPV4:
        if len(raw_data) < offset + 20:
            return None
        iph = raw_data[offset:offset + 20]
        ver_ihl, tos, tot_len, ip_id, frag_off, ttl, protocol, check, s_ip, d_ip = struct.unpack(
            "!BBHHHBBH4s4s", iph
        )
        ihl = (ver_ihl & 0x0F) * 4
        if len(raw_data) < offset + ihl:
            return None
        src_ip = format_ipv4(s_ip)
        dst_ip = format_ipv4(d_ip)
        l4_data = raw_data[offset + ihl:]

    elif ethertype == ETHERTYPE_IPV6:
        if len(raw_data) < offset + 40:
            return None
        ip6h = raw_data[offset:offset + 40]
        vtc_flow, payload_len, next_header, hop_limit, s_ip6, d_ip6 = struct.unpack(
            "!IHBB16s16s", ip6h
        )
        protocol = next_header
        src_ip = format_ipv6(s_ip6)
        dst_ip = format_ipv6(d_ip6)
        l4_data = raw_data[offset + 40:]

    elif ethertype == ETHERTYPE_ARP:
        if len(raw_data) < offset + 28:
            return None
        arph = raw_data[offset:offset + 28]
        hw_type, proto_type, hw_len, proto_len, opcode, s_mac, s_ip, t_mac, t_ip = struct.unpack(
            "!HHBBH6s4s6s4s", arph
        )
        return {
            "l2": {"src_mac": src_mac, "dst_mac": dst_mac},
            "l3": {
                "protocol_name": "ARP",
                "opcode": opcode,
                "src_ip": format_ipv4(s_ip),
                "dst_ip": format_ipv4(t_ip),
                "src_mac": format_mac(s_mac),
                "dst_mac": format_mac(t_mac),
            },
            "src_ip": format_ipv4(s_ip),
            "dst_ip": format_ipv4(t_ip),
            "src_port": 0,
            "dst_port": 0,
            "protocol": 2054,  # EtherType ARP
            "payload_len": len(l4_data),
        }
    else:
        return None

    # Parse Layer 4
    src_port, dst_port = 0, 0
    tcp_seq, tcp_ack, tcp_flags = 0, 0, 0
    dns_info = {}
    payload = b""

    if protocol == IPPROTO_TCP:
        if len(l4_data) < 20:
            return None
        tcph = l4_data[:20]
        src_port, dst_port, tcp_seq, tcp_ack, offset_reserved_flags, window, check, urg = struct.unpack(
            "!HHIIHHHH", tcph
        )
        tcp_header_len = ((offset_reserved_flags >> 12) & 0x0F) * 4
        tcp_flags = offset_reserved_flags & 0x01FF  # Extract flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS)
        payload = l4_data[tcp_header_len:]

    elif protocol == IPPROTO_UDP:
        if len(l4_data) < 8:
            return None
        src_port, dst_port, udp_len, check = struct.unpack("!HHHH", l4_data[:8])
        payload = l4_data[8:]

        # Decode DNS if port is 53
        if src_port == 53 or dst_port == 53:
            dns_info = decode_dns(payload)

    elif protocol in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        if len(l4_data) >= 8:
            icmp_type, icmp_code = l4_data[0], l4_data[1]
            src_port = icmp_type
            dst_port = icmp_code

    return {
        "l2": {"src_mac": src_mac, "dst_mac": dst_mac},
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "tcp_seq": tcp_seq,
        "tcp_ack": tcp_ack,
        "tcp_flags": tcp_flags,
        "dns_qname": dns_info.get("qname"),
        "dns_qtype": dns_info.get("qtype"),
        "payload_len": len(payload),
    }
