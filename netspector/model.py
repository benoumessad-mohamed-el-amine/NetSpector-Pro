"""Core data models for NetSpector Pro."""

from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class KillChainStage(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COMMAND_AND_CONTROL = "Command & Control"
    EXFILTRATION = "Exfiltration"


class PacketRef:
    """Lightweight slot-based packet reference representation.
    
    Avoids holding raw packet payload bytes in memory while preserving file offsets
    for instant binary PCAP carving.
    """
    __slots__ = (
        'ts_us',
        'file_offset',
        'caplen',
        'wirelen',
        'flow_id',
        'src_ip',
        'dst_ip',
        'src_port',
        'dst_port',
        'protocol',
        'tcp_seq',
        'tcp_ack',
        'tcp_flags',
        'dns_qname',
        'dns_qtype',
        'payload_len',
    )

    def __init__(
        self,
        ts_us: int,
        file_offset: int,
        caplen: int,
        wirelen: int,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        tcp_seq: int = 0,
        tcp_ack: int = 0,
        tcp_flags: int = 0,
        dns_qname: Optional[str] = None,
        dns_qtype: Optional[int] = None,
        payload_len: int = 0,
    ):
        self.ts_us = ts_us
        self.file_offset = file_offset
        self.caplen = caplen
        self.wirelen = wirelen
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.tcp_seq = tcp_seq
        self.tcp_ack = tcp_ack
        self.tcp_flags = tcp_flags
        self.dns_qname = dns_qname
        self.dns_qtype = dns_qtype
        self.payload_len = payload_len

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts_us": self.ts_us,
            "ts_sec": self.ts_us / 1_000_000.0,
            "file_offset": self.file_offset,
            "caplen": self.caplen,
            "wirelen": self.wirelen,
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "tcp_flags": self.tcp_flags,
            "dns_qname": self.dns_qname,
            "dns_qtype": self.dns_qtype,
            "payload_len": self.payload_len,
        }


class Flow:
    """Represents an active or historical network flow keyed by canonical 5-tuple."""
    def __init__(
        self,
        flow_id: str,
        endpoint_a_ip: str,
        endpoint_a_port: int,
        endpoint_b_ip: str,
        endpoint_b_port: int,
        protocol: int,
    ):
        self.flow_id = flow_id
        self.endpoint_a_ip = endpoint_a_ip
        self.endpoint_a_port = endpoint_a_port
        self.endpoint_b_ip = endpoint_b_ip
        self.endpoint_b_port = endpoint_b_port
        self.protocol = protocol

        self.packet_count: int = 0
        self.byte_count: int = 0
        self.start_ts_us: int = 0
        self.last_ts_us: int = 0
        self.packet_refs: List[PacketRef] = []

        # TCP state tracking variables
        self.tcp_state: str = "CLOSED"
        self.syn_count: int = 0
        self.syn_ack_count: int = 0
        self.ack_count: int = 0
        self.fin_count: int = 0
        self.rst_count: int = 0
        self.closed: bool = False

    def add_packet(self, pkt: PacketRef):
        if self.packet_count == 0:
            self.start_ts_us = pkt.ts_us
        self.last_ts_us = pkt.ts_us
        self.packet_count += 1
        self.byte_count += pkt.wirelen
        self.packet_refs.append(pkt)

    @property
    def duration_sec(self) -> float:
        if self.packet_count <= 1:
            return 0.0
        return (self.last_ts_us - self.start_ts_us) / 1_000_000.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "endpoint_a": f"{self.endpoint_a_ip}:{self.endpoint_a_port}",
            "endpoint_b": f"{self.endpoint_b_ip}:{self.endpoint_b_port}",
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "start_ts_sec": self.start_ts_us / 1_000_000.0,
            "last_ts_sec": self.last_ts_us / 1_000_000.0,
            "duration_sec": round(self.duration_sec, 4),
            "tcp_state": self.tcp_state,
            "closed": self.closed,
        }


class Alert:
    """Forensic alert object containing findings and transparent arithmetic proofs."""
    def __init__(
        self,
        alert_id: str,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        stage: KillChainStage,
        source_ip: str,
        target_ip: str,
        source_port: int,
        target_port: int,
        protocol: str,
        timestamp_us: int,
        flow_id: Optional[str] = None,
        packet_refs: Optional[List[PacketRef]] = None,
        arithmetic_proof: Optional[Dict[str, Any]] = None,
    ):
        self.alert_id = alert_id
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.stage = stage
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.source_port = source_port
        self.target_port = target_port
        self.protocol = protocol
        self.timestamp_us = timestamp_us
        self.flow_id = flow_id
        self.packet_refs = packet_refs or []
        self.arithmetic_proof = arithmetic_proof or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "stage": self.stage.value,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "source_port": self.source_port,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "timestamp_us": self.timestamp_us,
            "timestamp_sec": self.timestamp_us / 1_000_000.0,
            "flow_id": self.flow_id,
            "packet_count": len(self.packet_refs),
            "packet_offsets": [p.file_offset for p in self.packet_refs],
            "arithmetic_proof": self.arithmetic_proof,
        }
