"""Module 3: TCP State Auditor and Scan Detector."""

from typing import Any, Dict, List, Set
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


# TCP Flag Bitmasks
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


def get_flag_names(flags: int) -> List[str]:
    names = []
    if flags & TCP_SYN: names.append("SYN")
    if flags & TCP_ACK: names.append("ACK")
    if flags & TCP_FIN: names.append("FIN")
    if flags & TCP_RST: names.append("RST")
    if flags & TCP_PSH: names.append("PSH")
    if flags & TCP_URG: names.append("URG")
    if flags & TCP_ECE: names.append("ECE")
    if flags & TCP_CWR: names.append("CWR")
    return names


class TcpStateModule(BaseModule):
    """Audits TCP connection state machine transitions and flags port scans / illegal flag combinations."""

    def __init__(self):
        super().__init__("tcpstate")
        self.syn_scan_threshold: int = 10
        self.flag_anomalies_enabled: bool = True

        # Tracks half-open SYN scan targets per source IP: src_ip -> set of (target_ip, target_port)
        self.half_open_scans: Dict[str, Set[tuple[str, int]]] = {}
        self.half_open_pkt_refs: Dict[str, List[PacketRef]] = {}
        self.alerted_scanners: Set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("tcpstate", {})
        self.syn_scan_threshold = cfg.get("syn_scan_threshold", 10)
        self.flag_anomalies_enabled = cfg.get("flag_anomalies_enabled", True)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        if pkt.protocol != 6:  # TCP protocol only
            return alerts

        flags = pkt.tcp_flags

        # 1. Flag Anomaly Detection (NULL, XMAS, FIN-only, SYN-FIN)
        if self.flag_anomalies_enabled:
            flag_alert = self._check_flag_anomalies(pkt, flags)
            if flag_alert:
                alerts.append(flag_alert)

        # 2. Strict State Transition & Half-Open Tracking
        self._update_flow_tcp_state(pkt, flow, flags)

        # Track half-open SYN attempts
        if (flags & TCP_SYN) and not (flags & TCP_ACK):
            src_ip = pkt.src_ip
            if src_ip not in self.half_open_scans:
                self.half_open_scans[src_ip] = set()
                self.half_open_pkt_refs[src_ip] = []

            self.half_open_scans[src_ip].add((pkt.dst_ip, pkt.dst_port))
            self.half_open_pkt_refs[src_ip].append(pkt)

            # Check threshold gate for SYN Scan
            unique_targets = len(self.half_open_scans[src_ip])
            if unique_targets >= self.syn_scan_threshold and src_ip not in self.alerted_scanners:
                self.alerted_scanners.add(src_ip)
                scan_alert = Alert(
                    alert_id=f"ALT-TCPSCAN-{abs(hash(src_ip)) % 1000000:06d}",
                    rule_id="RULE-TCP-SCAN-01",
                    title="TCP Half-Open SYN Port Scan Detected",
                    description=(
                        f"Host {src_ip} initiated {unique_targets} half-open SYN connection attempts "
                        f"across target ports without completing 3-way handshakes."
                    ),
                    severity=Severity.HIGH,
                    stage=KillChainStage.RECONNAISSANCE,
                    source_ip=src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol="TCP",
                    timestamp_us=pkt.ts_us,
                    flow_id=pkt.flow_id,
                    packet_refs=list(self.half_open_pkt_refs[src_ip]),
                    arithmetic_proof={
                        "metric": "TCP Half-Open SYN Scan Count",
                        "source_host": src_ip,
                        "unique_target_ports_count": unique_targets,
                        "scan_threshold": self.syn_scan_threshold,
                        "state_pattern": "SYN sent without final ACK",
                        "passed_gate": True,
                    },
                )
                alerts.append(scan_alert)

        return alerts

    def _check_flag_anomalies(self, pkt: PacketRef, flags: int) -> Alert | None:
        anomaly_type = None

        if flags == 0:
            anomaly_type = "NULL Scan (No Flags Set)"
        elif (flags & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG):
            anomaly_type = "XMAS Scan (FIN+PSH+URG Flags Set)"
        elif (flags & TCP_FIN) and not (flags & TCP_ACK):
            anomaly_type = "FIN Stealth Scan (FIN without ACK)"
        elif (flags & TCP_SYN) and (flags & TCP_FIN):
            anomaly_type = "SYN-FIN Illegal Flag Combination"

        if anomaly_type:
            return Alert(
                alert_id=f"ALT-FLAGANOM-{abs(hash(pkt.file_offset)) % 1000000:06d}",
                rule_id="RULE-TCP-FLAGS-01",
                title=f"TCP Flag Anomaly: {anomaly_type}",
                description=f"Packet from {pkt.src_ip} contains illegal or stealth scan flag combination: {get_flag_names(flags)}.",
                severity=Severity.MEDIUM,
                stage=KillChainStage.RECONNAISSANCE,
                source_ip=pkt.src_ip,
                target_ip=pkt.dst_ip,
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol="TCP",
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=[pkt],
                arithmetic_proof={
                    "metric": "TCP Flag Bitmask Anomaly",
                    "raw_flags_hex": f"0x{flags:03x}",
                    "parsed_flag_names": get_flag_names(flags),
                    "anomaly_classification": anomaly_type,
                },
            )
        return None

    def _update_flow_tcp_state(self, pkt: PacketRef, flow: Flow, flags: int):
        if flags & TCP_SYN:
            flow.syn_count += 1
            if flags & TCP_ACK:
                flow.syn_ack_count += 1
                flow.tcp_state = "SYN_RCVD"
            else:
                flow.tcp_state = "SYN_SENT"
        elif flags & TCP_ACK:
            flow.ack_count += 1
            if flow.tcp_state in ("SYN_RCVD", "SYN_SENT"):
                flow.tcp_state = "ESTABLISHED"
        if flags & TCP_FIN:
            flow.fin_count += 1
            flow.tcp_state = "FIN_WAIT"
        if flags & TCP_RST:
            flow.rst_count += 1
            flow.tcp_state = "RESET"

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
