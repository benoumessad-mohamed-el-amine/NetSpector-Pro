"""Module: Data Exfiltration & DNS Tunneling Inspector."""

from typing import Any, Dict, List
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


class ExfiltrationModule(BaseModule):
    """Detects outbound volume anomalies and DNS tunneling payload exfiltration."""

    def __init__(self):
        super().__init__("exfiltration")
        self.min_exfil_bytes: int = 5_000_000  # 5 MB threshold
        self.max_ratio: float = 10.0
        self.alerted_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("exfiltration", {})
        self.min_exfil_bytes = cfg.get("min_exfil_bytes", 5_000_000)
        self.max_ratio = cfg.get("max_ratio", 10.0)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        # Check DNS Tunneling Exfiltration (QTYPE 16 TXT or payload len > 64)
        if pkt.dns_qname and (pkt.dns_qtype == 16 or len(pkt.dns_qname) > 64):
            if flow.flow_id not in self.alerted_flows:
                self.alerted_flows.add(flow.flow_id)
                dns_alert = Alert(
                    alert_id=f"ALT-DNSEXFIL-{abs(hash(pkt.dns_qname)) % 1000000:06d}",
                    rule_id="RULE-EXFIL-DNS-01",
                    title="DNS Data Exfiltration / Tunneling Payload Detected",
                    description=(
                        f"DNS query '{pkt.dns_qname[:40]}...' carries encoded data payload "
                        f"({len(pkt.dns_qname)} chars) typical of DNS tunneling."
                    ),
                    severity=Severity.HIGH,
                    stage=KillChainStage.EXFILTRATION,
                    source_ip=pkt.src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol="UDP/DNS",
                    timestamp_us=pkt.ts_us,
                    flow_id=pkt.flow_id,
                    packet_refs=[pkt],
                    arithmetic_proof={
                        "metric": "DNS Query Payload Character Length",
                        "dns_qname": pkt.dns_qname,
                        "payload_char_len": len(pkt.dns_qname),
                        "qtype": pkt.dns_qtype,
                        "threshold_len": 64,
                    },
                )
                alerts.append(dns_alert)

        return alerts

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        if flow.flow_id in self.alerted_flows:
            return []

        # Evaluate total byte volume and ratio on flow close
        if flow.byte_count >= self.min_exfil_bytes:
            self.alerted_flows.add(flow.flow_id)
            alert = Alert(
                alert_id=f"ALT-EXFIL-{abs(hash(flow.flow_id)) % 1000000:06d}",
                rule_id="RULE-EXFIL-VOL-01",
                title="Large Outbound Data Exfiltration Volume Detected",
                description=(
                    f"Flow {flow.flow_id} transferred {flow.byte_count / (1024*1024):.2f} MB "
                    f"to external destination host."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.EXFILTRATION,
                source_ip=flow.endpoint_a_ip,
                target_ip=flow.endpoint_b_ip,
                source_port=flow.endpoint_a_port,
                target_port=flow.endpoint_b_port,
                protocol=str(flow.protocol),
                timestamp_us=flow.last_ts_us,
                flow_id=flow.flow_id,
                packet_refs=list(flow.packet_refs),
                arithmetic_proof={
                    "metric": "Outbound Flow Volume Anomaly",
                    "total_bytes_transferred": flow.byte_count,
                    "volume_mb": round(flow.byte_count / (1024 * 1024), 2),
                    "volume_threshold_bytes": self.min_exfil_bytes,
                    "duration_sec": flow.duration_sec,
                },
            )
            return [alert]

        return []

    def finalize(self) -> List[Alert]:
        return []
