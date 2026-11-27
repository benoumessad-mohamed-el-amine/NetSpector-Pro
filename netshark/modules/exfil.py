"""Module 5: Data Exfiltration & Volume Skew Detector."""

import ipaddress
from typing import Any, Dict, List, Optional, Tuple
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity, stable_id
from netshark.modules import BaseModule
from netshark.modules.lateral import DEFAULT_INTERNAL_SUBNETS, is_internal_ip


class ExfiltrationModule(BaseModule):
    """Detects outbound volume anomalies and DNS tunneling payload exfiltration."""

    def __init__(self):
        super().__init__("exfil")
        self.min_exfil_bytes: int = 5_000_000  # 5 MB threshold
        self.max_ratio: float = 10.0
        self.alerted_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("exfil", rules.get("exfiltration", {}))
        self.min_exfil_bytes = cfg.get("min_exfil_bytes", 5_000_000)
        self.max_ratio = cfg.get("max_ratio", 10.0)
        subnets = rules.get("lateral", {}).get("internal_subnets") or DEFAULT_INTERNAL_SUBNETS
        self.internal_networks = [ipaddress.ip_network(n) for n in subnets]

    def _outbound(self, flow: Flow) -> Optional[Tuple[str, str, int, int]]:
        """Returns (internal_ip, external_ip, bytes_out, bytes_in) or None."""
        a_in = is_internal_ip(flow.endpoint_a_ip, self.internal_networks)
        b_in = is_internal_ip(flow.endpoint_b_ip, self.internal_networks)
        if a_in and not b_in:
            return flow.endpoint_a_ip, flow.endpoint_b_ip, flow.bytes_a_to_b, flow.bytes_b_to_a
        if b_in and not a_in:
            return flow.endpoint_b_ip, flow.endpoint_a_ip, flow.bytes_b_to_a, flow.bytes_a_to_b
        return None  # internal<->internal or external<->external is not exfil

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        # Check DNS Tunneling Exfiltration (QTYPE 16 TXT or payload len > 64)
        if pkt.dns_qname and (pkt.dns_qtype == 16 or len(pkt.dns_qname) > 64):
            if flow.flow_id not in self.alerted_flows:
                self.alerted_flows.add(flow.flow_id)
                dns_alert = Alert(
                    alert_id=f"ALT-DNSEXFIL-{stable_id(pkt.dns_qname):06d}",
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

        direction = self._outbound(flow)
        if direction is None:
            return []
        internal_ip, external_ip, bytes_out, bytes_in = direction
        # Upload-heavy: enough bytes out, and out/in skew above max_ratio.
        # The old check used total bytes, so every large download alerted.
        ratio = bytes_out / max(bytes_in, 1)
        if bytes_out >= self.min_exfil_bytes and ratio >= self.max_ratio:
            self.alerted_flows.add(flow.flow_id)
            alert = Alert(
                alert_id=f"ALT-EXFIL-{stable_id(flow.flow_id):06d}",
                rule_id="RULE-EXFIL-VOL-01",
                title="Large Outbound Data Exfiltration Volume Detected",
                description=(
                    f"{internal_ip} sent {bytes_out / (1024*1024):.2f} MB to {external_ip} "
                    f"({ratio:.1f}x more than it received)."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.EXFILTRATION,
                source_ip=internal_ip,
                target_ip=external_ip,
                source_port=flow.endpoint_a_port if internal_ip == flow.endpoint_a_ip else flow.endpoint_b_port,
                target_port=flow.endpoint_b_port if internal_ip == flow.endpoint_a_ip else flow.endpoint_a_port,
                protocol=str(flow.protocol),
                timestamp_us=flow.last_ts_us,
                flow_id=flow.flow_id,
                packet_refs=list(flow.packet_refs),
                arithmetic_proof={
                    "metric": "Outbound Flow Volume Anomaly",
                    "bytes_outbound": bytes_out,
                    "bytes_inbound": bytes_in,
                    "volume_mb": round(bytes_out / (1024 * 1024), 2),
                    "volume_threshold_bytes": self.min_exfil_bytes,
                    "out_in_ratio": round(ratio, 2),
                    "ratio_threshold": self.max_ratio,
                    "duration_sec": flow.duration_sec,
                },
            )
            return [alert]

        return []

    def finalize(self) -> List[Alert]:
        return []
