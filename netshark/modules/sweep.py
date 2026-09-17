"""Module 7: Stealth Port Scan & Horizontal Subnet Sweep Detector."""

from typing import Any, Dict, List, Set
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netshark.modules import BaseModule


class SubnetSweepModule(BaseModule):
    """Detects stateful horizontal network sweeps and multi-target IP scanning activities."""

    def __init__(self):
        super().__init__("sweep")
        self.sweep_threshold: int = 10
        # Tracks target IPs contacted per source IP: src_ip -> set of target_ip
        self.sweeper_targets: Dict[str, Set[str]] = {}
        self.sweeper_ports: Dict[str, Set[int]] = {}
        self.sweeper_pkt_refs: Dict[str, List[PacketRef]] = {}
        self.alerted_sweepers: Set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("sweep", {})
        self.sweep_threshold = cfg.get("sweep_threshold", 10)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        # Only evaluate outbound TCP SYN attempts or ICMP echo requests
        is_syn = (pkt.protocol == 6 and (pkt.tcp_flags & 0x02) and not (pkt.tcp_flags & 0x10))
        is_icmp_echo = (pkt.protocol == 1 and pkt.src_port == 8)  # ICMP type 8 (Echo Request)

        if not (is_syn or is_icmp_echo):
            return alerts

        src_ip = pkt.src_ip
        dst_ip = pkt.dst_ip

        # Ignore local loopback self-scanning
        if src_ip == dst_ip:
            return alerts

        if src_ip not in self.sweeper_targets:
            self.sweeper_targets[src_ip] = set()
            self.sweeper_ports[src_ip] = set()
            self.sweeper_pkt_refs[src_ip] = []

        self.sweeper_targets[src_ip].add(dst_ip)
        self.sweeper_ports[src_ip].add(pkt.dst_port)
        self.sweeper_pkt_refs[src_ip].append(pkt)

        unique_targets_count = len(self.sweeper_targets[src_ip])

        if unique_targets_count >= self.sweep_threshold and src_ip not in self.alerted_sweepers:
            self.alerted_sweepers.add(src_ip)

            target_sample = sorted(list(self.sweeper_targets[src_ip]))[:5]
            ports_sample = sorted(list(self.sweeper_ports[src_ip]))[:5]

            alert = Alert(
                alert_id=f"ALT-SWEEP-{abs(hash(src_ip)) % 1000000:06d}",
                rule_id="RULE-RECON-SWEEP-01",
                title="Horizontal Subnet Reconnaissance Sweep Detected",
                description=(
                    f"Host {src_ip} executed a horizontal subnet reconnaissance sweep across "
                    f"{unique_targets_count} distinct target IP addresses."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.RECONNAISSANCE,
                source_ip=src_ip,
                target_ip=pkt.dst_ip,
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol="IP/Sweep",
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=list(self.sweeper_pkt_refs[src_ip]),
                arithmetic_proof={
                    "metric": "Horizontal Target IP Sweep Count",
                    "source_sweeper_host": src_ip,
                    "unique_target_ips_count": unique_targets_count,
                    "sweep_threshold": self.sweep_threshold,
                    "sample_target_ips": target_sample,
                    "sample_target_ports": ports_sample,
                    "passed_threshold": True,
                },
            )
            alerts.append(alert)

        return alerts

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
