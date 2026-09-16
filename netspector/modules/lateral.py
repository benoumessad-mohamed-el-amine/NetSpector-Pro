"""Module 4: Lateral Movement and Internal High-Risk Port Pivoting Detector."""

import ipaddress
from typing import Any, Dict, List, Set
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


DEFAULT_HIGH_RISK_PORTS = {22, 88, 135, 139, 445, 3389, 5985, 5986}
DEFAULT_INTERNAL_SUBNETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


def is_internal_ip(ip_str: str, networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    """Returns True if IP address belongs to one of the internal network ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in networks)
    except Exception:
        return False


class LateralMovementModule(BaseModule):
    """Detects internal host fan-out ratios and lateral movement pivoting over remote management protocols."""

    def __init__(self):
        super().__init__("lateral")
        self.fanout_threshold: int = 15
        self.high_risk_ports: Set[int] = set(DEFAULT_HIGH_RISK_PORTS)
        self.internal_networks: List[Any] = [
            ipaddress.ip_network(net) for net in DEFAULT_INTERNAL_SUBNETS
        ]

        # Tracks internal connection fan-out: src_ip -> set of (target_ip, target_port)
        self.host_pivots: Dict[str, Set[tuple[str, int]]] = {}
        self.host_pkt_refs: Dict[str, List[PacketRef]] = {}
        self.alerted_hosts: Set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("lateral", {})
        self.fanout_threshold = cfg.get("fanout_threshold", 15)

        ports = cfg.get("high_risk_ports")
        if ports:
            self.high_risk_ports = set(ports)

        subnets = cfg.get("internal_subnets")
        if subnets:
            parsed_nets = []
            for net in subnets:
                try:
                    parsed_nets.append(ipaddress.ip_network(net))
                except Exception:
                    pass
            if parsed_nets:
                self.internal_networks = parsed_nets

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        # Check if destination port is high-risk
        if pkt.dst_port not in self.high_risk_ports:
            return alerts

        # Check if both source and target IPs are internal network addresses
        if not is_internal_ip(pkt.src_ip, self.internal_networks) or not is_internal_ip(pkt.dst_ip, self.internal_networks):
            return alerts

        src_ip = pkt.src_ip
        if src_ip not in self.host_pivots:
            self.host_pivots[src_ip] = set()
            self.host_pkt_refs[src_ip] = []

        self.host_pivots[src_ip].add((pkt.dst_ip, pkt.dst_port))
        self.host_pkt_refs[src_ip].append(pkt)

        # Count unique internal targets contacted over high-risk ports
        unique_targets = len(self.host_pivots[src_ip])

        if unique_targets >= self.fanout_threshold and src_ip not in self.alerted_hosts:
            self.alerted_hosts.add(src_ip)

            ports_used = sorted(list({port for _, port in self.host_pivots[src_ip]}))
            targets_list = sorted(list({ip for ip, _ in self.host_pivots[src_ip]}))

            alert = Alert(
                alert_id=f"ALT-LATERAL-{abs(hash(src_ip)) % 1000000:06d}",
                rule_id="RULE-LATERAL-MOVE-01",
                title="Internal Host Lateral Movement & Pivot Activity",
                description=(
                    f"Internal host {src_ip} initiated remote management connections to {unique_targets} "
                    f"internal target endpoints over high-risk management ports ({ports_used})."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.LATERAL_MOVEMENT,
                source_ip=src_ip,
                target_ip=pkt.dst_ip,
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol="TCP/Pivoting",
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=list(self.host_pkt_refs[src_ip]),
                arithmetic_proof={
                    "metric": "Internal High-Risk Target Fan-Out Count",
                    "source_internal_host": src_ip,
                    "unique_internal_targets_count": unique_targets,
                    "fanout_threshold": self.fanout_threshold,
                    "ports_contacted": ports_used,
                    "high_risk_ports_monitored": sorted(list(self.high_risk_ports)),
                    "sample_target_ips": targets_list[:5],
                    "passed_threshold": True,
                },
            )
            alerts.append(alert)

        return alerts

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
