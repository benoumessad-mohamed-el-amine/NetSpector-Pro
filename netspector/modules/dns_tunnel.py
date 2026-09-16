"""Module 12: Advanced DNS Tunneling Payload Inspector."""

import math
from typing import Any, Dict, List
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule
from netspector.modules.entropy import extract_subdomain_parts, is_ad_enterprise_noise


class DnsTunnelModule(BaseModule):
    """Detects DNS Tunneling channels by tracking record type distribution (TXT/CNAME/NULL) and query repetition ratios."""

    def __init__(self):
        super().__init__("dns_tunnel")
        self.enabled: bool = True
        self.min_queries: int = 8
        self.min_avg_subdomain_len: float = 20.0
        self.domain_stats: Dict[str, Dict[str, Any]] = {}
        self.alerted_domains: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("dns_tunnel", {})
        self.enabled = cfg.get("enabled", True)
        self.min_queries = cfg.get("min_queries", 8)
        self.min_avg_subdomain_len = cfg.get("min_avg_subdomain_len", 20.0)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        if not self.enabled or not pkt.dns_qname:
            return []

        qname = pkt.dns_qname.lower()
        if is_ad_enterprise_noise(qname):
            return []

        subdomain, parent_domain = extract_subdomain_parts(qname)
        if not subdomain or parent_domain in self.alerted_domains:
            return []

        if parent_domain not in self.domain_stats:
            self.domain_stats[parent_domain] = {
                "query_count": 0,
                "txt_cname_count": 0,
                "subdomains": [],
                "total_len": 0,
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "packet_refs": [],
            }

        stats = self.domain_stats[parent_domain]
        stats["query_count"] += 1
        stats["subdomains"].append(subdomain)
        stats["total_len"] += len(subdomain)
        stats["packet_refs"].append(pkt)

        # Check QTYPE for TXT (16), CNAME (5), NULL (10), MX (15)
        if pkt.dns_qtype in (5, 10, 15, 16) or len(subdomain) > 30:
            stats["txt_cname_count"] += 1

        avg_len = stats["total_len"] / stats["query_count"]

        # Evaluate DNS Tunneling threshold gate
        if stats["query_count"] >= self.min_queries and avg_len >= self.min_avg_subdomain_len:
            self.alerted_domains.add(parent_domain)

            alert = Alert(
                alert_id=f"ALT-TUNNEL-{abs(hash(parent_domain)) % 1000000:06d}",
                rule_id="RULE-DNS-TUNNEL-01",
                title="Covert DNS Tunneling & Payload Encapsulation Channel Detected",
                description=(
                    f"Repetitive high-length DNS queries to domain '{parent_domain}' ({stats['query_count']} queries, "
                    f"avg subdomain length {avg_len:.1f} chars) indicates active covert DNS tunneling."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.COMMAND_AND_CONTROL,
                source_ip=stats["src_ip"],
                target_ip=stats["dst_ip"],
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol="UDP/DNS",
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=list(stats["packet_refs"]),
                arithmetic_proof={
                    "metric": "DNS Subdomain Length & Repetition Volume",
                    "target_parent_domain": parent_domain,
                    "total_queries_received": stats["query_count"],
                    "min_queries_threshold": self.min_queries,
                    "avg_subdomain_len_calculated": round(avg_len, 2),
                    "min_avg_subdomain_len_threshold": self.min_avg_subdomain_len,
                    "txt_cname_null_queries": stats["txt_cname_count"],
                    "sample_subdomains": stats["subdomains"][:5],
                },
            )
            return [alert]

        return []

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
