from typing import Any, Dict, List
from netshark.model import Alert, KillChainStage
from netshark.modules.entropy import calculate_shannon_entropy


STAGE_ORDER = {
    KillChainStage.RECONNAISSANCE: 1,
    KillChainStage.INITIAL_ACCESS: 2,
    KillChainStage.EXECUTION: 3,
    KillChainStage.PERSISTENCE: 4,
    KillChainStage.PRIVILEGE_ESCALATION: 5,
    KillChainStage.DEFENSE_EVASION: 6,
    KillChainStage.CREDENTIAL_ACCESS: 7,
    KillChainStage.DISCOVERY: 8,
    KillChainStage.LATERAL_MOVEMENT: 9,
    KillChainStage.COMMAND_AND_CONTROL: 10,
    KillChainStage.EXFILTRATION: 11,
}

QTYPE_MAP = {
    1: "A",
    28: "AAAA",
    5: "CNAME",
    16: "TXT",
    15: "MX",
    12: "PTR",
    33: "SRV",
    255: "ANY",
}


def extract_dns_telemetry(alerts: List[Alert]) -> List[Dict[str, Any]]:
    """Aggregates DNS queries, entropy scores, QTYPEs, and threat classifications."""
    dns_records: Dict[str, Dict[str, Any]] = {}

    for alert in alerts:
        proof = alert.arithmetic_proof or {}
        qname = proof.get("dns_qname") or proof.get("target_parent_domain")

        pkts = alert.packet_refs or []
        for pkt in pkts:
            p_qname = getattr(pkt, "dns_qname", None)
            if p_qname:
                qname = p_qname
                qtype_val = getattr(pkt, "dns_qtype", 1) or 1
                qtype_str = QTYPE_MAP.get(qtype_val, f"TYPE-{qtype_val}")

                if qname not in dns_records:
                    label = qname.split(".")[0] if "." in qname else qname
                    entropy_val, _ = calculate_shannon_entropy(label)
                    dns_records[qname] = {
                        "domain": qname,
                        "qtype": qtype_str,
                        "count": 0,
                        "entropy": round(entropy_val, 2),
                        "threat_status": "BENIGN",
                        "client_ip": pkt.src_ip,
                    }
                dns_records[qname]["count"] += 1

        if qname and qname in dns_records:
            if "TUNNEL" in alert.rule_id or "TUNNEL" in alert.alert_id:
                dns_records[qname]["threat_status"] = "COVERT DNS TUNNELING"
            elif "DGA" in alert.rule_id or "ENTROPY" in alert.rule_id:
                dns_records[qname]["threat_status"] = "HIGH ENTROPY / DGA"

    return list(dns_records.values())


def extract_suspicious_payloads(alerts: List[Alert]) -> List[Dict[str, Any]]:
    """Extracts suspicious URLs, HTTP User-Agents, cleartext auth credentials, and file transfers."""
    payload_items = []

    for alert in alerts:
        proof = alert.arithmetic_proof or {}

        if "HTTP" in alert.rule_id or "WEB" in alert.rule_id or "HTTP" in alert.title.upper():
            payload_items.append({
                "source_ip": alert.source_ip,
                "target_ip": alert.target_ip,
                "target_port": alert.target_port,
                "url_or_path": proof.get("request_path") or proof.get("uri") or f"http://{alert.target_ip}:{alert.target_port}/",
                "method": proof.get("http_method") or "GET",
                "user_agent": proof.get("user_agent") or "N/A",
                "threat_category": proof.get("threat_type") or alert.title,
                "proof_summary": alert.description,
            })

        elif "CRED" in alert.rule_id or "Credential" in alert.title:
            payload_items.append({
                "source_ip": alert.source_ip,
                "target_ip": alert.target_ip,
                "target_port": alert.target_port,
                "url_or_path": f"{alert.protocol.lower()}://{alert.target_ip}:{alert.target_port}",
                "method": "AUTH",
                "user_agent": "Unencrypted Auth Client",
                "threat_category": "Exposed Cleartext Credentials",
                "proof_summary": f"Exposed Username: {proof.get('username', 'N/A')} | Protocol: {proof.get('protocol', alert.protocol)}",
            })

        elif "MAGIC" in alert.rule_id or "CARVE" in alert.rule_id or "File Signature" in alert.title:
            payload_items.append({
                "source_ip": alert.source_ip,
                "target_ip": alert.target_ip,
                "target_port": alert.target_port,
                "url_or_path": f"tcp://{alert.target_ip}:{alert.target_port} (Offset: {proof.get('payload_offset', 0)})",
                "method": "BINARY TRANSFER",
                "user_agent": f"Magic Bytes: {proof.get('magic_bytes_ascii', 'N/A')} ({proof.get('magic_bytes_hex', '')})",
                "threat_category": f"Cleartext Binary File Transfer ({proof.get('detected_file_type', 'Executable')})",
                "proof_summary": alert.description,
            })

    return payload_items


class EntityTimeline:
    """Represents a correlated timeline of alerts for a specific host entity."""

    def __init__(self, entity_ip: str):
        self.entity_ip = entity_ip
        self.alerts: List[Alert] = []

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)

    def finalize_timeline(self) -> Dict[str, Any]:
        """Sorts alerts chronologically and calculates attack chain plausibility score."""
        self.alerts.sort(key=lambda a: a.timestamp_us)

        stages_present = []
        stage_order_indices = []

        for a in self.alerts:
            st = a.stage
            if st.value not in stages_present:
                stages_present.append(st.value)
                stage_order_indices.append(STAGE_ORDER.get(st, 99))

        distinct_stages_count = len(stages_present)
        coverage_score = min(distinct_stages_count / 5.0, 1.0) * 60.0

        is_monotonic = all(
            stage_order_indices[i] <= stage_order_indices[i + 1]
            for i in range(len(stage_order_indices) - 1)
        )
        alignment_score = 40.0 if (is_monotonic and len(stage_order_indices) > 1) else 15.0

        plausibility_score = round(coverage_score + alignment_score, 1)

        return {
            "entity_ip": self.entity_ip,
            "total_alerts": len(self.alerts),
            "stages_covered": stages_present,
            "plausibility_score": plausibility_score,
            "chronological_alignment": "High" if is_monotonic else "Moderate",
            "timeline": [a.to_dict() for a in self.alerts],
        }


class AttackChainStitcher:
    """Stitches correlated forensic alerts into entity-centric attack chain narratives."""

    def __init__(self, alerts: List[Alert]):
        self.alerts = alerts

    def correlate(self) -> Dict[str, Any]:
        entities: Dict[str, EntityTimeline] = {}

        for alert in self.alerts:
            if alert.source_ip:
                if alert.source_ip not in entities:
                    entities[alert.source_ip] = EntityTimeline(alert.source_ip)
                entities[alert.source_ip].add_alert(alert)

            if alert.target_ip and alert.target_ip != alert.source_ip:
                if alert.target_ip not in entities:
                    entities[alert.target_ip] = EntityTimeline(alert.target_ip)
                entities[alert.target_ip].add_alert(alert)

        correlated_entities = []
        for ip, timeline in entities.items():
            narrative = timeline.finalize_timeline()
            correlated_entities.append(narrative)

        correlated_entities.sort(key=lambda e: e["plausibility_score"], reverse=True)

        dns_report = extract_dns_telemetry(self.alerts)
        suspicious_payloads = extract_suspicious_payloads(self.alerts)

        return {
            "total_correlated_entities": len(correlated_entities),
            "entities": correlated_entities,
            "dns_report": dns_report,
            "suspicious_payloads": suspicious_payloads,
        }
