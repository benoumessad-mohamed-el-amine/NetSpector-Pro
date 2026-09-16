"""JA3 & JA4 TLS Client Hello Fingerprinting Module."""

import hashlib
from typing import Any, Dict, List, Optional
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


KNOWN_SUSPICIOUS_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon Default TLS Profile",
    "a0e9f5d64349da131239751b7525677e": "Metasploit Meterpreter Reverse HTTPS",
    "51c64c77e60f3980eea0a10352e6097d": "AsyncRAT / QuasarRAT C2 Implant",
    "3b40583800ee314328701d15e8812202": "Sliver C2 Implant Framework",
    "b32309a26951912be7dba376398abc3b": "Mythic C2 Agent Profile",
    "67346d8e9252066e66d17135623401e5": "AgentTesla / Formbook Stealer",
}


def calculate_ja3_fingerprint(tls_info: Dict[str, Any]) -> tuple[str, str]:
    """Calculates JA3 string and MD5 hash from decoded TLS Client Hello fields."""
    ver = tls_info.get("version", 0)
    ciphers = "-".join(str(c) for c in tls_info.get("ciphers", []))
    extensions = "-".join(str(e) for e in tls_info.get("extensions", []))
    groups = "-".join(str(g) for g in tls_info.get("supported_groups", []))
    ec_points = "-".join(str(p) for p in tls_info.get("ec_point_formats", []))

    ja3_str = f"{ver},{ciphers},{extensions},{groups},{ec_points}"
    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    return ja3_str, ja3_hash


def calculate_ja4_fingerprint(tls_info: Dict[str, Any]) -> str:
    """Calculates JA4 TLS Client fingerprint string."""
    proto = "t"  # TCP
    ver = "13" if tls_info.get("version") == 0x0304 else "12"
    sni_flag = "d" if tls_info.get("sni") else "i"
    c_count = f"{min(len(tls_info.get('ciphers', [])), 99):02d}"
    e_count = f"{min(len(tls_info.get('extensions', [])), 99):02d}"
    alpn = "00"

    a_part = f"{proto}{ver}{sni_flag}{c_count}{e_count}{alpn}"

    ciphers_str = ",".join(f"{c:04x}" for c in sorted(tls_info.get("ciphers", [])))
    b_part = hashlib.md5(ciphers_str.encode("utf-8")).hexdigest()[:12]

    exts_str = ",".join(f"{e:04x}" for e in sorted(tls_info.get("extensions", [])))
    c_part = hashlib.md5(exts_str.encode("utf-8")).hexdigest()[:12]

    return f"{a_part}_{b_part}_{c_part}"


class Ja3FingerprintModule(BaseModule):
    """Inspects TLS Client Hello records and alerts on known malicious or anomalous JA3/JA4 fingerprints."""

    def __init__(self):
        super().__init__("ja3_fingerprint")
        self.seen_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        pass

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        # Access decoded TLS info if present
        tls_info = getattr(pkt, "tls_info", None)
        if not tls_info:
            return alerts

        if flow.flow_id in self.seen_flows:
            return alerts
        self.seen_flows.add(flow.flow_id)

        ja3_str, ja3_hash = calculate_ja3_fingerprint(tls_info)
        ja4_fingerprint = calculate_ja4_fingerprint(tls_info)

        malware_match = KNOWN_SUSPICIOUS_JA3.get(ja3_hash)

        if malware_match:
            alert = Alert(
                alert_id=f"ALT-JA3-{abs(hash(ja3_hash)) % 1000000:06d}",
                rule_id="RULE-TLS-JA3-01",
                title=f"Malicious TLS JA3 Fingerprint: {malware_match}",
                description=(
                    f"TLS connection from {pkt.src_ip} matches known threat actor JA3 hash "
                    f"'{ja3_hash}' associated with {malware_match}."
                ),
                severity=Severity.CRITICAL,
                stage=KillChainStage.COMMAND_AND_CONTROL,
                source_ip=pkt.src_ip,
                target_ip=pkt.dst_ip,
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol="TCP/TLS",
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=[pkt],
                arithmetic_proof={
                    "metric": "TLS Client Hello JA3 & JA4 Fingerprinting",
                    "ja3_string": ja3_str,
                    "ja3_hash_md5": ja3_hash,
                    "ja4_fingerprint": ja4_fingerprint,
                    "threat_intel_match": malware_match,
                    "sni_hostname": tls_info.get("sni"),
                },
            )
            alerts.append(alert)

        return alerts

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
