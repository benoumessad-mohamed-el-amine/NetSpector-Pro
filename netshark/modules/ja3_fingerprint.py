"""JA3 & JA4 TLS Client Hello Fingerprinting Module."""

import hashlib
from typing import Any, Dict, List, Optional
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity, stable_id
from netshark.modules import BaseModule


KNOWN_SUSPICIOUS_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon Default TLS Profile",
    "a0e9f5d64349da131239751b7525677e": "Metasploit Meterpreter Reverse HTTPS",
    "51c64c77e60f3980eea0a10352e6097d": "AsyncRAT / QuasarRAT C2 Implant",
    "3b40583800ee314328701d15e8812202": "Sliver C2 Implant Framework",
    "b32309a26951912be7dba376398abc3b": "Mythic C2 Agent Profile",
    "67346d8e9252066e66d17135623401e5": "AgentTesla / Formbook Stealer",
}


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa).

    Browsers insert random GREASE values into every ClientHello. JA3/JA4 both
    exclude them; leaving them in makes the same client hash differently on
    every connection, so no fingerprint would ever match a known one.
    """
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _no_grease(values):
    return [v for v in values if not is_grease(v)]


def calculate_ja3_fingerprint(tls_info: Dict[str, Any]) -> tuple[str, str]:
    """Calculates JA3 string and MD5 hash from decoded TLS Client Hello fields."""
    ver = tls_info.get("version", 0)
    ciphers = "-".join(str(c) for c in _no_grease(tls_info.get("ciphers", [])))
    extensions = "-".join(str(e) for e in _no_grease(tls_info.get("extensions", [])))
    groups = "-".join(str(g) for g in _no_grease(tls_info.get("supported_groups", [])))
    ec_points = "-".join(str(p) for p in tls_info.get("ec_point_formats", []))

    ja3_str = f"{ver},{ciphers},{extensions},{groups},{ec_points}"
    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    return ja3_str, ja3_hash


def calculate_ja4_fingerprint(tls_info: Dict[str, Any]) -> str:
    """JA4-style client fingerprint.

    Follows the JA4 layout (sorted, GREASE-free, SHA-256/12 hashes) but is not
    byte-identical to FoxIO JA4: the decoder does not yet extract ALPN or
    signature algorithms, so the ALPN field is "00" and the c-part omits them.
    """
    proto = "t"  # TCP
    ver = "13" if tls_info.get("version") == 0x0304 else "12"
    sni_flag = "d" if tls_info.get("sni") else "i"
    c_count = f"{min(len(_no_grease(tls_info.get('ciphers', []))), 99):02d}"
    e_count = f"{min(len(_no_grease(tls_info.get('extensions', []))), 99):02d}"
    alpn = "00"

    a_part = f"{proto}{ver}{sni_flag}{c_count}{e_count}{alpn}"

    ciphers_str = ",".join(f"{c:04x}" for c in sorted(_no_grease(tls_info.get("ciphers", []))))
    b_part = hashlib.sha256(ciphers_str.encode("utf-8")).hexdigest()[:12]

    # JA4 hashes extensions without SNI (0x0000) and ALPN (0x0010); both are
    # already represented in the a-part.
    exts_str = ",".join(f"{e:04x}" for e in sorted(_no_grease(tls_info.get("extensions", []))) if e not in (0x0000, 0x0010))
    c_part = hashlib.sha256(exts_str.encode("utf-8")).hexdigest()[:12]

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
                alert_id=f"ALT-JA3-{stable_id(ja3_hash):06d}",
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
