"""Module 6: Shannon Entropy & DGA Domain Detection with Active Directory Noise Filtering."""

import math
from typing import Any, Dict, List, Tuple
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


# Active Directory & Enterprise Infrastructure Noise Whitelist Patterns
# Suppresses false positives on standard Windows SRV records (_ldap._tcp, _kerberos._tcp, _msdcs, etc.)
AD_NOISE_PREFIXES = (
    "_ldap.", "_kerberos.", "_kpasswd.", "_gc.", "_msdcs.",
    "_sites.", "_tcp.", "_udp.", "_vlmcs.", "_autodiscover.",
    "_domainkey.", "_sip.", "_turn.", "_stun."
)

AD_NOISE_SUBSTRINGS = (
    "._msdcs.", "._sites.", "._tcp.", "._udp.",
    "in-addr.arpa", "ip6.arpa", "wpad.", "isatap."
)

TELEMETRY_DOMAINS = (
    ".microsoft.com", ".msftncsi.com", ".windowsupdate.com", "clients6.google.com",
    ".googleapis.com", "mshome.net", ".local", ".trafficmanager.net", ".azure.com",
    ".amazonaws.com", ".cloudfront.net", ".akamaihd.net", ".live.com"
)


def is_ad_enterprise_noise(qname: str) -> bool:
    """Returns True if DNS QNAME matches Active Directory SRV or enterprise infrastructure/telemetry patterns."""
    q_lower = qname.lower()
    if any(q_lower.startswith(prefix) for prefix in AD_NOISE_PREFIXES):
        return True
    if any(sub in q_lower for sub in AD_NOISE_SUBSTRINGS):
        return True
    if any(q_lower.endswith(td) or q_lower == td.lstrip(".") for td in TELEMETRY_DOMAINS):
        return True
    return False


def calculate_shannon_entropy(text: str) -> Tuple[float, Dict[str, float]]:
    """Calculates Shannon Entropy H(S) = -sum(P(c) * log2(P(c))) for a string."""
    if not text:
        return 0.0, {}

    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    probabilities: Dict[str, float] = {}
    for char, count in char_counts.items():
        p = count / length
        probabilities[char] = round(p, 4)
        entropy -= p * math.log2(p)

    return round(entropy, 4), probabilities


def max_consonant_run(text: str) -> int:
    """Finds the maximum number of consecutive consonants in a text label."""
    vowels = set("aeiouAEIOU")
    max_run = 0
    current_run = 0
    for char in text:
        if char.isalpha() and char not in vowels:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0
    return max_run


def extract_subdomain_parts(qname: str) -> Tuple[str, str]:
    """Splits a FQDN into subdomain label and registered parent domain."""
    parts = qname.strip(".").split(".")
    if len(parts) <= 2:
        return parts[0] if parts else "", qname

    subdomain = ".".join(parts[:-2])
    parent_domain = ".".join(parts[-2:])
    return subdomain, parent_domain


class DnsEntropyModule(BaseModule):
    """Detects Domain Generation Algorithm (DGA) domains and DNS tunneling via high Shannon entropy."""

    def __init__(self):
        super().__init__("dns_entropy")
        self.entropy_threshold: float = 3.8
        self.consonant_cluster_len: int = 5
        self.min_subdomain_len: int = 8
        self.seen_domains: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("entropy", {})
        self.entropy_threshold = cfg.get("entropy_threshold", 3.8)
        self.consonant_cluster_len = cfg.get("consonant_cluster_len", 5)
        self.min_subdomain_len = cfg.get("min_subdomain_len", 8)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        if not pkt.dns_qname:
            return []

        qname = pkt.dns_qname.lower()
        if qname in self.seen_domains:
            return []

        # Mandatory Whitelist Filtering: Filter Active Directory & Enterprise Infrastructure Noise FIRST
        if is_ad_enterprise_noise(qname):
            return []

        subdomain, parent_domain = extract_subdomain_parts(qname)
        if len(subdomain) < self.min_subdomain_len:
            return []

        entropy, probs = calculate_shannon_entropy(subdomain)
        consonant_run = max_consonant_run(subdomain)

        # Flag if entropy exceeds threshold or consonant run indicates artificial randomness
        if entropy >= self.entropy_threshold or consonant_run >= self.consonant_cluster_len:
            self.seen_domains.add(qname)

            alert = Alert(
                alert_id=f"ALT-DGA-{abs(hash(qname)) % 1000000:06d}",
                rule_id="RULE-DNS-DGA-01",
                title="High Shannon Entropy / DGA Domain Query Detected",
                description=(
                    f"DNS query '{qname}' exhibits randomized subdomain entropy ({entropy:.2f} bits/char) "
                    f"typical of Domain Generation Algorithms (DGA) or DNS tunneling."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.COMMAND_AND_CONTROL,
                source_ip=pkt.src_ip,
                target_ip=pkt.dst_ip,
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol="UDP/DNS",
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=[pkt],
                arithmetic_proof={
                    "metric": "Shannon Entropy H(S) & Character Anomaly",
                    "dns_qname": qname,
                    "subdomain_analyzed": subdomain,
                    "parent_domain": parent_domain,
                    "subdomain_length": len(subdomain),
                    "min_subdomain_len_threshold": self.min_subdomain_len,
                    "shannon_entropy_calculated": entropy,
                    "entropy_threshold": self.entropy_threshold,
                    "consonant_cluster_run": consonant_run,
                    "consonant_cluster_threshold": self.consonant_cluster_len,
                    "char_probabilities": probs,
                    "formula": "H(S) = -sum(P(c) * log2(P(c)))",
                    "ad_noise_filter_passed": True,
                },
            )
            return [alert]

        return []

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
