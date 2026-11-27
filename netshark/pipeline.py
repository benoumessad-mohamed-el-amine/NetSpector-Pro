"""Single triage pipeline shared by the CLI and the web dashboard.

Before this module existed, ``__main__`` and ``report.html_rep`` each carried
their own copy of the packet loop. The copies drifted (the web path saved
history twice and never refreshed the alert list used for carving), so the
loop now lives here and both front-ends call it.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from netshark.capture.pcap import PcapReader
from netshark.capture.pcapng import PCAPNG_MAGIC, PcapngReader
from netshark.correlate import AttackChainStitcher
from netshark.flows import FlowTable
from netshark.model import Alert, PacketRef, Severity
from netshark.modules import (
    BaseModule,
    C2BeaconModule,
    CleartextCredentialsModule,
    DnsEntropyModule,
    DnsTunnelModule,
    ExfiltrationModule,
    FileCarverModule,
    HttpAuditModule,
    Ja3FingerprintModule,
    LateralMovementModule,
    SmbAuditModule,
    SubnetSweepModule,
    TcpStateModule,
)
from netshark.rules.yamlsub import load_yaml_file

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "defaults.yaml")


# Module name -> section in the rules file, where they differ.
RULES_KEY = {"c2_beacon": "beacon", "dns_entropy": "entropy"}


def build_modules(rules: Dict[str, Any]) -> List[BaseModule]:
    """Instantiates and configures every detection module."""
    modules: List[BaseModule] = [
        C2BeaconModule(),
        CleartextCredentialsModule(),
        LateralMovementModule(),
        ExfiltrationModule(),
        DnsEntropyModule(),
        SubnetSweepModule(),
        HttpAuditModule(),
        Ja3FingerprintModule(),
        TcpStateModule(),
        FileCarverModule(),
        SmbAuditModule(),
        DnsTunnelModule(),
    ]
    # `enabled: false` in the rules file was documented but ignored by most
    # modules; enforce it once here instead of in twelve places.
    active = [m for m in modules if rules.get(RULES_KEY.get(m.name, m.name), {}).get("enabled", True) is not False]
    for m in active:
        m.configure(rules)
    return active


def load_rules(path: Optional[str] = None) -> Dict[str, Any]:
    """Loads a rules file, falling back to the bundled defaults."""
    target = path or DEFAULT_RULES_PATH
    if path and not os.path.isfile(path):
        raise FileNotFoundError(f"Rules file '{path}' not found.")
    return load_yaml_file(target) if os.path.isfile(target) else {}


def open_capture(filepath: str):
    """Returns the right reader for a capture file, detected by magic bytes."""
    with open(filepath, "rb") as f:
        magic = f.read(4)
    if magic == PCAPNG_MAGIC:
        return PcapngReader(filepath)
    return PcapReader(filepath)


@dataclass
class TriageResult:
    alerts: List[Alert]
    summary: Dict[str, Any]
    correlation: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

    def to_dict(self, tool_version: Optional[str] = None) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {"summary": self.summary}
        if tool_version:
            metadata.update({"tool": "NetShark", "version": tool_version})
        return {
            "metadata": metadata,
            "attack_chain_correlation": self.correlation,
            "alerts": [a.to_dict() for a in self.alerts],
        }


def run_triage(
    packets: Iterable[PacketRef],
    rules: Optional[Dict[str, Any]] = None,
    capacity: int = 200_000,
) -> TriageResult:
    """Streams packets through the flow table and every module, then correlates."""
    modules = build_modules(rules if rules is not None else load_rules())
    flow_table = FlowTable(max_capacity=capacity)
    collected: List[Alert] = []
    errors: List[str] = []

    def on_close(flow):
        for m in modules:
            collected.extend(m.on_flow_close(flow) or [])

    flow_table.register_evict_callback(on_close)

    start = time.time()
    total_packets = 0
    try:
        for pkt in packets:
            total_packets += 1
            flow = flow_table.touch_or_create(pkt)
            for m in modules:
                collected.extend(m.on_packet(pkt, flow) or [])
            # Payload bytes are only needed during on_packet. Dropping them here
            # keeps memory proportional to packet *metadata*, not capture size;
            # carving re-reads bytes from disk via file_offset.
            pkt._raw_payload = None
    except KeyboardInterrupt:
        errors.append("Interrupted by user; results cover packets processed so far.")
    except (ValueError, OSError) as e:
        errors.append(f"Capture read stopped early: {e}")

    flow_table.flush_all()
    for m in modules:
        collected.extend(m.finalize() or [])

    # Alert IDs are deterministic per finding (see model.stable_id), so this
    # collapses repeat detections of the same thing into one alert.
    unique: Dict[str, Alert] = {}
    for a in collected:
        unique[a.alert_id] = a
    alerts = list(unique.values())

    correlation = AttackChainStitcher(alerts).correlate()
    summary = {
        "total_packets": total_packets,
        "total_flows": flow_table.total_flows,
        "analysis_duration_sec": round(time.time() - start, 4),
        "severity_counts": {s.value: sum(1 for a in alerts if a.severity == s) for s in Severity},
    }
    return TriageResult(alerts=alerts, summary=summary, correlation=correlation, errors=errors)


def triage_file(filepath: str, rules: Optional[Dict[str, Any]] = None, capacity: int = 200_000) -> TriageResult:
    with open_capture(filepath) as reader:
        return run_triage(reader.packets(), rules=rules, capacity=capacity)
