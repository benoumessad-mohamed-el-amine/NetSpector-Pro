"""STIX 2.1 bundle export.

Design notes (see the wiki "Design Decisions" page for the longer version):
- Each alert becomes an Indicator, an Observed Data object, and the SCOs it
  references (addresses + one network-traffic object).
- The Indicator pattern describes the *connection*
  (src AND dst AND port inside one network-traffic observation). The previous
  pattern ANDed two independent address observations, which matches any
  bundle that merely mentions both IPs.
- Indicator -> Observed Data uses "based-on"; "indicates" is only valid
  towards things like malware or attack-pattern.
- IDs are UUIDv5 so re-exporting the same capture yields the same bundle,
  which lets a TIP de-duplicate instead of piling up copies. SCO IDs use the
  STIX-defined namespace, as the spec requires for deterministic SCO IDs.
"""

import ipaddress
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from netshark.model import Alert

STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
NETSHARK_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/benoumessad-mohamed-el-amine/NetSpector-Pro")
PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp"}


def _ts(us: int) -> str:
    return datetime.fromtimestamp(us / 1_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _addr(ip: str) -> Dict[str, Any]:
    try:
        kind = "ipv6-addr" if ipaddress.ip_address(ip).version == 6 else "ipv4-addr"
    except ValueError:
        kind = "ipv4-addr"
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid5(STIX_SCO_NAMESPACE, json.dumps({'value': ip}))}",
        "value": ip,
    }


def _protocols(proto: str) -> List[str]:
    p = (proto or "").lower()
    if p in PROTO_NAMES:
        return [PROTO_NAMES[p]]
    return [part for part in p.replace("/", " ").split() if part] or ["unknown"]


def alert_to_stix(alert: Alert, created: str) -> List[Dict[str, Any]]:
    src, dst = _addr(alert.source_ip), _addr(alert.target_ip)
    traffic = {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": f"network-traffic--{uuid.uuid5(NETSHARK_NAMESPACE, 'nt:' + alert.alert_id)}",
        "src_ref": src["id"],
        "dst_ref": dst["id"],
        "src_port": alert.source_port,
        "dst_port": alert.target_port,
        "protocols": _protocols(alert.protocol),
    }
    seen = _ts(alert.timestamp_us)
    observed = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{uuid.uuid5(NETSHARK_NAMESPACE, 'od:' + alert.alert_id)}",
        "created": created,
        "modified": created,
        "first_observed": seen,
        "last_observed": seen,
        "number_observed": max(len(alert.packet_refs), 1),
        "object_refs": [src["id"], dst["id"], traffic["id"]],
    }
    pattern = (
        f"[network-traffic:src_ref.value = '{alert.source_ip}' AND "
        f"network-traffic:dst_ref.value = '{alert.target_ip}' AND "
        f"network-traffic:dst_port = {int(alert.target_port)}]"
    )
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(NETSHARK_NAMESPACE, 'ind:' + alert.alert_id)}",
        "created": created,
        "modified": created,
        "name": f"NetShark: {alert.title}",
        "description": alert.description,
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": seen,
        "labels": [alert.stage.value, alert.severity.value],
        "kill_chain_phases": [{"kill_chain_name": "netshark", "phase_name": alert.stage.value.lower().replace(" & ", "-").replace(" ", "-")}],
        # STIX 2.1 custom properties are top-level and x_-prefixed.
        "x_netshark_alert_id": alert.alert_id,
        "x_netshark_rule_id": alert.rule_id,
        "x_netshark_proof": alert.arithmetic_proof,
    }
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid5(NETSHARK_NAMESPACE, 'rel:' + alert.alert_id)}",
        "created": created,
        "modified": created,
        "relationship_type": "based-on",
        "source_ref": indicator["id"],
        "target_ref": observed["id"],
    }
    return [src, dst, traffic, observed, indicator, relationship]


def build_stix21_bundle(alerts: List[Alert]) -> Dict[str, Any]:
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    objects: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        for obj in alert_to_stix(alert, created):
            objects.setdefault(obj["id"], obj)  # shared SCOs (same IP) appear once
    ids = sorted(a.alert_id for a in alerts)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(NETSHARK_NAMESPACE, 'bundle:' + ','.join(ids))}",
        "objects": list(objects.values()),
    }


def export_stix21_bundle(alerts: List[Alert], output_path: str) -> bool:
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(build_stix21_bundle(alerts), f, indent=2)
        return True
    except OSError as e:
        print(f"Error exporting STIX 2.1 bundle to '{output_path}': {e}")
        return False
