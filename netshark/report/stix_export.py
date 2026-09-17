"""STIX 2.1 Threat Intelligence JSON Bundle exporter for NetSpector Pro."""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from netshark.model import Alert


def export_stix21_bundle(alerts: List[Alert], output_path: str) -> bool:
    """Exports triage alerts as a STIX 2.1 JSON Bundle for SIEM / SOAR / MISP integration."""
    stix_objects = []

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    for alert in alerts:
        indicator_id = f"indicator--{uuid.uuid4()}"
        observed_id = f"observed-data--{uuid.uuid4()}"

        # 1. STIX 2.1 Indicator SDO
        indicator_sdo = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"NetSpector: {alert.title}",
            "description": alert.description,
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{alert.source_ip}'] AND [ipv4-addr:value = '{alert.target_ip}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "labels": [alert.stage.value, alert.severity.value],
            "custom_properties": {
                "x_netshark_rule_id": alert.rule_id,
                "x_netshark_proof": alert.arithmetic_proof,
            },
        }
        stix_objects.append(indicator_sdo)

        # 2. STIX 2.1 Observed Data SDO
        obs_time = datetime.fromtimestamp(alert.timestamp_us / 1_000_000.0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        observed_sdo = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now_iso,
            "modified": now_iso,
            "first_observed": obs_time,
            "last_observed": obs_time,
            "number_observed": len(alert.packet_refs) or 1,
            "objects": {
                "0": {
                    "type": "ipv4-addr",
                    "value": alert.source_ip,
                },
                "1": {
                    "type": "ipv4-addr",
                    "value": alert.target_ip,
                },
                "2": {
                    "type": "network-traffic",
                    "src_ref": "0",
                    "dst_ref": "1",
                    "src_port": alert.source_port,
                    "dst_port": alert.target_port,
                    "protocols": [alert.protocol.lower()],
                },
            },
        }
        stix_objects.append(observed_sdo)

        # 3. STIX 2.1 Relationship SDO
        rel_sdo = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": observed_id,
        }
        stix_objects.append(rel_sdo)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": stix_objects,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        return True
    except Exception as e:
        print(f"Error exporting STIX 2.1 bundle to '{output_path}': {e}")
        return False
