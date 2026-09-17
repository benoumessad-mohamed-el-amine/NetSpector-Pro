"""Structured JSON triage report exporter for NetShark Pro."""

import json
from typing import Any, Dict, List
from netshark.model import Alert


def export_json_report(
    alerts: List[Alert],
    summary_stats: Dict[str, Any],
    correlation_data: Dict[str, Any],
    filepath: str,
) -> bool:
    """Exports forensic triage report as a structured JSON file."""
    report_dict = {
        "metadata": {
            "tool": "NetShark Pro",
            "version": "1.0.0",
            "summary": summary_stats,
        },
        "attack_chain_correlation": correlation_data,
        "alerts": [alert.to_dict() for alert in alerts],
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
        return True
    except Exception as e:
        print(f"Error exporting JSON report to '{filepath}': {e}")
        return False
