"""CLI text summary report formatter for NetSpector Pro."""

from typing import Any, Dict, List
from netspector.model import Alert


def render_text_report(alerts: List[Alert], summary_stats: Dict[str, Any], correlation_data: Dict[str, Any]) -> str:
    """Formats forensic triage findings into terminal text report."""
    lines = []
    lines.append("================================================================================")
    lines.append("                         NETSPECTOR PRO FORENSIC SUMMARY                        ")
    lines.append("================================================================================")
    lines.append(f"Total Packets Processed: {summary_stats.get('total_packets', 0):,}")
    lines.append(f"Total Flows Tracked:    {summary_stats.get('total_flows', 0):,}")
    lines.append(f"Total Alerts Triggered: {len(alerts):,}")
    lines.append(f"Analysis Duration:      {summary_stats.get('analysis_duration_sec', 0.0):.2f}s")
    lines.append("--------------------------------------------------------------------------------")
    
    # Severity Count Breakdown
    severity_counts = summary_stats.get("severity_counts", {})
    lines.append("ALERT SEVERITY BREAKDOWN:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        lines.append(f"  - {sev:<10}: {count}")
    lines.append("--------------------------------------------------------------------------------")

    # Correlated Entities & Attack Chains
    entities = correlation_data.get("entities", [])
    lines.append(f"CORRELATED HOST ATTACK CHAINS ({len(entities)} Entities Identified):")
    for ent in entities:
        lines.append(f"  * Host IP: {ent['entity_ip']:<15} | Plausibility Score: {ent['plausibility_score']}%")
        lines.append(f"    Kill Chain Stages: {' -> '.join(ent['stages_covered'])}")
        lines.append(f"    Total Alerts:      {ent['total_alerts']}")
    lines.append("--------------------------------------------------------------------------------")

    # Detailed Alert List
    lines.append("DETAILED DETECTED ALERTS & ARITHMETIC PROOFS:")
    lines.append("")
    for idx, alert in enumerate(alerts, start=1):
        lines.append(f"[{idx}] {alert.alert_id} - {alert.title}")
        lines.append(f"    Severity:    {alert.severity.value} | Stage: {alert.stage.value}")
        lines.append(f"    Flow:        {alert.source_ip}:{alert.source_port} -> {alert.target_ip}:{alert.target_port} ({alert.protocol})")
        lines.append(f"    Description: {alert.description}")
        lines.append("    Arithmetic Proof:")
        for k, v in alert.arithmetic_proof.items():
            lines.append(f"      - {k}: {v}")
        lines.append("")

    lines.append("================================================================================")
    return "\n".join(lines)
