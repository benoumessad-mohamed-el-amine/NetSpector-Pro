"""CLI text summary report formatter with ASCII shark logo and rich formatting for NetShark."""

import sys
from typing import Any, Dict, List
from netshark.model import Alert

ASCII_LOGO_TEXT = r"""
        ,-.
       / \ \      _.__
      /   \ \  .-'    `-.
     / / \ \ \/  .---.   \
    / /   \ \   /     \   \       _  _ ___ _____ ___ _  _    _   ___ _  __
   / /     \ \ /       \   \     | \| | __|_   _/ __| || |  /_\ | _ \ |/ /
  / /       \ \         \   \    | .` | _|  | | \__ \ __ | / _ \|   / ' < 
 ( (         ) )         )   )   |_|\_|___| |_| |___/_||_|/_/ \_\_|_\_|\_\
  \ \       / /         /   /
   \ \     / /    .-.  /   /               FORENSIC PCAP TRIAGE ENGINE
    \ `---' /    /   `----'
     `-----'    '
"""


def _use_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def render_text_report(alerts: List[Alert], summary_stats: Dict[str, Any], correlation_data: Dict[str, Any]) -> str:
    """Formats forensic triage findings into terminal text report with ASCII logo and styled boxes."""
    use_clr = _use_color()

    CYAN = "\033[96m" if use_clr else ""
    BOLD = "\033[1m" if use_clr else ""
    RESET = "\033[0m" if use_clr else ""
    GREEN = "\033[92m" if use_clr else ""
    YELLOW = "\033[93m" if use_clr else ""
    RED = "\033[91m" if use_clr else ""
    BLUE = "\033[94m" if use_clr else ""
    GRAY = "\033[90m" if use_clr else ""
    MAGENTA = "\033[95m" if use_clr else ""

    lines = []
    
    # ASCII Art Logo Header
    lines.append(CYAN + BOLD + ASCII_LOGO_TEXT + RESET)

    # Box Header
    lines.append(CYAN + "╭──────────────────────────────────────────────────────────────────────────────╮" + RESET)
    lines.append(CYAN + f"│                       {BOLD}NETSHARK FORENSIC SUMMARY{RESET}{CYAN}                              │" + RESET)
    lines.append(CYAN + "├──────────────────────────────────────────────────────────────────────────────┤" + RESET)
    
    total_pkts = summary_stats.get('total_packets', 0)
    total_flows = summary_stats.get('total_flows', 0)
    total_alerts = len(alerts)
    duration = summary_stats.get('analysis_duration_sec', 0.0)

    lines.append(f"│  {BOLD}Packets Processed:{RESET} {total_pkts:<12,} │ {BOLD}Flows Tracked:{RESET} {total_flows:<14,} │")
    lines.append(f"│  {BOLD}Alerts Triggered:{RESET}  {total_alerts:<12,} │ {BOLD}Duration:{RESET}      {duration:<14.2f}s │")
    lines.append(CYAN + "├──────────────────────────────────────────────────────────────────────────────┤" + RESET)

    # Severity Breakdown
    severity_counts = summary_stats.get("severity_counts", {})
    sev_str_parts = []
    sev_colors = {
        "CRITICAL": RED + BOLD,
        "HIGH": YELLOW + BOLD,
        "MEDIUM": MAGENTA,
        "LOW": BLUE,
        "INFO": GRAY,
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = severity_counts.get(sev, 0)
        clr = sev_colors.get(sev, "")
        sev_str_parts.append(f"{clr}{sev}:{RESET} {cnt}")

    lines.append(f"│  {BOLD}Severities:{RESET} " + " | ".join(sev_str_parts))
    lines.append(CYAN + "╰──────────────────────────────────────────────────────────────────────────────╯" + RESET)
    lines.append("")

    # Correlated Entities & Attack Chains
    entities = correlation_data.get("entities", [])
    if entities:
        lines.append(GREEN + BOLD + f"── [ Correlated Host Attack Chains ({len(entities)} Identified) ] ──" + RESET)
        for ent in entities:
            stages_joined = " -> ".join(ent['stages_covered'])
            lines.append(f"  • {BOLD}Host IP:{RESET} {GREEN}{ent['entity_ip']:<15}{RESET} │ {BOLD}Plausibility:{RESET} {YELLOW}{ent['plausibility_score']}%{RESET} │ {BOLD}Alerts:{RESET} {ent['total_alerts']}")
            lines.append(f"    {GRAY}Stages:{RESET} {stages_joined}")
        lines.append("")

    # Detailed Alert List
    if alerts:
        lines.append(CYAN + BOLD + f"── [ Detailed Alert Findings & Arithmetic Proofs ({len(alerts)}) ] ──" + RESET)
        lines.append("")
        for idx, alert in enumerate(alerts, start=1):
            sev_name = alert.severity.value
            sev_clr = sev_colors.get(sev_name, "")
            
            lines.append(f"{BOLD}[{idx}]{RESET} {sev_clr}{alert.alert_id}{RESET} ── {BOLD}{alert.title}{RESET}")
            lines.append(f"    {GRAY}Severity:{RESET} {sev_clr}{sev_name}{RESET} │ {GRAY}Kill Chain Stage:{RESET} {alert.stage.value}")
            lines.append(f"    {GRAY}Flow:{RESET} {alert.source_ip}:{alert.source_port} -> {alert.target_ip}:{alert.target_port} ({alert.protocol})")
            lines.append(f"    {GRAY}Description:{RESET} {alert.description}")
            if alert.arithmetic_proof:
                lines.append(f"    {GRAY}Arithmetic Proof:{RESET}")
                for k, v in alert.arithmetic_proof.items():
                    lines.append(f"      - {k}: {v}")
            lines.append("")

    lines.append(CYAN + "════════════════════════════════════════════════════════════════════════════════" + RESET)
    return "\n".join(lines)
