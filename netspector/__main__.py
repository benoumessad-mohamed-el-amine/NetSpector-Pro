"""NetSpector Pro CLI Entry Point and Orchestration Engine."""

import argparse
import os
import sys
import time
from typing import List

from netspector import __version__
from netspector.capture.pcap import PcapReader
from netspector.capture.pcapng import PcapngReader
from netspector.carve import PcapCarver
from netspector.correlate import AttackChainStitcher
from netspector.flows import FlowTable
from netspector.model import Alert, Severity
from netspector.modules.beacon import C2BeaconModule
from netspector.modules.entropy import DnsEntropyModule
from netspector.modules.lateral import LateralMovementModule
from netspector.modules.tcpstate import TcpStateModule
from netspector.report import export_json_report, render_static_html, render_text_report, start_web_dashboard
from netspector.rules.yamlsub import load_yaml_file


def create_pcap_reader(filepath: str):
    """Auto-detects whether file is classic PCAP or PCAPNG based on header magic bytes."""
    with open(filepath, "rb") as f:
        magic = f.read(4)

    if magic in (b"\x0a\x0d\x0d\x0a", b"\x0a\x0d\x0d\x0a"):
        return PcapngReader(filepath)
    else:
        return PcapReader(filepath)


def main():
    parser = argparse.ArgumentParser(
        prog="netspector",
        description="NetSpector Pro - Offline Automated Forensic PCAP & Network Triage Tool",
    )

    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG binary capture file")
    parser.add_argument("--rules", help="Path to custom YAML rules file", default=None)
    parser.add_argument("--capacity", help="Flow table max LRU capacity", type=int, default=200000)
    parser.add_argument("--json", help="Export structured JSON triage report to specified path", default=None)
    parser.add_argument("--html", help="Dump static HTML report to specified path", default=None)
    parser.add_argument("--web", help="Launch interactive local web dashboard", action="store_true")
    parser.add_argument("--port", help="Web server port (default 8080)", type=int, default=8080)
    parser.add_argument("--carve-all", help="Automatically carve evidence PCAP files for all alerts", action="store_true")
    parser.add_argument("--version", action="version", version=f"NetSpector Pro v{__version__}")

    args = parser.parse_args()

    if not os.path.isfile(args.pcap_file):
        print(f"Error: Input PCAP file '{args.pcap_file}' does not exist.")
        sys.exit(1)

    # 1. Load Rules Configuration
    rules_cfg = {}
    if args.rules:
        if os.path.isfile(args.rules):
            rules_cfg = load_yaml_file(args.rules)
        else:
            print(f"Error: Rules file '{args.rules}' not found.")
            sys.exit(1)
    else:
        # Load bundled defaults.yaml
        pkg_dir = os.path.dirname(__file__)
        default_yaml_path = os.path.join(pkg_dir, "rules", "defaults.yaml")
        if os.path.isfile(default_yaml_path):
            rules_cfg = load_yaml_file(default_yaml_path)

    # 2. Initialize Core Engine & Modules
    flow_table = FlowTable(max_capacity=args.capacity)

    modules = [
        C2BeaconModule(),
        DnsEntropyModule(),
        TcpStateModule(),
        LateralMovementModule(),
    ]

    for m in modules:
        m.configure(rules_cfg)

    # Callback when flows are closed or evicted from LRU
    def handle_flow_close(closed_flow):
        for m in modules:
            alerts = m.on_flow_close(closed_flow)
            if alerts:
                collected_alerts.extend(alerts)

    flow_table.register_evict_callback(handle_flow_close)

    # 3. Stream Process PCAP Packets
    print(f"[*] NetSpector Pro v{__version__} starting forensic analysis...")
    print(f"[*] Input File: '{args.pcap_file}'")
    start_time = time.time()

    reader = create_pcap_reader(args.pcap_file)
    total_packets = 0
    collected_alerts: List[Alert] = []

    try:
        with reader as pcap_stream:
            for pkt in pcap_stream.packets():
                total_packets += 1
                flow = flow_table.touch_or_create(pkt)

                for m in modules:
                    pkt_alerts = m.on_packet(pkt, flow)
                    if pkt_alerts:
                        collected_alerts.extend(pkt_alerts)

    except Exception as e:
        print(f"Error during packet parsing: {e}")

    # 4. Finalize Flow Engine & Modules
    flow_table.flush_all()

    for m in modules:
        fin_alerts = m.finalize()
        if fin_alerts:
            collected_alerts.extend(fin_alerts)

    analysis_duration = time.time() - start_time

    # Deduplicate alerts by alert_id
    unique_alerts_map = {}
    for a in collected_alerts:
        unique_alerts_map[a.alert_id] = a
    all_alerts = list(unique_alerts_map.values())

    # 5. Correlate Attack Chains
    stitcher = AttackChainStitcher(all_alerts)
    correlation_data = stitcher.correlate()

    # Calculate Severity Counts
    sev_counts = {
        "CRITICAL": sum(1 for a in all_alerts if a.severity == Severity.CRITICAL),
        "HIGH": sum(1 for a in all_alerts if a.severity == Severity.HIGH),
        "MEDIUM": sum(1 for a in all_alerts if a.severity == Severity.MEDIUM),
        "LOW": sum(1 for a in all_alerts if a.severity == Severity.LOW),
        "INFO": sum(1 for a in all_alerts if a.severity == Severity.INFO),
    }

    summary_stats = {
        "total_packets": total_packets,
        "total_flows": len(flow_table.closed_flows) + len(flow_table),
        "analysis_duration_sec": round(analysis_duration, 4),
        "severity_counts": sev_counts,
    }

    # 6. Render Terminal Report
    text_report = render_text_report(all_alerts, summary_stats, correlation_data)
    print("\n" + text_report)

    # 7. Optional JSON Export
    if args.json:
        export_json_report(all_alerts, summary_stats, correlation_data, args.json)
        print(f"[+] JSON report exported to '{args.json}'")

    # 8. Optional Static HTML Export
    if args.html:
        render_static_html(all_alerts, summary_stats, correlation_data, args.html)
        print(f"[+] Static HTML report written to '{args.html}'")

    # 9. Optional Carve All Alerts
    if args.carve_all:
        carver = PcapCarver(args.pcap_file)
        carve_count = 0
        for alert in all_alerts:
            out_pcap = f"evidence_{alert.alert_id}.pcap"
            if carver.carve_alert(alert, out_pcap):
                carve_count += 1
        print(f"[+] Carved evidence files for {carve_count} alerts.")

    # 10. Optional Web Dashboard Server
    if args.web:
        start_web_dashboard(all_alerts, summary_stats, correlation_data, args.pcap_file, port=args.port)


if __name__ == "__main__":
    main()
