"""NetSpector Pro CLI Entry Point and Orchestration Engine."""

import argparse
import os
import sys
import time
from typing import List

from netspector import __version__
from netspector.capture.live import LiveSocketReader
from netspector.capture.pcap import PcapReader
from netspector.capture.pcapng import PcapngReader
from netspector.carve import PcapCarver
from netspector.correlate import AttackChainStitcher
from netspector.flows import FlowTable
from netspector.model import Alert, Severity
from netspector.modules.beacon import C2BeaconModule
from netspector.modules.credentials import CleartextCredentialsModule
from netspector.modules.entropy import DnsEntropyModule
from netspector.modules.exfil import ExfiltrationModule
from netspector.modules.http_audit import HttpAuditModule
from netspector.modules.ja3_fingerprint import Ja3FingerprintModule
from netspector.modules.lateral import LateralMovementModule
from netspector.modules.sweep import SubnetSweepModule
from netspector.modules.tcpstate import TcpStateModule
from netspector.report import export_json_report, render_static_html, render_text_report, start_web_dashboard
from netspector.report.stix_export import export_stix21_bundle
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
        description="NetSpector Pro - Offline Automated Forensic PCAP & Network Triage Engine",
    )

    parser.add_argument("pcap_file", nargs="?", help="Path to input PCAP or PCAPNG binary capture file", default=None)
    parser.add_argument("-i", "--interface", help="Live network interface to sniff (e.g. eth0, wlan0)", default=None)
    parser.add_argument("--rules", help="Path to custom YAML rules file", default=None)
    parser.add_argument("--capacity", help="Flow table max LRU capacity", type=int, default=200000)
    parser.add_argument("--json", help="Export structured JSON triage report to specified path", default=None)
    parser.add_argument("--stix", help="Export STIX 2.1 Threat Intel JSON Bundle to specified path", default=None)
    parser.add_argument("--html", help="Dump static HTML report to specified path", default=None)
    parser.add_argument("--web", help="Launch interactive local web dashboard", action="store_true")
    parser.add_argument("--port", help="Web server port (default 8080)", type=int, default=8080)
    parser.add_argument("--carve-all", help="Automatically carve evidence PCAP files for all alerts", action="store_true")
    parser.add_argument("--version", action="version", version=f"NetSpector Pro v{__version__}")

    args = parser.parse_args()

    if not args.pcap_file and not args.interface and not args.web:
        parser.print_help()
        sys.exit(1)

    if args.pcap_file and not os.path.isfile(args.pcap_file):
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
        pkg_dir = os.path.dirname(__file__)
        default_yaml_path = os.path.join(pkg_dir, "rules", "defaults.yaml")
        if os.path.isfile(default_yaml_path):
            rules_cfg = load_yaml_file(default_yaml_path)

    # 2. Initialize Core LRU Flow Engine & Detection Modules
    flow_table = FlowTable(max_capacity=args.capacity)

    modules = [
        C2BeaconModule(),
        CleartextCredentialsModule(),
        LateralMovementModule(),
        ExfiltrationModule(),
        DnsEntropyModule(),
        SubnetSweepModule(),
        HttpAuditModule(),
        Ja3FingerprintModule(),
        TcpStateModule(),
    ]

    for m in modules:
        m.configure(rules_cfg)

    def handle_flow_close(closed_flow):
        for m in modules:
            alerts = m.on_flow_close(closed_flow)
            if alerts:
                collected_alerts.extend(alerts)

    flow_table.register_evict_callback(handle_flow_close)

    # 3. Stream Process Packets (Live, PCAP File, or Standalone Web UI)
    print(f"[*] NetSpector Pro v{__version__} starting forensic analysis...")
    start_time = time.time()

    total_packets = 0
    collected_alerts: List[Alert] = []

    if args.interface:
        print(f"[*] Live Socket Sniffing Mode on Interface: '{args.interface}'")
        reader = LiveSocketReader(interface=args.interface)
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
            print(f"Error during packet processing: {e}")

    elif args.pcap_file:
        print(f"[*] File Processing Mode: '{args.pcap_file}'")
        reader = create_pcap_reader(args.pcap_file)
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
            print(f"Error during packet processing: {e}")

    elif args.web:
        print("[*] Standalone Web Dashboard Mode Ready.")

    # 4. Finalize Flow Engine & Modules
    flow_table.flush_all()

    for m in modules:
        fin_alerts = m.finalize()
        if fin_alerts:
            collected_alerts.extend(fin_alerts)

    analysis_duration = time.time() - start_time

    unique_alerts_map = {}
    for a in collected_alerts:
        unique_alerts_map[a.alert_id] = a
    all_alerts = list(unique_alerts_map.values())

    # 5. Correlate Attack Chains
    stitcher = AttackChainStitcher(all_alerts)
    correlation_data = stitcher.correlate()

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

    # 7. Exports & Output Options
    if args.json:
        export_json_report(all_alerts, summary_stats, correlation_data, args.json)
        print(f"[+] JSON report exported to '{args.json}'")

    if args.stix:
        export_stix21_bundle(all_alerts, args.stix)
        print(f"[+] STIX 2.1 Threat Intel Bundle exported to '{args.stix}'")

    if args.html:
        render_static_html(all_alerts, summary_stats, correlation_data, args.html)
        print(f"[+] Static HTML report written to '{args.html}'")

    if args.carve_all and args.pcap_file:
        carver = PcapCarver(args.pcap_file)
        carve_count = 0
        for alert in all_alerts:
            out_pcap = f"evidence_{alert.alert_id}.pcap"
            if carver.carve_alert(alert, out_pcap):
                carve_count += 1
        print(f"[+] Carved evidence files for {carve_count} alerts.")

    if args.web:
        source_path = args.pcap_file or args.interface or ""
        start_web_dashboard(all_alerts, summary_stats, correlation_data, source_path, port=args.port)


if __name__ == "__main__":
    main()
