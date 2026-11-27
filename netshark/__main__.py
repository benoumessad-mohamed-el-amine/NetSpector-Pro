"""NetShark CLI entry point."""

import argparse
import os
import sys

from netshark import __version__
from netshark.capture.live import LiveSocketReader
from netshark.carve import PcapCarver
from netshark.pipeline import load_rules, open_capture, run_triage
from netshark.report import HistoryManager, export_json_report, render_static_html, render_text_report, start_web_dashboard
from netshark.report.stix_export import export_stix21_bundle
from netshark.rules.yamlsub import YAMLParseError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netshark",
        description="NetShark - offline PCAP/PCAPNG forensic triage engine",
    )
    parser.add_argument("pcap_file", nargs="?", help="Path to input PCAP or PCAPNG capture file", default=None)
    parser.add_argument("-i", "--interface", help="Live network interface to sniff (Linux only, needs CAP_NET_RAW)", default=None)
    parser.add_argument("--rules", help="Path to custom YAML rules file", default=None)
    parser.add_argument("--capacity", help="Flow table max LRU capacity", type=int, default=200000)
    parser.add_argument("--json", help="Export structured JSON triage report to specified path", default=None)
    parser.add_argument("--stix", help="Export STIX 2.1 bundle to specified path", default=None)
    parser.add_argument("--html", help="Write static HTML report to specified path", default=None)
    parser.add_argument("--web", help="Launch interactive local web dashboard", action="store_true")
    parser.add_argument("--port", help="Web server port (default 8080)", type=int, default=8080)
    parser.add_argument("--carve-all", help="Carve a PCAPNG evidence file for every alert", action="store_true")
    parser.add_argument("--no-history", help="Do not archive this run in ./netshark_history", action="store_true")
    parser.add_argument("--version", action="version", version=f"NetShark v{__version__}")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.pcap_file and not args.interface and not args.web:
        parser.print_help()
        sys.exit(1)

    if args.pcap_file and not os.path.isfile(args.pcap_file):
        print(f"Error: Input PCAP file '{args.pcap_file}' does not exist.")
        sys.exit(1)

    try:
        rules = load_rules(args.rules)
    except (FileNotFoundError, YAMLParseError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"[*] NetShark v{__version__} starting forensic analysis...")

    if args.interface:
        print(f"[*] Live capture on interface '{args.interface}' (Ctrl+C to stop)")
        with LiveSocketReader(interface=args.interface) as reader:
            result = run_triage(reader.packets(), rules=rules, capacity=args.capacity)
    elif args.pcap_file:
        print(f"[*] File processing mode: '{args.pcap_file}'")
        with open_capture(args.pcap_file) as reader:
            result = run_triage(reader.packets(), rules=rules, capacity=args.capacity)
    else:
        print("[*] Standalone web dashboard mode.")
        result = run_triage([], rules=rules)

    for err in result.errors:
        print(f"[!] {err}")

    print("\n" + render_text_report(result.alerts, result.summary, result.correlation))

    if (args.pcap_file or args.interface) and not args.no_history:
        meta = HistoryManager().save_profile(args.pcap_file or args.interface, result.to_dict(__version__))
        print(f"[+] Triage session profile archived: '{meta['profile_id']}'")

    if args.json:
        export_json_report(result.alerts, result.summary, result.correlation, args.json)
        print(f"[+] JSON report exported to '{args.json}'")

    if args.stix:
        export_stix21_bundle(result.alerts, args.stix)
        print(f"[+] STIX 2.1 bundle exported to '{args.stix}'")

    if args.html:
        render_static_html(result.alerts, result.summary, result.correlation, args.html)
        print(f"[+] Static HTML report written to '{args.html}'")

    if args.carve_all and args.pcap_file:
        carver = PcapCarver(args.pcap_file)
        carved = sum(1 for a in result.alerts if carver.carve_alert(a, f"evidence_{a.alert_id}.pcapng"))
        print(f"[+] Carved evidence files for {carved} alerts.")

    if args.web:
        start_web_dashboard(result.alerts, result.summary, result.correlation, args.pcap_file or "", port=args.port)


if __name__ == "__main__":
    main()
