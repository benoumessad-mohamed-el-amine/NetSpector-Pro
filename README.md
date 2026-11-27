# NetShark

Offline network-forensics triage for PCAP/PCAPNG captures. Point it at a capture and it streams every packet through twelve detectors (C2 beaconing, DGA domains, DNS tunnelling, lateral movement, scans, cleartext credentials, exfiltration and more). It then stitches the alerts into per-host attack timelines and writes Wireshark-ready evidence files for each finding.

It runs on the Python standard library alone: no `scapy`, no `dpkt`, no `pip install`. That lets it go onto an isolated forensics workstation as a single ~200 KB file.

[![ci](https://github.com/benoumessad-mohamed-el-amine/NetSpector-Pro/actions/workflows/ci.yml/badge.svg)](https://github.com/benoumessad-mohamed-el-amine/NetSpector-Pro/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)

> **Why the design looks the way it does** (the stdlib-only constraint, the streaming memory model, how the beacon statistics were chosen, the threat model for hostile captures) is written up in the **[project wiki](https://github.com/benoumessad-mohamed-el-amine/NetSpector-Pro/wiki)**.

## What it finds

| Detector | Signal | Kill-chain stage |
|---|---|---|
| C2 beaconing | Inter-arrival-time regularity: coefficient of variation ≤ 0.20 **and** MAD/median ≤ 0.25 over ≥ 12 samples | Command & Control |
| DGA domains | Shannon entropy ≥ 3.8 bits/char or ≥ 5-consonant runs, after AD/SRV and cloud-telemetry suppression | Command & Control |
| DNS tunnelling | Per-parent-domain query volume, long subdomains, TXT/NULL/CNAME/MX skew | Exfiltration |
| Exfiltration | Internal → external flows that are upload-heavy (bytes out ≥ 5 MB and out/in ≥ 10×) | Exfiltration |
| Lateral movement | One internal host fanning out to ≥ 15 internal targets on admin ports (SMB, RDP, WinRM, SSH, RPC, Kerberos) | Lateral Movement |
| Subnet sweep / SYN scan | ≥ 10 distinct targets via half-open SYNs or ICMP echo | Reconnaissance |
| TCP flag anomalies | NULL, XMAS, FIN-without-ACK, SYN+FIN | Reconnaissance |
| Cleartext credentials | HTTP Basic, FTP, POP3, SMTP AUTH (passwords masked in output) | Credential Access |
| HTTP audit | Script User-Agents, web-shell paths, `PUT`/`PROPFIND`/`TRACE` | Execution |
| TLS fingerprinting | JA3 / JA4 from the ClientHello, matched against known C2 frameworks | Command & Control |
| SMB / RPC | Named pipes used by remote-exec tooling (`svcctl`, `samr`, `lsarpc`…), `ADMIN$` / `C$` | Lateral Movement |
| File transfer | PE / ELF / ZIP / PDF / RAR / 7z magic bytes on cleartext channels | Execution |

Every alert carries an `arithmetic_proof`: the measured values and the threshold each one was compared against. An analyst can see *why* something fired without reading the source.

## Quick start

```bash
# Run from source
python -m netshark capture.pcap

# Or build the single-file executable
python build.py
./netshark.pyz capture.pcapng --json report.json --stix bundle.json --html report.html

# Carve one PCAPNG evidence file per alert (Wireshark shows the alert in the packet comment)
./netshark.pyz capture.pcap --carve-all

# Local dashboard on http://127.0.0.1:8080 (drag-and-drop more captures into it)
./netshark.pyz capture.pcap --web

# Live capture (Linux, needs CAP_NET_RAW)
sudo ./netshark.pyz -i eth0
```

You can override thresholds with `--rules my_rules.yaml` (see [`netshark/rules/defaults.yaml`](netshark/rules/defaults.yaml)). Any detector can be switched off with `enabled: false`.

## Outputs

- **Terminal summary**: alerts ordered by severity, each with its proof.
- **JSON**: the full report, including per-host kill-chain timelines.
- **STIX 2.1 bundle**: for import into MISP, OpenCTI or a SIEM.
- **HTML**: a self-contained report you can attach to a ticket.
- **Evidence PCAPNGs**: only the packets behind each alert, annotated.

## Layout

```
netshark/
├── capture/     PCAP + PCAPNG streaming readers, live AF_PACKET reader, L2–L7 decoder
├── modules/     the twelve detectors (shared configure / on_packet / on_flow_close / finalize contract)
├── flows.py     bounded LRU flow table, canonical bidirectional 5-tuple keys
├── pipeline.py  the single triage loop used by both the CLI and the dashboard
├── correlate.py per-host kill-chain timelines and plausibility scoring
├── carve.py     evidence extraction to annotated PCAPNG
├── rules/       strict-subset YAML parser + default thresholds
└── report/      text, JSON, STIX 2.1, HTML, history, local dashboard server
```

## Development

```bash
python -m unittest discover -s tests -v   # no dependencies to install, on purpose
```

CI runs the suite on Python 3.11–3.13 on a bare interpreter, which is what enforces the zero-dependency rule. It then builds and smoke-tests the `.pyz`.

## Limits

There is no TCP stream reassembly: payload detectors see one segment at a time. IPv6 extension headers are not walked. The flow table caps active flows, but a single very long flow keeps every packet reference it has seen. The wiki has the full list and the reasoning behind each limit.

## License

MIT
