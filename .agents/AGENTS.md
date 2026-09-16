# NetSpector Pro - Master Architectural Session & Codebase Cache

## Project Summary
**NetSpector Pro** is an offline, client-side automated PCAP and network-log forensic triage tool built for high-precision forensic analysis. It runs on Python 3.11+ with **zero external dependencies** (strictly standard library), bounded memory usage, low false positives, and transparent arithmetic proofs for every alert.

## Core Architectural Rules & Constraints
1. **Zero External Dependencies:**
   - Standard library ONLY (`struct`, `socket`, `math`, `collections`, `http.server`, `zipapp`, `unittest`, `hashlib`, `base64`, `re`).
   - No `pip` packages (`scapy`, `dpkt`, `PyYAML`, etc.).
2. **Binary PCAP/PCAPNG Stream Readers & Live Socket Sniffer:**
   - Stream-based parsing via `netspector/capture/pcap.py` and `netspector/capture/pcapng.py`.
   - Live socket sniffer via `netspector/capture/live.py` (`socket.AF_PACKET`, `socket.SOCK_RAW`).
   - Lightweight `PacketRef` (`__slots__`) storing packet metadata (`ts_us`, `file_offset`, `caplen`, `wirelen`, `flow_id`, `flags`, `tls_info`, `_raw_payload`) without buffering payload bytes in RAM.
3. **Canonical 5-Tuple LRU Flow Engine:**
   - `netspector/flows.py`: `FlowTable` max capacity 200,000.
   - Flow key format: `proto:min(ip1,port1)<->max(ip2,port2)` (bidirectional mapping).
4. **Strict-Subset YAML Parser:**
   - `netspector/rules/yamlsub.py`: Hand-rolled YAML parser with line-numbered error diagnostics (`YAMLParseError`).
5. **The 10 Automated Forensic Triage Engines (`netspector/modules/`):**
   - Contract: `configure(rules)`, `on_packet(pkt, flow)`, `on_flow_close(flow)`, `finalize()`.
   - **Engine 1 (`flows.py`):** TCP Session Reassembly & Flow Indexing.
   - **Engine 2 (`beacon.py`):** C2 Beaconing & Jitter Analyzer ($CoV = \sigma / \mu \le 0.20$, $MAD / M \le 0.25$, $N \ge 12$).
   - **Engine 3 (`credentials.py`):** Cleartext Credential Sniffer (HTTP Basic Auth, FTP, Telnet, POP3, SMTP).
   - **Engine 4 (`lateral.py`):** Lateral Movement Fan-Out Tracker (SMB 445, RDP 3389, WinRM 5985, SSH 22).
   - **Engine 5 (`exfil.py`):** Data Exfiltration & Volume Skew.
   - **Engine 6 (`entropy.py`):** Shannon Entropy & DGA Detector ($H(S) \ge 3.8$). Enforces mandatory Active Directory & infrastructure prefix/domain whitelisting (`_ldap._tcp`, `_kerberos._tcp`, `_sites.dc._msdcs`, `.in-addr.arpa`) to eliminate enterprise false positives.
   - **Engine 7 (`sweep.py`):** Stealth Port Scan & Subnet Sweep Detector ($N \ge 10$ target IPs).
   - **Engine 8 (`http_audit.py`):** HTTP Profiling & Web Shell Auditor (`curl`, `python-requests`, dangerous methods `PUT`/`PROPFIND`, web shell paths).
   - **Engine 9 (`ja3_fingerprint.py`):** JA3 & JA4 TLS Client Hello Fingerprinting & Threat Intel signatures.
   - **Engine 10 (`tcpstate.py`):** TCP State Machine Auditor & flag anomalies (NULL, XMAS, FIN).
6. **Timeline Stitcher & PCAPNG Carver with Comment Injection:**
   - `netspector/correlate.py`: Entity graph & Cyber Kill Chain timeline stitcher with plausibility scoring.
   - `netspector/carve.py`: Fast binary seek-and-copy PCAP packet carver with option comment injection (`opt_comment`) for Wireshark details panel.
7. **Reporting, STIX 2.1 & Interactive Web Dashboard:**
   - `netspector/report/text.py`: CLI terminal summary.
   - `netspector/report/json_rep.py`: Structured JSON report exporter.
   - `netspector/report/stix_export.py`: STIX 2.1 Threat Intel JSON Bundle exporter.
   - `netspector/report/html_rep.py`: Local `http.server` REST server & responsive HTML/JS UI dashboard with live search & severity filtering.
8. **Build & Distribution:**
   - `build.py`: Packages `netspector/` into `./netspector.pyz` standalone executable via `zipapp`.

## Build & Test Commands
```bash
# Run unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Build standalone executable
python3 build.py

# Test CLI
./netspector.pyz <pcap_file> --json report.json --stix stix_bundle.json --html report.html --web
```
