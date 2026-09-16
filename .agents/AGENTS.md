# NetSpector Pro - Agent Session & Architecture Cache

## Project Summary
**NetSpector Pro** is an offline, client-side automated PCAP and network-log forensic triage tool built for high-precision forensic analysis. It runs on Python 3.11+ with **zero external dependencies** (strictly standard library), bounded memory usage, low false positives, and transparent arithmetic proofs for every alert.

## Core Architectural Rules & Constraints
1. **Zero External Dependencies:**
   - Standard library ONLY (`struct`, `socket`, `math`, `collections`, `http.server`, `zipapp`, `unittest`).
   - No `pip` packages (`scapy`, `dpkt`, `PyYAML`, etc.).
2. **Binary PCAP/PCAPNG Stream Readers:**
   - Stream-based parsing via `netspector/capture/pcap.py` and `netspector/capture/pcapng.py`.
   - Lightweight `PacketRef` (`__slots__`) storing packet metadata (`ts_us`, `file_offset`, `caplen`, `wirelen`, `flow_id`, `flags`) without buffering payload bytes in RAM.
3. **Canonical 5-Tuple LRU Flow Engine:**
   - `netspector/flows.py`: `FlowTable` max capacity 200,000.
   - Flow key format: `proto:min(ip1,port1)<->max(ip2,port2)` (bidirectional mapping).
4. **Strict-Subset YAML Parser:**
   - `netspector/rules/yamlsub.py`: Hand-rolled YAML parser with line-numbered error diagnostics (`YAMLParseError`).
5. **Detection Engines (`netspector/modules/`):**
   - Contract: `configure(rules)`, `on_packet(pkt, flow)`, `on_flow_close(flow)`, `finalize()`.
   - **Module 1 (`beacon.py`):** C2 Beaconing using Inter-Arrival Time variance ($CoV = \sigma / \mu \le 0.20$, $MAD / M \le 0.25$, sample gate $N \ge 12$).
   - **Module 2 (`entropy.py`):** Shannon Entropy $H(S) = -\sum P(c) \log_2 P(c) \ge 3.8$ on DNS subdomains and consonant cluster runs.
   - **Module 3 (`tcpstate.py`):** TCP State Auditor tracking half-open SYN scans ($N \ge 10$) and flag anomalies (NULL, XMAS, FIN).
   - **Module 4 (`lateral.py`):** Lateral movement fan-out ratios over high-risk remote management ports (SMB 445, RDP 3389, WinRM 5985/5986, SSH 22).
6. **Timeline Stitcher & PCAP Carver:**
   - `netspector/correlate.py`: Entity graph & Cyber Kill Chain timeline stitcher with plausibility scoring.
   - `netspector/carve.py`: Fast binary seek-and-copy PCAP packet carver.
7. **Reporting & Interactive Web Dashboard:**
   - `netspector/report/text.py`: CLI terminal summary.
   - `netspector/report/json_rep.py`: Structured JSON report exporter.
   - `netspector/report/html_rep.py`: Local `http.server` REST server & responsive HTML/JS UI dashboard.
8. **Build & Distribution:**
   - `build.py`: Packages `netspector/` into `./netspector.pyz` standalone executable via `zipapp`.

## Build & Test Commands
```bash
# Run unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Build standalone executable
python3 build.py

# Test CLI
./netspector.pyz <pcap_file> --json report.json --html report.html --web
```
