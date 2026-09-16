# NetSpector Pro 🛡️
> **Offline, Client-Side Automated PCAP & Network-Log Forensic Triage Engine**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20stdlib--only-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/build-netspector.pyz%20(199KB)-purple.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

NetSpector Pro is a high-precision forensic co-pilot designed for incident response (IR) and human forensics teams. It processes raw PCAP/PCAPNG network captures entirely offline with **zero external dependencies**, low false positives, bounded memory usage, and transparent arithmetic proofs for every alert—pointing investigators to packets that matter while keeping control in human hands.

---

## 🌟 Core Philosophy

- 🔒 **Zero External Dependencies:** Built 100% on Python standard library (`struct`, `socket`, `math`, `collections`, `http.server`, `zipapp`, `unittest`). No `pip`, `scapy`, `dpkt`, or `PyYAML` required.
- ⚡ **Bounded Memory & Stream Processing:** Stream-based PCAP/PCAPNG readers coupled with a bounded LRU Flow Table (default 200,000 capacity). Employs slots-based `PacketRef` tracking (`file_offset`, `caplen`, `ts_us`) to avoid buffering raw payload bytes in RAM.
- 🧮 **Transparent Arithmetic Proofs:** Zero "black box" ML scores. Every alert exposes exact step-by-step arithmetic formulas, sample counts, thresholds, and statistical derivations.
- 🎯 **Low False Positives over High Recall:** Minimum sample gates ($N \ge 12$), variance thresholds, and strict transition checks ensure high confidence forensic findings.

---

## 🏗️ System Architecture

```
NetSpector-Pro/
├── build.py                     # Standalone zipapp build script
├── netspector.pyz               # Generated single executable binary (199 KB)
├── netspector/
│   ├── __init__.py              # Package version metadata
│   ├── __main__.py              # CLI entry point, argument parsing & workflow orchestrator
│   ├── model.py                 # Core models: PacketRef (__slots__), Alert, Flow, Severity
│   ├── flows.py                 # Canonical 5-tuple key & LRU FlowTable (200k cap)
│   ├── correlate.py             # Attack Chain Timeline Stitcher & Kill-Chain stage mapper
│   ├── carve.py                 # Binary seek-and-copy PCAP/PCAPNG evidence carver
│   ├── capture/
│   │   ├── decode.py            # Binary decoders (Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, DNS, ICMP)
│   │   ├── pcap.py              # Classic PCAP stream reader (magic bytes, micro/nanosec, endianness)
│   │   └── pcapng.py            # PCAPNG stream reader (SHB, IDB, EPB blocks, 64-bit timestamps)
│   ├── modules/
│   │   ├── beacon.py            # Module 1: C2 Beaconing (IAT, CoV, MAD, N>=12 gate)
│   │   ├── entropy.py           # Module 2: Shannon Entropy & DGA domain detector
│   │   ├── tcpstate.py          # Module 3: TCP State Auditor (half-open SYN scans, flags)
│   │   └── lateral.py           # Module 4: Fan-out ratios & high-risk port pivoting (SMB, RDP, WinRM, SSH)
│   ├── rules/
│   │   ├── yamlsub.py           # Strict-subset YAML parser with line-numbered error reporting
│   │   └── defaults.yaml        # Baseline detection thresholds
│   └── report/
│       ├── text.py              # CLI terminal text summary renderer
│       ├── json_rep.py          # Structured JSON triage report exporter
│       └── html_rep.py          # Stdlib HTTP server & embedded responsive Web UI dashboard
└── tests/                       # Complete unit test suite (13/13 passing)
```

---

## 🔍 Detection Engines Contract & Mathematical Formulas

Every detection engine implements a unified contract (`configure`, `on_packet`, `on_flow_close`, `finalize`) yielding structured `Alert` objects:

### 1. C2 Beaconing Engine (`netspector/modules/beacon.py`)
Tracks Inter-Arrival Times ($IAT_i = ts_i - ts_{i-1}$) across active flows:
- **Sample Gate:** Requires $N \ge 12$ samples in a flow before evaluating timing regularity.
- **Coefficient of Variation ($CoV$):**
  $$\mu = \frac{1}{N} \sum IAT_i, \quad \sigma = \sqrt{\frac{1}{N} \sum (IAT_i - \mu)^2}, \quad CoV = \frac{\sigma}{\mu} \le 0.20$$
- **Median Absolute Deviation ($MAD$):**
  $$M = \text{median}(IAT), \quad MAD = \text{median}(|IAT_i - M|), \quad \frac{MAD}{M} \le 0.25$$

### 2. Shannon Entropy & DGA Engine (`netspector/modules/entropy.py`)
Measures character randomness on DNS subdomain labels:
- **Shannon Entropy $H(S)$:**
  $$H(S) = -\sum_{c \in \Sigma} P(c) \log_2 P(c) \ge 3.8 \text{ bits/char}$$
- Consonant cluster run lengths ($\ge 5$ consecutive consonants) and character distribution anomalies vs parent-domain baselines.

### 3. TCP State Auditor (`netspector/modules/tcpstate.py`)
- Strictly audits connection state machine transitions ($CLOSED \rightarrow SYN\_SENT \rightarrow SYN\_RCVD \rightarrow ESTABLISHED \rightarrow FIN/RST$).
- Tracks half-open SYN scan targets per source IP ($N \ge 10$ target ports without completing handshakes).
- Flags stealth scan bitmasks: NULL scan (`flags == 0`), XMAS scan (`FIN+PSH+URG`), and FIN stealth scans (`FIN` without `ACK`).

### 4. Lateral Movement Pivoting Engine (`netspector/modules/lateral.py`)
- Monitors internal-to-internal host connection fan-out ratios over high-risk remote management ports:
  - **SMB (445)**, **RDP (3389)**, **WinRM (5985/5986)**, **SSH (22)**, **Kerberos (88)**, **NetBIOS/RPC (135/139)**.
- Triggers alerts when an internal host contacts $\ge 15$ unique internal targets over management ports within analysis windows.

---

## ⚡ Headline Forensic Features

### 🛠️ Attack Chain Timeline Stitcher (`netspector/correlate.py`)
Constructs an entity graph keyed on internal IP hosts, sorts alerts chronologically, maps them against Cyber Kill Chain stages (*Reconnaissance* $\rightarrow$ *Initial Access* $\rightarrow$ *Lateral Movement* $\rightarrow$ *Command & Control* $\rightarrow$ *Exfiltration*), and computes an Attack Chain Plausibility Score.

### ✂️ One-Click PCAP Packet Carving (`netspector/carve.py`)
Leverages stored `file_offset` and `caplen` in `PacketRef` to perform binary seek-and-copy extraction, creating standalone, evidence-ready `.pcap` files for immediate Wireshark inspection.

### 💻 Interactive Local Web Dashboard (`netspector/report/html_rep.py`)
Spawns a self-contained local web server using Python's stdlib `http.server` providing REST API endpoints (`/api/summary`, `/api/alerts`, `/api/timeline`, `/api/carve`) and a dark-theme responsive UI with search, entity drill-downs, arithmetic proof modals, and one-click PCAP carving triggers.

---

## 🚀 Quickstart & Usage

### 1. Build Standalone Executable
```bash
python3 build.py
```
This generates the self-contained `./netspector.pyz` binary executable.

### 2. Run Forensic Triage
```bash
# Basic terminal summary output
./netspector.pyz /path/to/capture.pcap

# Export JSON report & static HTML report
./netspector.pyz /path/to/capture.pcap --json report.json --html report.html

# Automatically carve mini-PCAP evidence files for all alerts
./netspector.pyz /path/to/capture.pcap --carve-all

# Launch interactive local Web UI dashboard (default http://127.0.0.1:8080)
./netspector.pyz /path/to/capture.pcap --web --port 8080
```

### 3. Run Unit Test Suite
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 📄 License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
