# NetSpector Pro 🛡️
> **Master Architectural Specification & Offline Automated Forensic PCAP Triage Engine**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20stdlib--only-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/build-netspector.pyz%20(290KB)-purple.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

NetSpector Pro is a high-precision forensic co-pilot designed for incident response (IR) and human forensics teams. It processes raw PCAP/PCAPNG network captures and live network streams entirely offline with **zero external dependencies**, low false positives, bounded memory usage, and transparent arithmetic proofs for every alert—pointing investigators to packets that matter while keeping raw control in human hands.

---

## 🌟 Core Philosophy

- 🔒 **Zero External Dependencies:** Built 100% on Python standard library (`struct`, `socket`, `math`, `collections`, `http.server`, `zipapp`, `unittest`, `hashlib`, `base64`, `re`). No `pip`, `scapy`, `dpkt`, or `PyYAML` required.
- ⚡ **Bounded Memory & Stream Processing:** Stream-based PCAP/PCAPNG readers and Live Interface Sniffer coupled with a bounded LRU Flow Table (default 200,000 capacity). Employs slots-based `PacketRef` tracking (`file_offset`, `caplen`, `ts_us`, `tls_info`, `_raw_payload`) to avoid buffering raw payload bytes in RAM.
- 🧮 **Transparent Arithmetic Proofs:** Zero "black box" ML scores. Every alert exposes exact step-by-step arithmetic formulas, sample counts, thresholds, and statistical derivations.
- 🎯 **Low False Positives over High Recall:** Minimum sample gates ($N \ge 12$), variance thresholds, JA3 threat signatures, and strict transition checks ensure high-confidence forensic findings.

---

## 🏛️ The 10 Automated Forensic Triage Engines (`modules/`)

Every module implements a unified contract (`configure`, `on_packet`, `on_flow_close`, `finalize`) yielding structured `Alert` objects:

1. **TCP Session Reassembly & Flow Indexing (`flows.py`):** Canonical 5-tuple LRU Flow Table (200k capacity). Bidirectional keying (`proto:min(ip1,port1)<->max(ip2,port2)`), state tracking, and stream metrics.
2. **C2 Beaconing & Jitter Analyzer (`beacon.py`):** Inter-Arrival Time ($IAT$) variance, Coefficient of Variation ($CoV = \sigma / \mu \le 0.20$), Median Absolute Deviation ($MAD / M \le 0.25$), sample gate $N \ge 12$.
3. **Cleartext Credential Sniffer (`credentials.py`):** Scans unencrypted traffic on legacy ports (HTTP Basic Auth `Authorization: Basic ...`, FTP `USER`/`PASS`, Telnet, POP3 `USER`/`PASS`, SMTP `AUTH PLAIN/LOGIN`) for exposed authentication credentials.
4. **Lateral Movement Fan-Out Tracker (`lateral.py`):** Evaluates internal host fan-out ratios over high-risk administrative management ports (SMB/445, RDP/3389, WinRM/5985, SSH/22, Kerberos/88, RPC/135).
5. **Data Exfiltration & Volume Skew (`exfil.py`):** Monitors asymmetric volume imbalances (outbound payload $> 5\text{MB}$ or outbound/inbound ratio $> 10.0$) and DNS tunneling payload sizes.
6. **Shannon Entropy & DGA Detector (`entropy.py`):** Measures subdomain randomness ($H(S) = -\sum P(c) \log_2 P(c) \ge 3.8$) and character frequency anomalies against parent-domain length baselines.
7. **Stealth Port Scan & Sweep Detector (`sweep.py`):** Combines stateful TCP flag tracking (SYN without final ACK/RST) with horizontal subnet sweeping across multiple destination target IPs ($N \ge 10$).
8. **HTTP Profiling & Web Shell Auditor (`http_audit.py`):** Detects script-based User-Agents (`curl`, `python-requests`, `go-http-client`, `powershell`, `nikto`, `sqlmap`), empty headers, non-standard HTTP methods (`PUT`, `PROPFIND`), and web shell query paths.
9. **JA3 / JA4 TLS Client Hello Fingerprinter (`ja3_fingerprint.py`):** Parses TLS Client Hello records, calculates JA3/JA4 MD5 hashes, and matches threat intelligence signatures (Cobalt Strike, AsyncRAT, Metasploit, Sliver, Mythic, AgentTesla).
10. **TCP State Machine Auditor (`tcpstate.py`):** Audits strict state machine transitions, half-open connection attempts, and stealth scan flag combinations (NULL, XMAS, FIN).

---

## ⚡ Headline Forensic Features

### 🛠️ Attack Chain Timeline Stitcher (`correlate.py`)
Constructs an entity graph keyed on internal IP hosts, sorts alerts chronologically, maps them against Cyber Kill Chain stages (*Reconnaissance* $\rightarrow$ *Initial Access* $\rightarrow$ *Lateral Movement* $\rightarrow$ *Command & Control* $\rightarrow$ *Exfiltration*), and computes an Attack Chain Plausibility Score.

### ✂️ PCAPNG Evidence Comment Injector (`carve.py`)
Injects PCAPNG Option `1` (`opt_comment`) into carved Enhanced Packet Blocks (EPB) so Wireshark automatically displays NetSpector alert titles and arithmetic proofs directly in the Packet Details pane when investigators open evidence files!

### 📊 STIX 2.1 Threat Intel Exporter (`netspector/report/stix_export.py`)
Exports triage findings as a STIX 2.1 JSON Bundle containing `indicator`, `observed-data`, `relationship`, and `sighting` SDO objects for SIEM / SOAR / MISP ingestion.

### 📡 Live Interface Sniffer (`netspector/capture/live.py`)
Sniffs live network traffic directly from Linux network interfaces (`eth0`, `wlan0`, `lo`) using stdlib `socket(AF_PACKET, SOCK_RAW)` without requiring `libpcap` or `scapy`.

### 💻 Interactive Local Web Dashboard (`netspector/report/html_rep.py`)
Spawns a self-contained local web server using Python's stdlib `http.server` providing REST API endpoints (`/api/summary`, `/api/alerts`, `/api/timeline`, `/api/carve`), live search bar, severity filtering pills, and dark-theme UI.

---

## 🚀 Quickstart & Usage

### 1. Build Standalone Executable
```bash
python3 build.py
```
This generates the self-contained `./netspector.pyz` binary executable.

### 2. Run Forensic Triage
```bash
# Basic PCAP file triage
./netspector.pyz /path/to/capture.pcap

# Live Interface Sniffing mode
./netspector.pyz -i eth0

# Export JSON, STIX 2.1 Threat Intel Bundle, & static HTML report
./netspector.pyz /path/to/capture.pcap --json report.json --stix stix_bundle.json --html report.html

# Automatically carve evidence PCAP files for all alerts
./netspector.pyz /path/to/capture.pcap --carve-all

# Launch interactive local Web UI dashboard (http://127.0.0.1:8080)
./netspector.pyz /path/to/capture.pcap --web --port 8080
```

### 3. Run Unit Test Suite
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 📄 License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
