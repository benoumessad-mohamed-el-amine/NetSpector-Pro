# NetSpector Pro 🛡️
> **Offline, Client-Side Automated PCAP & Network-Log Forensic Triage Engine**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20stdlib--only-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/build-netspector.pyz%20(290KB)-purple.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

NetSpector Pro is a high-precision forensic co-pilot built for Incident Response (IR) teams, SOC analysts, and threat hunters. It analyzes raw PCAP/PCAPNG network captures and live network streams entirely offline with **zero external dependencies**, low false positives, and bounded memory usage—pinpointing threat activity across the Cyber Kill Chain and extracting actionable PCAP evidence files for immediate analysis.

---

## 🌟 Core Features & Security Capabilities

- 🔒 **Zero External Dependencies:** Runs 100% on the Python standard library. No `pip` packages, no `scapy`, no `dpkt`, and no `PyYAML` required. Distributed as a single self-contained binary executable (`netspector.pyz`).
- ⚡ **High-Speed Stream Triage:** Bounded LRU flow engine (200,000 capacity) using lightweight packet indexing (`PacketRef`) to parse gigabyte-scale packet captures with minimal memory overhead.
- 🔍 **Low False-Positive Threat Hunting:** Minimum sample gates, stateful TCP tracking, and threat signatures prioritize actionable, high-confidence forensic findings over noisy alerts.
- 🛠️ **Cyber Kill Chain Campaign Correlation:** Automatically stitches isolated network events into an integrated campaign timeline per host entity, scoring campaign plausibility.
- 📁 **Scan History & Session Profiles:** Automatically archives forensic triage sessions into `./netspector_history/` as persistent JSON profiles. Switch between past triage sessions dynamically in the Web UI dashboard or REST API.
- 📤 **Drag & Drop UI Analysis:** Integrated browser dropzone with live analysis progress bar for immediate offline PCAP triage without leaving the Web Dashboard.
- ✂️ **One-Click Wireshark Evidence Carving:** Instant seek-and-copy binary packet carving that extracts suspicious network flows into standalone PCAP evidence files with embedded Wireshark details panel notes.
- 📊 **STIX 2.1 Threat Intel Export:** Generates standardized STIX 2.1 JSON Bundles for seamless SIEM, SOAR, and MISP platform ingestion.

---

## 🛡️ The 10 Automated Forensic Triage Engines

| Engine | Module | Forensic Detection Capability |
| :--- | :--- | :--- |
| **1. TCP Session Reassembly** | `flows.py` | Stateful canonical 5-tuple LRU flow tracking, bidirectional stream indexing, and connection metrics. |
| **2. C2 Beaconing Analyzer** | `beacon.py` | Detects periodic command-and-control implant timing regularity and automated beaconing intervals ($N \ge 12$). |
| **3. Cleartext Credential Sniffer** | `credentials.py` | Extracts exposed authentication strings over unencrypted protocols (HTTP Basic Auth, FTP, Telnet, POP3, SMTP). |
| **4. Lateral Movement Tracker** | `lateral.py` | Flags internal host fan-out pivoting over administrative management ports (SMB 445, RDP 3389, WinRM 5985, SSH 22, RPC 135). |
| **5. Data Exfiltration Inspector** | `exfil.py` | Identifies large outbound data transfers, volume skew anomalies, and DNS tunneling payload streams. |
| **6. DGA & Subdomain Inspector** | `entropy.py` | Detects Domain Generation Algorithms (DGA), randomized DNS queries, and anomalous consonant cluster runs ($H(S) \ge 3.8$). **Mandatory Whitelisting:** Suppresses Active Directory SRV noise (`_ldap._tcp`, `_kerberos._tcp`, `_sites.dc._msdcs`) to ensure zero AD false positives. |
| **7. Subnet Sweep Detector** | `sweep.py` | Uncovers horizontal reconnaissance sweeps across internal subnets and stateful TCP port scans ($N \ge 10$). |
| **8. HTTP & Web Shell Auditor** | `http_audit.py` | Flags script-based User-Agents (`curl`, `python-requests`, `powershell`), dangerous HTTP methods (`PUT`, `PROPFIND`), and web shell execution paths. |
| **9. TLS JA3/JA4 Fingerprinter** | `ja3_fingerprint.py` | Decodes TLS Client Hello records, generates JA3/JA4 fingerprints, and matches known malware signatures (Cobalt Strike, AsyncRAT, Metasploit, Sliver). |
| **10. TCP State Machine Auditor** | `tcpstate.py` | Audits TCP connection state transitions and flags stealth scan bitmasks (NULL, XMAS, FIN). |

---

## 🏗️ Project Architecture

```
NetSpector-Pro/
├── build.py                     # Standalone zipapp build script
├── netspector.pyz               # Single executable binary (290 KB)
├── netspector/
│   ├── __init__.py              # Package version metadata
│   ├── __main__.py              # CLI entry point, argument parsing & workflow orchestrator
│   ├── model.py                 # Core data models: PacketRef (__slots__), Alert, Flow, Severity
│   ├── flows.py                 # Canonical 5-tuple key & LRU FlowTable (200k cap)
│   ├── correlate.py             # Attack Chain Timeline Stitcher & Kill-Chain stage mapper
│   ├── carve.py                 # Seek-and-copy PCAP evidence carver with Wireshark comment injection
│   ├── capture/
│   │   ├── decode.py            # Binary decoders (Eth, VLAN, IPv4, IPv6, ARP, TCP, UDP, DNS, ICMP, TLS)
│   │   ├── pcap.py              # Classic PCAP stream reader (magic bytes, micro/nanosec, endianness)
│   │   ├── pcapng.py            # PCAPNG stream reader (SHB, IDB, EPB blocks, 64-bit timestamps)
│   │   └── live.py              # Live raw socket sniffer (socket.AF_PACKET)
│   ├── modules/
│   │   ├── beacon.py            # Module 1: C2 Beaconing Analyzer
│   │   ├── credentials.py       # Module 2: Cleartext Credential Sniffer
│   │   ├── lateral.py           # Module 3: Lateral Movement Fan-Out Tracker
│   │   ├── exfil.py             # Module 4: Data Exfiltration & Volume Skew
│   │   ├── entropy.py           # Module 5: DGA & Subdomain Inspector
│   │   ├── sweep.py             # Module 6: Subnet Sweep Detector
│   │   ├── http_audit.py        # Module 7: HTTP Profiling & Web Shell Auditor
│   │   ├── ja3_fingerprint.py   # Module 8: TLS JA3/JA4 Fingerprinter
│   │   └── tcpstate.py          # Module 9: TCP State Machine Auditor
│   ├── rules/
│   │   ├── yamlsub.py           # Strict-subset YAML parser with line-numbered error reporting
│   │   └── defaults.yaml        # Baseline detection thresholds
│   └── report/
│       ├── text.py              # CLI terminal text summary renderer
│       ├── json_rep.py          # Structured JSON triage report exporter
│       ├── stix_export.py       # STIX 2.1 Threat Intel JSON Bundle exporter
│       ├── history.py           # Scan History & Session Profiles Manager
│       └── html_rep.py          # Local http.server REST server & responsive Web UI dashboard
└── tests/                       # Complete unit test suite (23/23 passing)
```

---

## 🚀 Quickstart & Usage

### 1. Build Standalone Executable
```bash
python3 build.py
```
This packages the core engine into a single `./netspector.pyz` executable binary.

### 2. Forensic Triage Examples

```bash
# Basic terminal summary output
./netspector.pyz /path/to/capture.pcap

# Sniff live network traffic directly from an interface (Linux raw socket)
./netspector.pyz -i eth0

# Export JSON report, STIX 2.1 Threat Intel Bundle, and static HTML report
./netspector.pyz /path/to/capture.pcap --json report.json --stix stix_bundle.json --html report.html

# Automatically carve mini-PCAP evidence files for all triggered alerts
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
