"""Interactive Local Web Dashboard and Standalone HTML Report Generator for NetSpector Pro."""

import io
import json
import os
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List

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


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSpector Pro - Forensic Triage Dashboard</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-purple: #c084fc;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #3b82f6;
            --sev-info: #64748b;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            padding: 24px;
            line-height: 1.5;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--card-border);
            margin-bottom: 24px;
        }

        h1 { font-size: 24px; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 10px; }
        .logo-badge { background: linear-gradient(135deg, #38bdf8, #818cf8); color: #000; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 800; }

        /* Drag and Drop Zone & Progress Bar */
        .dropzone {
            background: rgba(30, 41, 59, 0.6);
            border: 2px dashed var(--accent-blue);
            border-radius: 12px;
            padding: 28px;
            text-align: center;
            margin-bottom: 28px;
            cursor: pointer;
            transition: all 0.2s ease-in-out;
        }
        .dropzone.hover {
            background: rgba(56, 189, 248, 0.15);
            border-color: #818cf8;
        }
        .dropzone-icon { font-size: 36px; margin-bottom: 8px; }
        .dropzone-title { font-size: 16px; font-weight: 700; color: var(--text-main); }
        .dropzone-desc { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

        .progress-container {
            width: 100%;
            max-width: 500px;
            margin: 16px auto 0 auto;
            display: none;
        }
        .progress-bar-bg {
            background: #0f172a;
            border-radius: 8px;
            height: 12px;
            overflow: hidden;
            border: 1px solid var(--card-border);
        }
        .progress-bar-fill {
            width: 0%;
            height: 100%;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            border-radius: 8px;
            transition: width 0.2s ease-in-out;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }

        .stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
        .stat-value { font-size: 28px; font-weight: 800; margin-top: 6px; color: var(--accent-blue); }

        .section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }

        .filter-bar {
            display: flex;
            gap: 12px;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }

        .search-input {
            background: #0f172a;
            border: 1px solid var(--card-border);
            color: var(--text-main);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 13px;
            width: 280px;
        }

        .filter-btn {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
        }
        .filter-btn.active {
            background: var(--accent-blue);
            color: #000;
            border-color: var(--accent-blue);
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: var(--sev-critical); color: #fff; }
        .badge-HIGH { background: var(--sev-high); color: #fff; }
        .badge-MEDIUM { background: var(--sev-medium); color: #000; }
        .badge-LOW { background: var(--sev-low); color: #fff; }
        .badge-INFO { background: var(--sev-info); color: #fff; }

        .entity-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
        }

        .entity-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .entity-ip { font-size: 16px; font-weight: 700; color: var(--accent-purple); }

        .killchain-timeline {
            display: flex;
            align-items: center;
            gap: 8px;
            overflow-x: auto;
            padding-top: 10px;
        }

        .kc-stage {
            background: #0f172a;
            border: 1px solid var(--card-border);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 12px;
            white-space: nowrap;
        }

        .alert-table-container {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            overflow: hidden;
            margin-top: 12px;
        }

        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
        th, td { padding: 14px 16px; border-bottom: 1px solid var(--card-border); }
        th { background: #0f172a; color: var(--text-muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
        tr:hover { background: rgba(255, 255, 255, 0.02); }

        .btn-carve {
            background: linear-gradient(135deg, #059669, #10b981);
            color: #fff;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn-carve:hover { opacity: 0.85; }

        .proof-box {
            background: #0f172a;
            border: 1px solid #334155;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 11px;
            color: #a7f3d0;
            white-space: pre-wrap;
            margin-top: 6px;
        }
    </style>
</head>
<body>

    <header>
        <h1><span class="logo-badge">NETSPECTOR PRO</span> Forensic Triage Dashboard</h1>
        <div style="font-size: 12px; color: var(--text-muted);">Offline Analysis Engine | Zero Dependencies</div>
    </header>

    <!-- Interactive Drag & Drop PCAP Zone with Progress Bar -->
    <div class="dropzone" id="dropzone" onclick="document.getElementById('file-input').click()">
        <div class="dropzone-icon">📁</div>
        <div class="dropzone-title">Drag & Drop PCAP / PCAPNG File Here</div>
        <div class="dropzone-desc">or click to browse from your computer to analyze immediately</div>
        
        <div class="progress-container" id="progress-container">
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" id="progress-bar-fill"></div>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px; display: flex; justify-content: space-between;">
                <span id="progress-status">Uploading & Analyzing...</span>
                <span id="progress-percentage">0%</span>
            </div>
        </div>

        <input type="file" id="file-input" style="display: none;" accept=".pcap,.pcapng,.cap" onchange="handleFileSelect(event)">
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Packets Processed</div>
            <div class="stat-value" id="stat-packets">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active & Closed Flows</div>
            <div class="stat-value" id="stat-flows">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Alerts Triggered</div>
            <div class="stat-value" id="stat-alerts" style="color: var(--sev-high);">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Correlated Host Entities</div>
            <div class="stat-value" id="stat-entities" style="color: var(--accent-purple);">0</div>
        </div>
    </div>

    <div class="section-title">
        <span>Attack Chain Narrative & Entity Graph</span>
    </div>
    <div id="entities-container"></div>

    <div class="section-title" style="margin-top: 32px;">
        <span>Detailed Forensic Alerts</span>
    </div>

    <div class="filter-bar">
        <input type="text" id="search-input" class="search-input" placeholder="🔍 Search IP, Domain, Rule, or ID..." onkeyup="filterAlerts()">
        <button class="filter-btn active" onclick="setSeverityFilter('ALL', this)">ALL</button>
        <button class="filter-btn" onclick="setSeverityFilter('CRITICAL', this)">CRITICAL</button>
        <button class="filter-btn" onclick="setSeverityFilter('HIGH', this)">HIGH</button>
        <button class="filter-btn" onclick="setSeverityFilter('MEDIUM', this)">MEDIUM</button>
    </div>

    <div class="alert-table-container">
        <table>
            <thead>
                <tr>
                    <th>Alert ID</th>
                    <th>Severity</th>
                    <th>Kill-Chain Stage</th>
                    <th>Source IP:Port</th>
                    <th>Target IP:Port</th>
                    <th>Title & Description</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="alerts-tbody"></tbody>
        </table>
    </div>

    <script>
        let currentData = __DATA_JSON__;
        let allAlerts = currentData.alerts || [];
        let currentSeverity = 'ALL';

        function renderDashboard(data) {
            currentData = data;
            allAlerts = data.alerts || [];

            const summary = data.metadata ? data.metadata.summary : {};
            document.getElementById('stat-packets').innerText = (summary.total_packets || 0).toLocaleString();
            document.getElementById('stat-flows').innerText = (summary.total_flows || 0).toLocaleString();
            document.getElementById('stat-alerts').innerText = allAlerts.length;

            const correlation = data.attack_chain_correlation || {};
            const entities = correlation.entities || [];
            document.getElementById('stat-entities').innerText = entities.length;

            const entContainer = document.getElementById('entities-container');
            entContainer.innerHTML = '';
            entities.forEach(ent => {
                const card = document.createElement('div');
                card.className = 'entity-card';
                card.innerHTML = `
                    <div class="entity-header">
                        <span class="entity-ip">🖥️ Entity Host: ${ent.entity_ip}</span>
                        <span class="badge badge-HIGH">Plausibility: ${ent.plausibility_score}%</span>
                    </div>
                    <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
                        Correlated Stages (${ent.stages_covered.length}):
                    </div>
                    <div class="killchain-timeline">
                        ${ent.stages_covered.map((st, i) => `<div class="kc-stage">${i+1}. ${st}</div>`).join('<span style="color:#64748b">➔</span>')}
                    </div>
                `;
                entContainer.appendChild(card);
            });

            filterAlerts();
        }

        function setSeverityFilter(sev, btn) {
            currentSeverity = sev;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterAlerts();
        }

        function filterAlerts() {
            const query = document.getElementById('search-input').value.toLowerCase();
            const tbody = document.getElementById('alerts-tbody');
            tbody.innerHTML = '';

            const filtered = allAlerts.filter(alt => {
                const matchSev = currentSeverity === 'ALL' || alt.severity === currentSeverity;
                const matchQuery = !query || 
                    alt.alert_id.toLowerCase().includes(query) ||
                    alt.title.toLowerCase().includes(query) ||
                    alt.description.toLowerCase().includes(query) ||
                    alt.source_ip.includes(query) ||
                    alt.target_ip.includes(query);
                return matchSev && matchQuery;
            });

            filtered.forEach(alt => {
                const tr = document.createElement('tr');
                const proofStr = JSON.stringify(alt.arithmetic_proof, null, 2);
                tr.innerHTML = `
                    <td style="font-weight: 700; color: var(--accent-blue);">${alt.alert_id}</td>
                    <td><span class="badge badge-${alt.severity}">${alt.severity}</span></td>
                    <td style="font-size: 12px; color: var(--text-muted);">${alt.stage}</td>
                    <td>${alt.source_ip}:${alt.source_port}</td>
                    <td>${alt.target_ip}:${alt.target_port}</td>
                    <td>
                        <div style="font-weight: 600;">${alt.title}</div>
                        <div style="font-size: 12px; color: var(--text-muted);">${alt.description}</div>
                        <details style="margin-top: 4px;">
                            <summary style="font-size: 11px; cursor: pointer; color: var(--accent-blue);">View Arithmetic Proof</summary>
                            <div class="proof-box">${proofStr}</div>
                        </details>
                    </td>
                    <td>
                        <button class="btn-carve" onclick="carveAlert('${alt.alert_id}')">Carve PCAP</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function carveAlert(alertId) {
            try {
                const res = await fetch(`/api/carve?alert_id=${alertId}`);
                const data = await res.json();
                alert(data.message || 'PCAP Carved successfully!');
            } catch (err) {
                alert('PCAP Carve triggered for ' + alertId);
            }
        }

        // Drag & Drop Handlers
        const dropzone = document.getElementById('dropzone');

        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.add('hover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.remove('hover');
            }, false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                uploadPcap(files[0]);
            }
        });

        function handleFileSelect(e) {
            const files = e.target.files;
            if (files.length > 0) {
                uploadPcap(files[0]);
            }
        }

        function updateProgress(percent, statusText) {
            const container = document.getElementById('progress-container');
            const fill = document.getElementById('progress-bar-fill');
            const pctText = document.getElementById('progress-percentage');
            const status = document.getElementById('progress-status');

            container.style.display = 'block';
            fill.style.width = Math.min(100, Math.max(0, percent)) + '%';
            pctText.innerText = Math.round(percent) + '%';
            if (statusText) status.innerText = statusText;
        }

        function uploadPcap(file) {
            const title = document.querySelector('.dropzone-title');
            title.innerText = `⏳ Triage in progress: '${file.name}'...`;
            updateProgress(10, "Uploading capture binary...");

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload', true);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');

            xhr.upload.onprogress = function(e) {
                if (e.lengthComputable) {
                    const uploadPct = (e.loaded / e.total) * 50; // Upload takes first 50%
                    updateProgress(uploadPct, `Uploading (${Math.round(uploadPct * 2)}%)...`);
                }
            };

            xhr.onload = function() {
                if (xhr.status === 200) {
                    updateProgress(85, "Executing 10 Forensic Triage Engines...");
                    setTimeout(() => {
                        updateProgress(100, "Analysis Complete!");
                        title.innerText = `✅ Triage Complete: '${file.name}'`;
                        const result = JSON.parse(xhr.responseText);
                        renderDashboard(result);
                        setTimeout(() => {
                            document.getElementById('progress-container').style.display = 'none';
                        }, 2500);
                    }, 400);
                } else {
                    title.innerText = `❌ Error analyzing '${file.name}'`;
                    updateProgress(0, "Triage Error");
                    alert('Failed to analyze PCAP file.');
                }
            };

            xhr.onerror = function() {
                title.innerText = `❌ Error analyzing '${file.name}'`;
                updateProgress(0, "Connection Error");
            };

            xhr.send(file);
        }

        renderDashboard(currentData);
    </script>
</body>
</html>
"""


def run_triage_on_pcap_file(filepath: str) -> Dict[str, Any]:
    """Runs all 10 triage engines on a PCAP file and returns full JSON report dict."""
    flow_table = FlowTable(max_capacity=200000)

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

    collected_alerts: List[Alert] = []

    def handle_flow_close(closed_flow):
        for m in modules:
            alerts = m.on_flow_close(closed_flow)
            if alerts:
                collected_alerts.extend(alerts)

    flow_table.register_evict_callback(handle_flow_close)

    # Detect pcap format
    with open(filepath, "rb") as f:
        magic = f.read(4)

    if magic in (b"\x0a\x0d\x0d\x0a", b"\x0a\x0d\x0d\x0a"):
        reader = PcapngReader(filepath)
    else:
        reader = PcapReader(filepath)

    total_packets = 0
    with reader as pcap_stream:
        for pkt in pcap_stream.packets():
            total_packets += 1
            flow = flow_table.touch_or_create(pkt)
            for m in modules:
                pkt_alerts = m.on_packet(pkt, flow)
                if pkt_alerts:
                    collected_alerts.extend(pkt_alerts)

    flow_table.flush_all()
    for m in modules:
        fin_alerts = m.finalize()
        if fin_alerts:
            collected_alerts.extend(fin_alerts)

    unique_alerts_map = {}
    for a in collected_alerts:
        unique_alerts_map[a.alert_id] = a
    all_alerts = list(unique_alerts_map.values())

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
        "severity_counts": sev_counts,
    }

    return {
        "metadata": {"summary": summary_stats},
        "attack_chain_correlation": correlation_data,
        "alerts": [a.to_dict() for a in all_alerts],
    }


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for NetSpector Pro local web dashboard with Drag & Drop PCAP upload."""

    alerts: List[Alert] = []
    summary_stats: Dict[str, Any] = {}
    correlation_data: Dict[str, Any] = {}
    source_pcap_path: str = ""

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == "/" or path == "/index.html":
            data_dict = {
                "metadata": {"summary": self.summary_stats},
                "attack_chain_correlation": self.correlation_data,
                "alerts": [a.to_dict() for a in self.alerts],
            }
            rendered_html = HTML_TEMPLATE.replace("__DATA_JSON__", json.dumps(data_dict))

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(rendered_html.encode("utf-8"))

        elif path == "/api/summary":
            self._send_json({"summary": self.summary_stats})

        elif path == "/api/alerts":
            self._send_json([a.to_dict() for a in self.alerts])

        elif path == "/api/timeline":
            self._send_json(self.correlation_data)

        elif path == "/api/carve":
            alert_id = query.get("alert_id", [""])[0]
            matched_alert = next((a for a in self.alerts if a.alert_id == alert_id), None)

            if matched_alert and self.source_pcap_path:
                output_path = f"evidence_{alert_id}.pcap"
                carver = PcapCarver(self.source_pcap_path)
                success = carver.carve_alert(matched_alert, output_path)
                if success:
                    self._send_json({"status": "success", "message": f"Carved evidence file written to '{output_path}'"})
                else:
                    self._send_json({"status": "error", "message": "Carving failed"}, code=500)
            else:
                self._send_json({"status": "error", "message": f"Alert '{alert_id}' not found or no source PCAP"}, code=404)

        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/upload":
            content_len = int(self.headers.get("Content-Length", 0))
            raw_data = self.rfile.read(content_len)

            if not raw_data:
                self._send_json({"error": "No PCAP data received"}, code=400)
                return

            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_f:
                tmp_f.write(raw_data)
                tmp_pcap_path = tmp_f.name

            try:
                result_dict = run_triage_on_pcap_file(tmp_pcap_path)
                DashboardRequestHandler.summary_stats = result_dict["metadata"]["summary"]
                DashboardRequestHandler.correlation_data = result_dict["attack_chain_correlation"]
                DashboardRequestHandler.source_pcap_path = tmp_pcap_path

                self._send_json(result_dict)
            except Exception as e:
                self._send_json({"error": f"Failed to triage uploaded PCAP: {e}"}, code=500)
        else:
            self.send_error(404, "Not Found")

    def _send_json(self, obj: Any, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode("utf-8"))

    def log_message(self, format, *args):
        return


def start_web_dashboard(
    alerts: List[Alert],
    summary_stats: Dict[str, Any],
    correlation_data: Dict[str, Any],
    source_pcap_path: str,
    port: int = 8080,
):
    """Starts local http.server web dashboard."""
    DashboardRequestHandler.alerts = alerts
    DashboardRequestHandler.summary_stats = summary_stats
    DashboardRequestHandler.correlation_data = correlation_data
    DashboardRequestHandler.source_pcap_path = source_pcap_path

    server = HTTPServer(("127.0.0.1", port), DashboardRequestHandler)
    print(f"\n[+] Interactive Web Dashboard running at http://127.0.0.1:{port}")
    print("[+] Drag & Drop PCAP upload active with live analysis progress bar!")
    print("[+] Press Ctrl+C to stop web server.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Web server stopped.")
        server.server_close()


def render_static_html(
    alerts: List[Alert],
    summary_stats: Dict[str, Any],
    correlation_data: Dict[str, Any],
    output_path: str,
):
    """Renders standalone static HTML file."""
    data_dict = {
        "metadata": {"summary": summary_stats},
        "attack_chain_correlation": correlation_data,
        "alerts": [a.to_dict() for a in alerts],
    }
    rendered = HTML_TEMPLATE.replace("__DATA_JSON__", json.dumps(data_dict))
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
