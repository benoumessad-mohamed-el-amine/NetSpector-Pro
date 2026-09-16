"""Interactive Local Web Dashboard and Standalone HTML Report Generator for NetSpector Pro."""

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List
from netspector.carve import PcapCarver
from netspector.model import Alert


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
        <h1><span class="logo-badge">NETSPECTOR PRO</span> Forensic Triage Dashboard v1.1.0</h1>
        <div style="font-size: 12px; color: var(--text-muted);">Offline Analysis Engine | Zero Dependencies</div>
    </header>

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
        const initialData = __DATA_JSON__;
        let allAlerts = initialData.alerts || [];
        let currentSeverity = 'ALL';

        function renderDashboard(data) {
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

        renderDashboard(initialData);
    </script>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for NetSpector Pro local web dashboard."""

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
