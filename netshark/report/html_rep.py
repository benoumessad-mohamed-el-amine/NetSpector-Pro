"""Interactive Local Web Dashboard and Standalone HTML Report Generator for NetShark Pro."""

import io
import json
import os
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from netshark.capture.pcap import PcapReader
from netshark.capture.pcapng import PcapngReader
from netshark.carve import PcapCarver
from netshark.correlate import AttackChainStitcher
from netshark.flows import FlowTable
from netshark.model import Alert, Severity
from netshark.modules import (
    C2BeaconModule,
    CleartextCredentialsModule,
    DnsEntropyModule,
    DnsTunnelModule,
    ExfiltrationModule,
    FileCarverModule,
    HttpAuditModule,
    Ja3FingerprintModule,
    LateralMovementModule,
    SmbAuditModule,
    SubnetSweepModule,
    TcpStateModule,
)
from netshark.report.history import HistoryManager


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetShark Pro 🦈 - Forensic Triage Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
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
            flex-wrap: wrap;
            gap: 16px;
        }

        h1 { font-size: 24px; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 12px; }
        .logo-badge {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 6px 16px 6px 10px;
            border-radius: 12px;
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.85), rgba(15, 23, 42, 0.95));
            border: 1px solid rgba(56, 189, 248, 0.35);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4), 0 0 12px rgba(56, 189, 248, 0.15);
            backdrop-filter: blur(8px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
        }
        .logo-badge:hover {
            border-color: rgba(56, 189, 248, 0.65);
            box-shadow: 0 6px 20px rgba(56, 189, 248, 0.25), 0 0 16px rgba(129, 140, 248, 0.2);
            transform: translateY(-1px);
        }
        .logo-text {
            font-weight: 900;
            font-size: 15px;
            letter-spacing: 0.8px;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        /* History & Profile Selector Controls */
        .history-controls {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .history-select {
            background: #0f172a;
            border: 1px solid var(--card-border);
            color: var(--accent-blue);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            max-width: 320px;
            cursor: pointer;
        }

        /* Drag and Drop Zone & Progress Bar */
        .dropzone {
            background: rgba(30, 41, 59, 0.6);
            border: 2px dashed var(--accent-blue);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            margin-bottom: 28px;
            cursor: pointer;
            transition: all 0.2s ease-in-out;
        }
        .dropzone.hover {
            background: rgba(56, 189, 248, 0.15);
            border-color: #818cf8;
        }
        .dropzone-icon { font-size: 32px; margin-bottom: 6px; }
        .dropzone-title { font-size: 15px; font-weight: 700; color: var(--text-main); }
        .dropzone-desc { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

        .progress-container {
            width: 100%;
            max-width: 480px;
            margin: 12px auto 0 auto;
            display: none;
        }
        .progress-bar-bg {
            background: #0f172a;
            border-radius: 8px;
            height: 10px;
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
        <h1>
            <span class="logo-badge">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="height: 32px; width: 32px; filter: drop-shadow(0 2px 8px rgba(56, 189, 248, 0.4));">
                  <mask id="ns-cut">
                    <rect width="100" height="100" fill="#000"/>
                    <g fill="#fff">
                      <path d="M10 36 L48 26 L58 26 L64 8 L74 29 C84 33 90 40 92 46 L100 38 L93 52 L100 66 L88 58 C82 64 74 66 66 66 L60 80 L50 64 C40 63 34 60 30 56 L40 46 L37 40 L34 45 L31 39 L28 44 L25 38 L22 43 L19 37 L16 42 L13 36 Z"/>
                      <path d="M12 45 L18 50 L22 44 L28 52 L32 46 L38 53 L41 52 L36 62 L14 55 Z"/>
                    </g>
                    <ellipse cx="36" cy="36" rx="3.4" ry="2.4" transform="rotate(-14 36 36)" fill="#000"/>
                    <g stroke="#000" stroke-width="2.2" stroke-linecap="round" fill="none">
                      <path d="M50 31 Q47 41 51 51"/>
                      <path d="M55 30 Q52 41 56 51"/>
                      <path d="M60 30 Q57 41 61 51"/>
                      <path d="M65 31 Q62 41 66 50"/>
                    </g>
                  </mask>
                  <rect width="100" height="100" fill="#38bdf8" mask="url(#ns-cut)"/>
                </svg>
                <span class="logo-text">NETSHARK PRO</span>
            </span>
            Forensic Triage Dashboard
        </h1>
        
        <!-- Scan History Profile Selector -->
        <div class="history-controls">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 600;">📜 Scan Profiles:</span>
            <select id="history-select" class="history-select" onchange="onProfileSelect(this.value)">
                <option value="CURRENT">-- Current Active Session --</option>
            </select>
        </div>
    </header>

    <!-- Interactive Drag & Drop PCAP Zone -->
    <div class="dropzone" id="dropzone" onclick="document.getElementById('file-input').click()">
        <div class="dropzone-icon">📁</div>
        <div class="dropzone-title">Drag & Drop PCAP / PCAPNG File Here</div>
        <div class="dropzone-desc">or click to browse from your computer to analyze immediately</div>
        
        <div class="progress-container" id="progress-container">
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" id="progress-bar-fill"></div>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; display: flex; justify-content: space-between;">
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

    <!-- Tab Navigation Bar -->
    <div style="display: flex; gap: 12px; margin-bottom: 24px; border-bottom: 1px solid var(--card-border); padding-bottom: 12px;">
        <button id="tab-btn-alerts" class="filter-btn active" style="font-size: 13px; padding: 8px 18px;" onclick="switchTab('tab-alerts')">🛡️ Forensic Alerts & Attack Chains</button>
        <button id="tab-btn-dns" class="filter-btn" style="font-size: 13px; padding: 8px 18px;" onclick="switchTab('tab-dns')">🌐 DNS Intelligence & Query Log</button>
        <button id="tab-btn-payloads" class="filter-btn" style="font-size: 13px; padding: 8px 18px;" onclick="switchTab('tab-payloads')">🔗 Suspicious Links & Payload Audit</button>
    </div>

    <!-- Tab 1 Content: Alerts & Attack Chains -->
    <div id="tab-alerts" class="tab-content">
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
    </div>

    <!-- Tab 2 Content: DNS Intelligence -->
    <div id="tab-dns" class="tab-content" style="display: none;">
        <div class="section-title">
            <span>🌐 DNS Query Intelligence & Domain Reputation Breakdown</span>
        </div>
        <div class="alert-table-container">
            <table>
                <thead>
                    <tr>
                        <th>Queried Domain (QNAME)</th>
                        <th>Record Type</th>
                        <th>Query Frequency</th>
                        <th>Shannon Entropy H(S)</th>
                        <th>Requesting Client IP</th>
                        <th>Threat Status</th>
                    </tr>
                </thead>
                <tbody id="dns-tbody"></tbody>
            </table>
        </div>
    </div>

    <!-- Tab 3 Content: Suspicious Links & Payloads -->
    <div id="tab-payloads" class="tab-content" style="display: none;">
        <div class="section-title">
            <span>🔗 Suspicious Links, HTTP URLs & Payload Audit Log</span>
        </div>
        <div class="alert-table-container">
            <table>
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Target IP:Port</th>
                        <th>HTTP Method / Auth</th>
                        <th>Extracted Link / URL / File Signature</th>
                        <th>User-Agent / Payload Header</th>
                        <th>Threat Category</th>
                    </tr>
                </thead>
                <tbody id="payloads-tbody"></tbody>
            </table>
        </div>
    </div>

    <script>
        let currentData = __DATA_JSON__;
        let activeData = currentData;
        let allAlerts = activeData.alerts || [];
        let currentSeverity = 'ALL';

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
            document.getElementById(tabId).style.display = 'block';

            document.getElementById('tab-btn-alerts').classList.remove('active');
            document.getElementById('tab-btn-dns').classList.remove('active');
            document.getElementById('tab-btn-payloads').classList.remove('active');

            if (tabId === 'tab-alerts') document.getElementById('tab-btn-alerts').classList.add('active');
            if (tabId === 'tab-dns') document.getElementById('tab-btn-dns').classList.add('active');
            if (tabId === 'tab-payloads') document.getElementById('tab-btn-payloads').classList.add('active');
        }

        function renderDashboard(data) {
            activeData = data;
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

            // Render DNS Intelligence Table
            const dnsList = correlation.dns_report || [];
            const dnsTbody = document.getElementById('dns-tbody');
            dnsTbody.innerHTML = '';
            if (dnsList.length === 0) {
                dnsTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">No DNS telemetry recorded in this session.</td></tr>';
            } else {
                dnsList.forEach(item => {
                    const tr = document.createElement('tr');
                    let statusBadge = `<span class="badge badge-INFO">${item.threat_status}</span>`;
                    if (item.threat_status.includes('DGA') || item.threat_status.includes('TUNNEL')) {
                        statusBadge = `<span class="badge badge-CRITICAL">${item.threat_status}</span>`;
                    }
                    tr.innerHTML = `
                        <td style="font-family: monospace; font-weight: 700; color: var(--accent-blue);">${item.domain}</td>
                        <td><span class="badge badge-LOW">${item.qtype}</span></td>
                        <td>${item.count}</td>
                        <td style="font-weight: 700;">${item.entropy} bits/char</td>
                        <td>${item.client_ip || 'N/A'}</td>
                        <td>${statusBadge}</td>
                    `;
                    dnsTbody.appendChild(tr);
                });
            }

            // Render Suspicious Links & Payloads Table
            const payloadList = correlation.suspicious_payloads || [];
            const payloadTbody = document.getElementById('payloads-tbody');
            payloadTbody.innerHTML = '';
            if (payloadList.length === 0) {
                payloadTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">No suspicious links or cleartext payload anomalies extracted.</td></tr>';
            } else {
                payloadList.forEach(p => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${p.source_ip}</td>
                        <td>${p.target_ip}:${p.target_port}</td>
                        <td><span class="badge badge-HIGH">${p.method}</span></td>
                        <td style="font-family: monospace; color: #a7f3d0; word-break: break-all;">${p.url_or_path}</td>
                        <td style="font-size: 12px; color: var(--text-muted);">${p.user_agent}</td>
                        <td><span class="badge badge-CRITICAL">${p.threat_category}</span></td>
                    `;
                    payloadTbody.appendChild(tr);
                });
            }

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

        async function fetchHistory() {
            try {
                const res = await fetch('/api/history');
                const profiles = await res.json();
                const sel = document.getElementById('history-select');
                sel.innerHTML = '<option value="CURRENT">-- Current Active Session --</option>';

                profiles.forEach(p => {
                    const opt = document.createElement('option');
                    opt.value = p.profile_id;
                    opt.innerText = `[${p.profile_id}] ${p.filename} (${p.total_alerts} Alerts) - ${p.created_at}`;
                    sel.appendChild(opt);
                });
            } catch (err) {
                console.error("Failed loading scan history", err);
            }
        }

        async function onProfileSelect(profId) {
            if (profId === 'CURRENT') {
                renderDashboard(currentData);
                return;
            }

            try {
                const res = await fetch(`/api/history?profile_id=${profId}`);
                const data = await res.json();
                renderDashboard(data);
            } catch (err) {
                alert('Error loading profile: ' + profId);
            }
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
                    const uploadPct = (e.loaded / e.total) * 50;
                    updateProgress(uploadPct, `Uploading (${Math.round(uploadPct * 2)}%)...`);
                }
            };

            xhr.onload = function() {
                if (xhr.status === 200) {
                    updateProgress(85, "Executing 12 Forensic Triage Engines...");
                    setTimeout(() => {
                        updateProgress(100, "Analysis Complete!");
                        title.innerText = `✅ Triage Complete: '${file.name}'`;
                        const result = JSON.parse(xhr.responseText);
                        renderDashboard(result);
                        fetchHistory();
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
        fetchHistory();
    </script>
</body>
</html>
"""


def run_triage_on_pcap_file(filepath: str) -> Dict[str, Any]:
    """Runs all 12 triage engines on a PCAP file and returns full JSON report dict."""
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
        FileCarverModule(),
        SmbAuditModule(),
        DnsTunnelModule(),
    ]

    collected_alerts: List[Alert] = []

    def handle_flow_close(closed_flow):
        for m in modules:
            alerts = m.on_flow_close(closed_flow)
            if alerts:
                collected_alerts.extend(alerts)

    flow_table.register_evict_callback(handle_flow_close)

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

    result = {
        "metadata": {"summary": summary_stats},
        "attack_chain_correlation": correlation_data,
        "alerts": [a.to_dict() for a in all_alerts],
    }

    # Automatically save profile into scan history
    hist = HistoryManager()
    hist.save_profile(filepath, result)

    return result


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for NetSpector Pro local web dashboard with Drag & Drop PCAP upload and History API."""

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

        elif path == "/api/history":
            hist = HistoryManager()
            profile_id = query.get("profile_id", [""])[0]

            if profile_id:
                prof_data = hist.get_profile(profile_id)
                if prof_data:
                    self._send_json(prof_data)
                else:
                    self._send_json({"error": f"Profile '{profile_id}' not found"}, code=404)
            else:
                profiles_list = hist.list_profiles()
                self._send_json(profiles_list)

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

        elif path in ("/netshark-logo.svg", "/netshark-mark.svg", "/favicon.svg", "/favicon.ico"):
            target_file = path.lstrip("/")
            if target_file == "favicon.ico":
                target_file = "favicon.svg"
            svg_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), target_file)
            if os.path.exists(svg_file_path):
                with open(svg_file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "File Not Found")

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

                HistoryManager().save_profile("Uploaded PCAP", result_dict)

                self._send_json(result_dict)
            except Exception as e:
                self._send_json({"error": f"Failed to triage uploaded PCAP: {e}"}, code=500)
        else:
            self.send_error(404, "Not Found")

    def do_DELETE(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == "/api/history":
            profile_id = query.get("profile_id", [""])[0]
            if profile_id:
                hist = HistoryManager()
                success = hist.delete_profile(profile_id)
                if success:
                    self._send_json({"status": "success", "message": f"Profile '{profile_id}' deleted"})
                else:
                    self._send_json({"error": f"Failed to delete profile '{profile_id}'"}, code=500)
            else:
                self._send_json({"error": "profile_id required"}, code=400)
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
    print("[+] Scan History Profiles active on dashboard!")
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
