"""Module 8: HTTP Profiling & Web Shell Auditor."""

import re
from typing import Any, Dict, List, Optional, Tuple
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


SCRIPT_USER_AGENTS = [
    "curl/", "python-requests", "go-http-client", "powershell",
    "nikto", "sqlmap", "nmap", "wget/", "python-urllib", "libwww-perl"
]

DANGEROUS_METHODS = {"PUT", "PROPFIND", "DELETE", "SEARCH", "TRACE", "CONNECT"}

WEBSHELL_PATTERNS = [
    r"c99\.php", r"r57\.php", r"cmd\.php", r"shell\.php",
    r"\?cmd=", r"\?exec=", r"eval-stdin", r"passthru\(", r"system\("
]


class HttpAuditModule(BaseModule):
    """Audits HTTP requests for script-based user agents, web shell execution signatures, and dangerous HTTP methods."""

    def __init__(self):
        super().__init__("http_audit")
        self.seen_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        pass

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        if flow.flow_id in self.seen_flows:
            return alerts

        # Inspect DNS or payload strings if HTTP ports (80, 8080, 8000)
        if pkt.dst_port not in (80, 8080, 8000) and pkt.src_port not in (80, 8080, 8000):
            return alerts

        payload_text = ""
        try:
            if hasattr(pkt, "_raw_payload") and pkt._raw_payload:
                payload_text = pkt._raw_payload.decode("ascii", errors="ignore")
        except Exception:
            pass

        if not payload_text and pkt.dns_qname:
            payload_text = f"GET /{pkt.dns_qname} HTTP/1.1\r\nHost: {pkt.dns_qname}\r\n\r\n"

        if not payload_text:
            return alerts

        # Parse HTTP request line & headers
        method, uri, user_agent = self._parse_http_request(payload_text)
        if not method:
            return alerts

        # 1. Web Shell Execution Query Detection
        for pat in WEBSHELL_PATTERNS:
            if re.search(pat, uri, re.IGNORECASE):
                self.seen_flows.add(flow.flow_id)
                alerts.append(Alert(
                    alert_id=f"ALT-WEBSHELL-{abs(hash(flow.flow_id)) % 1000000:06d}",
                    rule_id="RULE-HTTP-WEBSHELL-01",
                    title="Potential Web Shell Execution Attempt Detected",
                    description=f"HTTP request from {pkt.src_ip} contains web shell URI pattern: '{uri[:60]}'.",
                    severity=Severity.HIGH,
                    stage=KillChainStage.INITIAL_ACCESS,
                    source_ip=pkt.src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol="HTTP",
                    timestamp_us=pkt.ts_us,
                    flow_id=pkt.flow_id,
                    packet_refs=[pkt],
                    arithmetic_proof={
                        "metric": "HTTP Web Shell Signature Match",
                        "http_method": method,
                        "request_uri": uri,
                        "signature_matched": pat,
                        "user_agent": user_agent or "<none>",
                    },
                ))
                break

        # 2. Automated Script / Scanner User-Agent Detection
        if user_agent:
            ua_lower = user_agent.lower()
            for agent in SCRIPT_USER_AGENTS:
                if agent in ua_lower:
                    if flow.flow_id not in self.seen_flows:
                        self.seen_flows.add(flow.flow_id)
                        alerts.append(Alert(
                            alert_id=f"ALT-SCRIPTUA-{abs(hash(flow.flow_id)) % 1000000:06d}",
                            rule_id="RULE-HTTP-USERAGENT-01",
                            title=f"Automated Script / Scanner User-Agent: {user_agent[:30]}",
                            description=f"HTTP request from {pkt.src_ip} uses automated tool User-Agent string '{user_agent}'.",
                            severity=Severity.MEDIUM,
                            stage=KillChainStage.RECONNAISSANCE,
                            source_ip=pkt.src_ip,
                            target_ip=pkt.dst_ip,
                            source_port=pkt.src_port,
                            target_port=pkt.dst_port,
                            protocol="HTTP",
                            timestamp_us=pkt.ts_us,
                            flow_id=pkt.flow_id,
                            packet_refs=[pkt],
                            arithmetic_proof={
                                "metric": "Script-Based User-Agent Match",
                                "matched_agent_keyword": agent,
                                "full_user_agent": user_agent,
                                "http_method": method,
                                "request_uri": uri,
                            },
                        ))
                    break

        # 3. Non-Standard / Dangerous HTTP Method Detection
        if method in DANGEROUS_METHODS:
            if flow.flow_id not in self.seen_flows:
                self.seen_flows.add(flow.flow_id)
                alerts.append(Alert(
                    alert_id=f"ALT-HTTPMETHOD-{abs(hash(flow.flow_id)) % 1000000:06d}",
                    rule_id="RULE-HTTP-METHOD-01",
                    title=f"Dangerous Non-Standard HTTP Method: {method}",
                    description=f"HTTP request from {pkt.src_ip} issued non-standard HTTP method '{method}'.",
                    severity=Severity.MEDIUM,
                    stage=KillChainStage.DEFENSE_EVASION,
                    source_ip=pkt.src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol="HTTP",
                    timestamp_us=pkt.ts_us,
                    flow_id=pkt.flow_id,
                    packet_refs=[pkt],
                    arithmetic_proof={
                        "metric": "Dangerous HTTP Method Audit",
                        "http_method": method,
                        "request_uri": uri,
                        "user_agent": user_agent or "<none>",
                    },
                ))

        return alerts

    def _parse_http_request(self, text: str) -> Tuple[Optional[str], str, Optional[str]]:
        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return None, "", None

        first_line = lines[0].strip()
        parts = first_line.split(" ")
        if len(parts) < 2:
            return None, "", None

        method = parts[0].upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PROPFIND", "SEARCH", "TRACE", "CONNECT"):
            return None, "", None

        uri = parts[1]
        user_agent = None

        for line in lines[1:]:
            if line.lower().startswith("user-agent:"):
                user_agent = line.split(":", 1)[1].strip()
                break

        return method, uri, user_agent

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
