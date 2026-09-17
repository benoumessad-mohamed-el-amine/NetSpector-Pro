"""Module 3: Cleartext Credential Sniffer for unencrypted protocols (HTTP, FTP, Telnet, POP3, SMTP)."""

import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netshark.modules import BaseModule


HTTP_AUTH_BASIC_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
FTP_USER_RE = re.compile(r"USER\s+([^\r\n]+)", re.IGNORECASE)
FTP_PASS_RE = re.compile(r"PASS\s+([^\r\n]+)", re.IGNORECASE)
POP3_USER_RE = re.compile(r"USER\s+([^\r\n]+)", re.IGNORECASE)
POP3_PASS_RE = re.compile(r"PASS\s+([^\r\n]+)", re.IGNORECASE)
SMTP_AUTH_PLAIN_RE = re.compile(r"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)


class CleartextCredentialsModule(BaseModule):
    """Scans unencrypted network payloads for exposed cleartext credentials and authentication headers."""

    def __init__(self):
        super().__init__("credentials")
        self.seen_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        pass

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        alerts: List[Alert] = []

        if flow.flow_id in self.seen_flows:
            return alerts

        # Check payload presence
        if pkt.payload_len <= 0:
            return alerts

        # We inspect payload if port is associated with legacy cleartext protocols (80, 8080, 21, 23, 110, 25, 587)
        target_ports = {80, 8080, 8000, 21, 23, 110, 25, 587}
        if pkt.dst_port not in target_ports and pkt.src_port not in target_ports:
            return alerts

        # Attempt extracting payload text
        payload_text = ""
        try:
            # We fetch sample payload bytes from flow packet ref context if available
            # Note: PacketRef holds metadata; payload inspection occurs during parsing or stream window
            # Let's inspect dns_qname or raw packet payload if accessible
            if hasattr(pkt, "_raw_payload") and pkt._raw_payload:
                payload_text = pkt._raw_payload.decode("ascii", errors="ignore")
        except Exception:
            pass

        if not payload_text:
            return alerts

        cred_type, username, password = self._extract_credentials(pkt.dst_port, pkt.src_port, payload_text)
        if cred_type:
            self.seen_flows.add(flow.flow_id)

            masked_pass = "*" * len(password) if password else "<none>"

            alert = Alert(
                alert_id=f"ALT-CRED-{abs(hash(flow.flow_id)) % 1000000:06d}",
                rule_id="RULE-CRED-CLEARTEXT-01",
                title=f"Exposed Cleartext Credentials Detected ({cred_type})",
                description=(
                    f"Flow {flow.flow_id} transmitted exposed cleartext authentication credentials "
                    f"over unencrypted {cred_type} protocol (User: '{username}')."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.CREDENTIAL_ACCESS,
                source_ip=pkt.src_ip,
                target_ip=pkt.dst_ip,
                source_port=pkt.src_port,
                target_port=pkt.dst_port,
                protocol=cred_type,
                timestamp_us=pkt.ts_us,
                flow_id=pkt.flow_id,
                packet_refs=[pkt],
                arithmetic_proof={
                    "metric": "Unencrypted Cleartext Credential Extraction",
                    "protocol": cred_type,
                    "target_port": pkt.dst_port,
                    "extracted_user": username,
                    "extracted_pass_masked": masked_pass,
                    "payload_offset": pkt.file_offset,
                },
            )
            alerts.append(alert)

        return alerts

    def _extract_credentials(self, dst_port: int, src_port: int, text: str) -> Tuple[Optional[str], str, str]:
        # 1. HTTP Basic Auth
        m_http = HTTP_AUTH_BASIC_RE.search(text)
        if m_http:
            b64_str = m_http.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    u, p = decoded.split(":", 1)
                    return "HTTP Basic Auth", u, p
            except Exception:
                pass

        # 2. FTP
        m_ftp_user = FTP_USER_RE.search(text)
        m_ftp_pass = FTP_PASS_RE.search(text)
        if m_ftp_user or m_ftp_pass:
            u = m_ftp_user.group(1) if m_ftp_user else "<unknown>"
            p = m_ftp_pass.group(1) if m_ftp_pass else "<unknown>"
            return "FTP", u, p

        # 3. POP3
        m_pop_user = POP3_USER_RE.search(text)
        m_pop_pass = POP3_PASS_RE.search(text)
        if m_pop_user and m_pop_pass and (dst_port == 110 or src_port == 110):
            return "POP3", m_pop_user.group(1), m_pop_pass.group(1)

        # 4. SMTP Auth Plain
        m_smtp = SMTP_AUTH_PLAIN_RE.search(text)
        if m_smtp:
            b64_str = m_smtp.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                parts = decoded.split("\x00")
                if len(parts) >= 3:
                    return "SMTP AUTH PLAIN", parts[1], parts[2]
            except Exception:
                pass

        return None, "", ""

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
