"""Module 11: SMB / RPC Named Pipe Auditor."""

from typing import Any, Dict, List
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netshark.modules import BaseModule


HIGH_RISK_PIPES = {
    "svcctl": ("Service Control Manager (Remote Service Execution / PsExec)", Severity.CRITICAL, KillChainStage.LATERAL_MOVEMENT),
    "samr": ("Security Account Manager Remote Protocol (SAM Credential Dumping)", Severity.HIGH, KillChainStage.CREDENTIAL_ACCESS),
    "lsarpc": ("Local Security Authority RPC (LSA / Mimikatz Access)", Severity.HIGH, KillChainStage.CREDENTIAL_ACCESS),
    "atsvc": ("Task Scheduler RPC (Remote Scheduled Task Creation)", Severity.HIGH, KillChainStage.EXECUTION),
    "epmapper": ("RPC Endpoint Mapper Enumeration", Severity.LOW, KillChainStage.RECONNAISSANCE),
    "wkssvc": ("Workstation Service RPC", Severity.MEDIUM, KillChainStage.DISCOVERY),
    "srvsvc": ("Server Service RPC", Severity.MEDIUM, KillChainStage.DISCOVERY),
}

ADMIN_SHARES = {
    "admin$": ("Administrative Management Share Access", Severity.HIGH, KillChainStage.LATERAL_MOVEMENT),
    "c$": ("Default System C: Drive Administrative Share Access", Severity.HIGH, KillChainStage.LATERAL_MOVEMENT),
    "ipc$": ("Inter-Process Communication Share Access", Severity.LOW, KillChainStage.RECONNAISSANCE),
}


class SmbAuditModule(BaseModule):
    """Deep-dives into SMB/RPC sessions to detect access to dangerous exploitation named pipes and admin shares."""

    def __init__(self):
        super().__init__("smb_audit")
        self.enabled: bool = True
        self.seen_alerts: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("smb_audit", {})
        self.enabled = cfg.get("enabled", True)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        if not self.enabled:
            return []

        # Only evaluate SMB / NetBIOS / DCE-RPC traffic ports
        if flow.endpoint_a_port not in (445, 139, 135) and flow.endpoint_b_port not in (445, 139, 135):
            return []

        payload = pkt._raw_payload
        if not payload:
            return []

        payload_lower = payload.lower()

        # Check for High-Risk Named Pipes
        for pipe_key, (pipe_desc, sev, stage) in HIGH_RISK_PIPES.items():
            pipe_pattern = f"pipe\\{pipe_key}".encode("latin1")
            pipe_pattern_raw = pipe_key.encode("latin1")

            if pipe_pattern in payload_lower or pipe_pattern_raw in payload_lower:
                alert_key = f"{flow.endpoint_a_ip}->{flow.endpoint_b_ip}:{pipe_key}"
                if alert_key in self.seen_alerts:
                    continue
                self.seen_alerts.add(alert_key)

                alert = Alert(
                    alert_id=f"ALT-SMB-PIPE-{abs(hash(alert_key)) % 1000000:06d}",
                    rule_id="RULE-SMB-PIPE-01",
                    title=f"High-Risk SMB Named Pipe Accessed ({pipe_key})",
                    description=(
                        f"Host {pkt.src_ip} opened SMB named pipe '\\pipe\\{pipe_key}' on target {pkt.dst_ip}. "
                        f"Function: {pipe_desc}."
                    ),
                    severity=sev,
                    stage=stage,
                    source_ip=pkt.src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol="TCP/SMB",
                    timestamp_us=pkt.ts_us,
                    flow_id=flow.flow_id,
                    packet_refs=[pkt],
                    arithmetic_proof={
                        "metric": "SMB Named Pipe String Inspection",
                        "named_pipe": f"\\pipe\\{pipe_key}",
                        "pipe_function": pipe_desc,
                        "smb_port": pkt.dst_port,
                        "flow_id": flow.flow_id,
                    },
                )
                return [alert]

        # Check for Admin Share Access (ADMIN$, C$)
        for share_key, (share_desc, sev, stage) in ADMIN_SHARES.items():
            share_pattern = f"\\\\{share_key}".encode("latin1")
            share_pattern_raw = share_key.encode("latin1")

            if share_pattern in payload_lower or (b"\\\\\\" in payload_lower and share_pattern_raw in payload_lower):
                alert_key = f"{flow.endpoint_a_ip}->{flow.endpoint_b_ip}:{share_key}"
                if alert_key in self.seen_alerts:
                    continue
                self.seen_alerts.add(alert_key)

                alert = Alert(
                    alert_id=f"ALT-SMB-SHARE-{abs(hash(alert_key)) % 1000000:06d}",
                    rule_id="RULE-SMB-SHARE-01",
                    title=f"Administrative Share Tree Connect ({share_key.upper()})",
                    description=(
                        f"Host {pkt.src_ip} requested SMB Tree Connect to administrative share '{share_key.upper()}' "
                        f"on target {pkt.dst_ip}."
                    ),
                    severity=sev,
                    stage=stage,
                    source_ip=pkt.src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol="TCP/SMB",
                    timestamp_us=pkt.ts_us,
                    flow_id=flow.flow_id,
                    packet_refs=[pkt],
                    arithmetic_proof={
                        "metric": "SMB Admin Share Inspection",
                        "share_name": share_key.upper(),
                        "share_desc": share_desc,
                        "smb_port": pkt.dst_port,
                        "flow_id": flow.flow_id,
                    },
                )
                return [alert]

        return []

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
