"""Module 10: File Carving & Magic Byte Inspector for Unencrypted Streams."""

from typing import Any, Dict, List
from netshark.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netshark.modules import BaseModule


MAGIC_BYTES_MAP = {
    b"MZ": ("Windows PE Executable (.exe / .dll)", Severity.HIGH, KillChainStage.EXECUTION),
    b"\x7fELF": ("Linux ELF Executable binary", Severity.HIGH, KillChainStage.EXECUTION),
    b"PK\x03\x04": ("ZIP Archive / Office Open XML Container", Severity.MEDIUM, KillChainStage.EXECUTION),
    b"%PDF-": ("PDF Document", Severity.MEDIUM, KillChainStage.INITIAL_ACCESS),
    b"Rar!\x1a\x07": ("RAR Archive", Severity.MEDIUM, KillChainStage.EXECUTION),
    b"7z\xbc\xaf\x27\x1c": ("7-Zip Archive", Severity.MEDIUM, KillChainStage.EXECUTION),
    b"\xca\xfe\xba\xbe": ("Java Class File / Mach-O Binary", Severity.HIGH, KillChainStage.EXECUTION),
}

# Encrypted / Secure transport ports to bypass to prevent FP on encrypted payloads
ENCRYPTED_PORTS = {443, 8443, 993, 995, 465, 22}


class FileCarverModule(BaseModule):
    """Inspects unencrypted stream payloads for embedded executable binaries and archive file signatures."""

    def __init__(self):
        super().__init__("file_carver")
        self.enabled: bool = True
        self.seen_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("file_carver", {})
        self.enabled = cfg.get("enabled", True)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        if not self.enabled or flow.flow_id in self.seen_flows:
            return []

        # Skip encrypted TLS/SSH ports
        if flow.endpoint_a_port in ENCRYPTED_PORTS or flow.endpoint_b_port in ENCRYPTED_PORTS:
            return []

        payload = pkt._raw_payload
        if not payload or len(payload) < 4:
            return []

        # Search for magic bytes at offset 0 or within payload head
        head = payload[:512]
        for magic, (file_desc, sev, stage) in MAGIC_BYTES_MAP.items():
            offset = head.find(magic)
            if offset != -1:
                self.seen_flows.add(flow.flow_id)
                hex_magic = magic.hex()

                alert = Alert(
                    alert_id=f"ALT-CARVE-{abs(hash(flow.flow_id + magic.decode('latin1', errors='ignore'))) % 1000000:06d}",
                    rule_id="RULE-FILE-MAGIC-01",
                    title=f"Binary File Signature Detected ({file_desc})",
                    description=(
                        f"Unencrypted stream flow {flow.flow_id} contains embedded file magic header "
                        f"'{hex_magic}' at payload offset {offset}, indicating binary transfer over cleartext channel."
                    ),
                    severity=sev,
                    stage=stage,
                    source_ip=pkt.src_ip,
                    target_ip=pkt.dst_ip,
                    source_port=pkt.src_port,
                    target_port=pkt.dst_port,
                    protocol=str(flow.protocol),
                    timestamp_us=pkt.ts_us,
                    flow_id=flow.flow_id,
                    packet_refs=[pkt],
                    arithmetic_proof={
                        "metric": "Magic Byte Header Inspection",
                        "detected_file_type": file_desc,
                        "magic_bytes_hex": hex_magic,
                        "magic_bytes_ascii": magic.decode("latin1", errors="replace"),
                        "payload_offset": offset,
                        "flow_id": flow.flow_id,
                        "unencrypted_channel": True,
                    },
                )
                return [alert]

        return []

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        return []

    def finalize(self) -> List[Alert]:
        return []
