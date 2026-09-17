"""Base detection module contract and registry."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from netshark.model import Alert, Flow, PacketRef


class BaseModule(ABC):
    """Abstract contract interface for all NetSpector Pro detection modules."""

    def __init__(self, name: str):
        self.name = name
        self.config: Dict[str, Any] = {}
        self.alerts: List[Alert] = []

    @abstractmethod
    def configure(self, rules: Dict[str, Any]):
        """Configures module thresholds and options from rule dictionary."""
        pass

    @abstractmethod
    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        """Processes an incoming packet and associated flow state."""
        return []

    @abstractmethod
    def on_flow_close(self, flow: Flow) -> List[Alert]:
        """Handles flow eviction or explicit TCP connection termination."""
        return []

    @abstractmethod
    def finalize(self) -> List[Alert]:
        """Finalizes batch analysis when capture stream ends."""
        return []


from netshark.modules.beacon import C2BeaconModule
from netshark.modules.credentials import CleartextCredentialsModule
from netshark.modules.lateral import LateralMovementModule
from netshark.modules.exfil import ExfiltrationModule
from netshark.modules.entropy import DnsEntropyModule
from netshark.modules.sweep import SubnetSweepModule
from netshark.modules.http_audit import HttpAuditModule
from netshark.modules.ja3_fingerprint import Ja3FingerprintModule
from netshark.modules.tcpstate import TcpStateModule
from netshark.modules.file_carver import FileCarverModule
from netshark.modules.smb_audit import SmbAuditModule
from netshark.modules.dns_tunnel import DnsTunnelModule

__all__ = [
    "BaseModule",
    "C2BeaconModule",
    "CleartextCredentialsModule",
    "LateralMovementModule",
    "ExfiltrationModule",
    "DnsEntropyModule",
    "SubnetSweepModule",
    "HttpAuditModule",
    "Ja3FingerprintModule",
    "TcpStateModule",
    "FileCarverModule",
    "SmbAuditModule",
    "DnsTunnelModule",
]
