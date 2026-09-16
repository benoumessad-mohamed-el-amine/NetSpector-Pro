"""Base detection module contract and registry."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from netspector.model import Alert, Flow, PacketRef


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
