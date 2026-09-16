"""Module 1: C2 Beaconing Detection based on IAT variance, CoV, and MAD analysis."""

import math
from typing import Any, Dict, List
from netspector.model import Alert, Flow, KillChainStage, PacketRef, Severity
from netspector.modules import BaseModule


class C2BeaconModule(BaseModule):
    """Detects periodic Command & Control (C2) beaconing patterns using robust statistical timing metrics."""

    def __init__(self):
        super().__init__("c2_beacon")
        self.min_samples: int = 12
        self.max_cov: float = 0.20
        self.max_mad_ratio: float = 0.25
        self.min_duration_sec: float = 10.0
        self.evaluated_flows: set[str] = set()

    def configure(self, rules: Dict[str, Any]):
        cfg = rules.get("beacon", {})
        self.min_samples = cfg.get("min_samples", 12)
        self.max_cov = cfg.get("max_cov", 0.20)
        self.max_mad_ratio = cfg.get("max_mad_ratio", 0.25)
        self.min_duration_sec = cfg.get("min_duration_sec", 10.0)

    def on_packet(self, pkt: PacketRef, flow: Flow) -> List[Alert]:
        # We evaluate flows as packets arrive once they pass min_samples gate
        if flow.flow_id in self.evaluated_flows:
            return []

        if flow.packet_count >= self.min_samples and flow.duration_sec >= self.min_duration_sec:
            alerts = self._analyze_flow(flow)
            if alerts:
                self.evaluated_flows.add(flow.flow_id)
            return alerts
        return []

    def on_flow_close(self, flow: Flow) -> List[Alert]:
        if flow.flow_id in self.evaluated_flows:
            return []
        alerts = self._analyze_flow(flow)
        if alerts:
            self.evaluated_flows.add(flow.flow_id)
        return alerts

    def finalize(self) -> List[Alert]:
        return []

    def _analyze_flow(self, flow: Flow) -> List[Alert]:
        if flow.packet_count < self.min_samples:
            return []

        # Calculate Inter-Arrival Times (IAT) in seconds
        timestamps = [p.ts_us / 1_000_000.0 for p in flow.packet_refs]
        timestamps.sort()

        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        if not iats:
            return []

        n = len(iats)
        mean_iat = sum(iats) / n
        if mean_iat <= 0.001:  # Filter out instantaneous bursts / local loops
            return []

        variance = sum((x - mean_iat) ** 2 for x in iats) / n
        stddev = math.sqrt(variance)
        cov = stddev / mean_iat  # Coefficient of Variation

        # Calculate Median and Median Absolute Deviation (MAD)
        sorted_iats = sorted(iats)
        mid = n // 2
        median_iat = sorted_iats[mid] if n % 2 != 0 else (sorted_iats[mid - 1] + sorted_iats[mid]) / 2.0

        if median_iat <= 0.001:
            return []

        abs_deviations = sorted([abs(x - median_iat) for x in iats])
        mad = abs_deviations[mid] if n % 2 != 0 else (abs_deviations[mid - 1] + abs_deviations[mid]) / 2.0
        mad_ratio = mad / median_iat

        # Evaluate against low-variance beacon criteria
        if cov <= self.max_cov and mad_ratio <= self.max_mad_ratio:
            alert = Alert(
                alert_id=f"ALT-BEACON-{abs(hash(flow.flow_id)) % 1000000:06d}",
                rule_id="RULE-C2-BEACON-01",
                title="Command & Control (C2) Beaconing Pattern Detected",
                description=(
                    f"Flow {flow.flow_id} demonstrates highly regular periodic inter-arrival timing "
                    f"characteristic of automated C2 implant beaconing."
                ),
                severity=Severity.HIGH,
                stage=KillChainStage.COMMAND_AND_CONTROL,
                source_ip=flow.endpoint_a_ip,
                target_ip=flow.endpoint_b_ip,
                source_port=flow.endpoint_a_port,
                target_port=flow.endpoint_b_port,
                protocol=str(flow.protocol),
                timestamp_us=flow.last_ts_us,
                flow_id=flow.flow_id,
                packet_refs=list(flow.packet_refs),
                arithmetic_proof={
                    "metric": "Inter-Arrival Time (IAT) Statistical Regularity",
                    "sample_count_N": n + 1,
                    "sample_gate_min_N": self.min_samples,
                    "mean_iat_sec": round(mean_iat, 4),
                    "stddev_iat_sec": round(stddev, 4),
                    "cov_calculated": round(cov, 4),
                    "cov_threshold": self.max_cov,
                    "median_iat_sec": round(median_iat, 4),
                    "mad_sec": round(mad, 4),
                    "mad_ratio_calculated": round(mad_ratio, 4),
                    "mad_ratio_threshold": self.max_mad_ratio,
                    "formula_cov": "CoV = stddev / mean",
                    "formula_mad": "MAD = median(|IAT_i - median(IAT)|)",
                    "passed_gate": True,
                },
            )
            return [alert]

        return []
