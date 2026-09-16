"""Attack Chain Timeline Stitcher and Entity Correlation Engine."""

from typing import Any, Dict, List
from netspector.model import Alert, KillChainStage


STAGE_ORDER = {
    KillChainStage.RECONNAISSANCE: 1,
    KillChainStage.INITIAL_ACCESS: 2,
    KillChainStage.EXECUTION: 3,
    KillChainStage.PERSISTENCE: 4,
    KillChainStage.PRIVILEGE_ESCALATION: 5,
    KillChainStage.DEFENSE_EVASION: 6,
    KillChainStage.CREDENTIAL_ACCESS: 7,
    KillChainStage.DISCOVERY: 8,
    KillChainStage.LATERAL_MOVEMENT: 9,
    KillChainStage.COMMAND_AND_CONTROL: 10,
    KillChainStage.EXFILTRATION: 11,
}


class EntityTimeline:
    """Represents a correlated timeline of alerts for a specific host entity."""

    def __init__(self, entity_ip: str):
        self.entity_ip = entity_ip
        self.alerts: List[Alert] = []

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)

    def finalize_timeline(self) -> Dict[str, Any]:
        """Sorts alerts chronologically and calculates attack chain plausibility score."""
        self.alerts.sort(key=lambda a: a.timestamp_us)

        stages_present = []
        stage_order_indices = []

        for a in self.alerts:
            st = a.stage
            if st.value not in stages_present:
                stages_present.append(st.value)
                stage_order_indices.append(STAGE_ORDER.get(st, 99))

        # Calculate Plausibility Score
        # 1. Base score based on stage coverage count
        distinct_stages_count = len(stages_present)
        coverage_score = min(distinct_stages_count / 5.0, 1.0) * 60.0

        # 2. Chronological alignment bonus (are stages strictly monotonic/increasing in kill chain order?)
        is_monotonic = all(
            stage_order_indices[i] <= stage_order_indices[i + 1]
            for i in range(len(stage_order_indices) - 1)
        )
        alignment_score = 40.0 if (is_monotonic and len(stage_order_indices) > 1) else 15.0

        plausibility_score = round(coverage_score + alignment_score, 1)

        return {
            "entity_ip": self.entity_ip,
            "total_alerts": len(self.alerts),
            "stages_covered": stages_present,
            "plausibility_score": plausibility_score,
            "chronological_alignment": "High" if is_monotonic else "Moderate",
            "timeline": [a.to_dict() for a in self.alerts],
        }


class AttackChainStitcher:
    """Stitches correlated forensic alerts into entity-centric attack chain narratives."""

    def __init__(self, alerts: List[Alert]):
        self.alerts = alerts

    def correlate(self) -> Dict[str, Any]:
        entities: Dict[str, EntityTimeline] = {}

        for alert in self.alerts:
            # Associate alert with source host entity
            if alert.source_ip:
                if alert.source_ip not in entities:
                    entities[alert.source_ip] = EntityTimeline(alert.source_ip)
                entities[alert.source_ip].add_alert(alert)

            # Associate alert with target host entity if different
            if alert.target_ip and alert.target_ip != alert.source_ip:
                if alert.target_ip not in entities:
                    entities[alert.target_ip] = EntityTimeline(alert.target_ip)
                entities[alert.target_ip].add_alert(alert)

        correlated_entities = []
        for ip, timeline in entities.items():
            narrative = timeline.finalize_timeline()
            correlated_entities.append(narrative)

        # Sort entities by plausibility score descending
        correlated_entities.sort(key=lambda e: e["plausibility_score"], reverse=True)

        return {
            "total_correlated_entities": len(correlated_entities),
            "entities": correlated_entities,
        }
