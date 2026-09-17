"""Unit tests for Attack Chain Timeline Stitcher."""

import unittest
from netshark.correlate import AttackChainStitcher
from netshark.model import Alert, KillChainStage, Severity


class TestCorrelate(unittest.TestCase):
    def test_timeline_stitching_and_plausibility(self):
        a1 = Alert(
            "ALT-01", "R1", "Scan", "Recon scan", Severity.MEDIUM,
            KillChainStage.RECONNAISSANCE, "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 1600000000000000
        )
        a2 = Alert(
            "ALT-02", "R2", "Lateral", "SMB pivot", Severity.HIGH,
            KillChainStage.LATERAL_MOVEMENT, "10.0.0.1", "10.0.0.3", 1234, 445, "TCP", 1600000100000000
        )
        a3 = Alert(
            "ALT-03", "R3", "C2", "Beaconing", Severity.HIGH,
            KillChainStage.COMMAND_AND_CONTROL, "10.0.0.1", "1.2.3.4", 1234, 443, "TCP", 1600000200000000
        )

        stitcher = AttackChainStitcher([a1, a2, a3])
        result = stitcher.correlate()

        self.assertGreaterEqual(result["total_correlated_entities"], 1)
        top_entity = result["entities"][0]
        self.assertEqual(top_entity["entity_ip"], "10.0.0.1")
        self.assertGreater(top_entity["plausibility_score"], 50.0)


if __name__ == "__main__":
    unittest.main()
