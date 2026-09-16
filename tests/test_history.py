"""Unit tests for HistoryManager scan history & profiles system."""

import os
import tempfile
import unittest
from netspector.report.history import HistoryManager


class TestHistoryManager(unittest.TestCase):
    def test_history_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            hist = HistoryManager(history_dir=tmp_dir)

            sample_data = {
                "metadata": {
                    "tool": "NetSpector Pro",
                    "version": "1.0.0",
                    "summary": {
                        "total_packets": 500,
                        "total_flows": 42,
                        "severity_counts": {"CRITICAL": 1, "HIGH": 2},
                    },
                },
                "attack_chain_correlation": {
                    "total_correlated_entities": 3,
                },
                "alerts": [
                    {"alert_id": "ALT-101", "rule_id": "BEACON-01", "severity": "HIGH"},
                    {"alert_id": "ALT-102", "rule_id": "ENTROPY-01", "severity": "CRITICAL"},
                ],
            }

            # 1. Save Profile
            meta = hist.save_profile("sample.pcap", sample_data)
            self.assertIsNotNone(meta)
            self.assertIn("profile_id", meta)
            profile_id = meta["profile_id"]
            self.assertEqual(meta["total_packets"], 500)
            self.assertEqual(meta["total_alerts"], 2)

            # 2. List Profiles
            profiles = hist.list_profiles()
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0]["profile_id"], profile_id)

            # 3. Retrieve Profile
            loaded_data = hist.get_profile(profile_id)
            self.assertIsNotNone(loaded_data)
            self.assertEqual(len(loaded_data["alerts"]), 2)
            self.assertEqual(loaded_data["alerts"][0]["alert_id"], "ALT-101")

            # 4. Delete Profile
            deleted = hist.delete_profile(profile_id)
            self.assertTrue(deleted)
            self.assertEqual(len(hist.list_profiles()), 0)
            self.assertIsNone(hist.get_profile(profile_id))


if __name__ == "__main__":
    unittest.main()
