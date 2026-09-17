"""Unit tests for text and JSON report generators."""

import os
import tempfile
import unittest
from netshark.model import Alert, KillChainStage, Severity
from netshark.report.json_rep import export_json_report
from netshark.report.text import render_text_report


class TestReports(unittest.TestCase):
    def test_report_generation(self):
        alert = Alert(
            "ALT-01", "R1", "Title", "Desc", Severity.HIGH,
            KillChainStage.COMMAND_AND_CONTROL, "10.0.0.1", "1.1.1.1", 1234, 80, "TCP", 1600000000000000,
            arithmetic_proof={"cov": 0.05}
        )
        summary = {"total_packets": 100, "total_flows": 10, "analysis_duration_sec": 0.5, "severity_counts": {"HIGH": 1}}
        correlation = {"entities": []}

        text_out = render_text_report([alert], summary, correlation)
        self.assertIn("NETSHARK FORENSIC SUMMARY", text_out)
        self.assertIn("ALT-01", text_out)

        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = os.path.join(tmp_dir, "report.json")
            res = export_json_report([alert], summary, correlation, json_path)
            self.assertTrue(res)
            self.assertTrue(os.path.exists(json_path))


if __name__ == "__main__":
    unittest.main()
