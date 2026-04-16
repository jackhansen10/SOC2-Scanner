import json
import os
import tempfile
import unittest
from unittest.mock import patch

from soc2_scanner.scanner import ScanConfig, run_scan


class GcpScannerTests(unittest.TestCase):
    def test_run_scan_gcp_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = ScanConfig(
                controls=["CC1"],
                regions=["global"],
                profile=None,
                output_dir=tmp_dir,
                provider="gcp",
                project_id="my-project",
            )

            with patch(
                "soc2_scanner.scanner._get_gcp_identity",
                return_value=(
                    "creds",
                    {"account_id": "my-project", "arn": "sa@project.iam", "identity_error": None},
                ),
            ):
                with patch("soc2_scanner.scanner.evaluate_control") as mock_eval:
                    mock_eval.return_value = {
                        "control_id": "CC1",
                        "title": "Control Environment",
                        "control_language": "...",
                        "status": "pass",
                        "evidence_sources": [],
                        "collected_at": "now",
                        "gaps": [],
                        "errors": [],
                        "data": {},
                    }
                    result = run_scan(config)

            run_dir = os.path.dirname(result["artifacts"][0])
            json_path = os.path.join(run_dir, "evidence.json")
            csv_path = os.path.join(run_dir, "evidence_summary.csv")
            hash_path = os.path.join(run_dir, "evidence.json.sha256")

            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(hash_path))

            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["provider"], "gcp")
            self.assertEqual(payload["account_id"], "my-project")
            self.assertEqual(payload["controls"], ["CC1"])


if __name__ == "__main__":
    unittest.main()
