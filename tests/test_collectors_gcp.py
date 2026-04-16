import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors import gcp


class GcpCollectorTests(unittest.TestCase):
    def test_collect_organizations_happy_path(self) -> None:
        with patch.object(gcp, "_build") as build:
            svc = Mock()
            build.return_value = (svc, None)
            with patch.object(gcp, "_safe") as safe:
                safe.side_effect = [
                    ({"organizations": [{"name": "organizations/123"}]}, None),
                    ({"projects": [{"projectId": "p1"}, {"projectId": "p2"}]}, None),
                    ({"policies": [{"name": "p/a"}, {"name": "p/b"}]}, None),
                ]
                result = gcp.collect_organizations("creds", "p1")
        self.assertTrue(result["organization_present"])
        self.assertEqual(result["root_count"], 1)
        self.assertEqual(result["account_count"], 2)
        self.assertEqual(result["scp_count"], 2)
        self.assertEqual(result["errors"], [])

    def test_collect_organizations_build_error(self) -> None:
        with patch.object(gcp, "_build", return_value=(None, "boom")):
            result = gcp.collect_organizations("creds", "p1")
        self.assertFalse(result["organization_present"])
        self.assertTrue(any("boom" in err for err in result["errors"]))

    def test_collect_cloudtrail_returns_sinks(self) -> None:
        with patch.object(gcp, "_build", return_value=(Mock(), None)):
            with patch.object(gcp, "_safe") as safe:
                safe.return_value = (
                    {"sinks": [{"name": "s1", "disabled": False}, {"name": "s2", "disabled": True}]},
                    None,
                )
                result = gcp.collect_cloudtrail("creds", "p1", ["global"])
        self.assertEqual(result["trail_count"], 2)
        self.assertEqual(result["logging_trail_count"], 1)

    def test_collect_cloudwatch_counts(self) -> None:
        with patch.object(gcp, "_build", return_value=(Mock(), None)):
            with patch.object(gcp, "_safe") as safe:
                safe.side_effect = [
                    ({"alertPolicies": [{"displayName": "a", "enabled": True}]}, None),
                    ({"logNames": ["projects/p/logs/x"]}, None),
                ]
                result = gcp.collect_cloudwatch("creds", "p1", [])
        self.assertEqual(result["alarm_count"], 1)
        self.assertEqual(result["log_group_count"], 1)

    def test_collect_vpc_flow_logs(self) -> None:
        with patch.object(gcp, "_build", return_value=(Mock(), None)):
            with patch.object(gcp, "_safe") as safe:
                safe.return_value = (
                    {"items": {"regions/us-east1": {"subnetworks": [{"name": "s", "enableFlowLogs": True}]}}},
                    None,
                )
                result = gcp.collect_vpc("creds", "p1", [])
        self.assertEqual(result["active_flow_log_count"], 1)

    def test_collect_iam_counts_users(self) -> None:
        with patch.object(gcp, "_build", return_value=(Mock(), None)):
            with patch.object(gcp, "_safe") as safe:
                safe.return_value = (
                    {"bindings": [
                        {"role": "roles/owner", "members": ["user:a@x.com"]},
                        {"role": "roles/viewer", "members": ["user:b@x.com", "serviceAccount:s@x"]},
                    ]},
                    None,
                )
                result = gcp.collect_iam("creds", "p1")
        self.assertEqual(result["user_count"], 2)
        self.assertTrue(result["root_mfa_enabled"])
        self.assertTrue(result["password_policy_present"])

    def test_collect_config_rules_from_orgpolicy(self) -> None:
        with patch.object(gcp, "_build", return_value=(Mock(), None)):
            with patch.object(gcp, "_safe") as safe:
                safe.return_value = (
                    {"policies": [{"name": "projects/p/policies/x"}]},
                    None,
                )
                result = gcp.collect_config_rules("creds", "p1", [])
        self.assertEqual(result["rule_count"], 1)
        self.assertEqual(result["noncompliant_count"], 0)


if __name__ == "__main__":
    unittest.main()
