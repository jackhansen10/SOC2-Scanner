import argparse
import json
import os
from typing import Any, Dict, List

from soc2_scanner.scanner import ScanConfig, run_scan


DEFAULT_CONTROLS = ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8"]


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        if path.endswith((".yaml", ".yml")):
            try:
                import yaml
            except ImportError as exc:
                raise RuntimeError("PyYAML is required for YAML config files.") from exc
            data = yaml.safe_load(handle) or {}
            if not isinstance(data, dict):
                raise ValueError("YAML config must be a mapping at the top level.")
            return data
        data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("JSON config must be a mapping at the top level.")
        return data


def _validate_external_ids(external_ids: Any) -> Dict[str, str]:
    if external_ids is None:
        return {}
    if not isinstance(external_ids, dict):
        raise ValueError("external_ids must be a JSON/YAML object of account_id to external_id.")
    normalized: Dict[str, str] = {}
    for account_id, external_id in external_ids.items():
        if not isinstance(account_id, str) or not isinstance(external_id, str):
            raise ValueError("external_ids keys and values must be strings.")
        normalized[account_id] = external_id
    return normalized


def _merge_cli_config(args: argparse.Namespace) -> Dict[str, Any]:
    config: Dict[str, Any] = {}
    if args.config:
        config.update(_load_config(args.config))

    def _set_if(value: Any, key: str) -> None:
        if value is not None:
            config[key] = value

    _set_if(args.profile, "profile")
    _set_if(args.regions, "regions")
    _set_if(args.controls, "controls")
    _set_if(args.output, "output")
    if args.account_ids:
        config["account_ids"] = args.account_ids
    if args.all_accounts:
        config["all_accounts"] = True
    _set_if(args.role_name, "role_name")
    _set_if(args.external_id, "external_id")
    _set_if(args.provider, "provider")
    _set_if(args.project_id, "project_id")
    if args.simulate:
        config["simulate"] = True
    if args.external_ids:
        config["external_ids"] = _validate_external_ids(json.loads(args.external_ids))
    return config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOC2 evidence collection and reporting",
    )
    parser.add_argument(
        "--config",
        help="Path to JSON config file (CLI args override)",
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name from ~/.aws/credentials",
    )
    parser.add_argument(
        "--regions",
        help="Comma-separated AWS regions, e.g. us-east-1,us-west-2",
    )
    parser.add_argument(
        "--controls",
        help="Comma-separated SOC2 controls (default: CC1,CC2,CC3,CC4,CC5,CC6,CC7,CC8)",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for reports (default: reports)",
    )
    parser.add_argument(
        "--all-accounts",
        action="store_true",
        help="Scan all AWS Organization accounts using AssumeRole",
    )
    parser.add_argument(
        "--account-ids",
        help="Comma-separated AWS account IDs to scan",
    )
    parser.add_argument(
        "--role-name",
        default="OrganizationAccountAccessRole",
        help="Role name to assume in child accounts",
    )
    parser.add_argument(
        "--external-id",
        help="External ID to use when assuming roles",
    )
    parser.add_argument(
        "--external-ids",
        help="JSON map of account_id to external_id",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run a simulated scan without AWS API calls",
    )
    parser.add_argument(
        "--provider",
        choices=["aws", "gcp"],
        help="Cloud provider to scan (default: aws)",
    )
    parser.add_argument(
        "--project-id",
        help="GCP project ID to scan (falls back to default credentials project)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    merged = _merge_cli_config(args)
    controls = _split_csv(merged.get("controls")) if merged.get("controls") else DEFAULT_CONTROLS
    regions = _split_csv(merged.get("regions")) if merged.get("regions") else []
    if isinstance(merged.get("account_ids"), list):
        account_ids = [str(item) for item in merged.get("account_ids")]
    else:
        account_ids = _split_csv(merged.get("account_ids")) if merged.get("account_ids") else []

    config = ScanConfig(
        controls=controls,
        regions=regions,
        profile=merged.get("profile"),
        output_dir=merged.get("output") or "reports",
        account_ids=account_ids,
        all_accounts=bool(merged.get("all_accounts")),
        role_name=merged.get("role_name") or "OrganizationAccountAccessRole",
        external_id=merged.get("external_id"),
        external_ids=_validate_external_ids(merged.get("external_ids")),
        simulate=bool(merged.get("simulate")),
        provider=(merged.get("provider") or "aws").lower(),
        project_id=merged.get("project_id"),
    )

    result = run_scan(config)
    artifacts = result["artifacts"]
    run_dir = os.path.dirname(artifacts[0]) if artifacts else config.output_dir
    print(f"Evidence report created in: {run_dir}")
    for path in artifacts:
        print(f"- {path}")
    if result.get("identity_error"):
        print("Warning: unable to resolve AWS account identity.")
        print(result["identity_error"])
