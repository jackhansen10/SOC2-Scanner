from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.controls.context import EvidenceContext, collect


CONTROL_ID = "CC5"
TITLE = "Control Activities"
CONTROL_LANGUAGE = (
    "The entity selects and develops control activities that mitigate risks "
    "to achieving objectives."
)
SOURCES = ["AWS Backup", "Organizations", "AWS Config"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    backup_data = collect(context, "backup")
    org_data = collect(context, "organizations")
    config_rules_data = collect(context, "config_rules")
    gaps: List[str] = []
    errors = backup_data["errors"] + org_data["errors"] + config_rules_data["errors"]

    if backup_data["backup_plan_count"] == 0:
        gaps.append("No AWS Backup plans detected.")
    if org_data["scp_count"] == 0:
        gaps.append("No Service Control Policies detected.")
    if config_rules_data["rule_count"] == 0:
        gaps.append("No AWS Config rules detected.")

    return {
        "backup": backup_data,
        "organizations": org_data,
        "config_rules": config_rules_data,
    }, gaps, errors
