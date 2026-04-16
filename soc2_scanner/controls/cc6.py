from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.controls.context import EvidenceContext, collect


CONTROL_ID = "CC6"
TITLE = "Logical and Physical Access"
CONTROL_LANGUAGE = (
    "The entity implements logical and physical access controls to protect "
    "systems and data from unauthorized access."
)
SOURCES = ["IAM", "Access Analyzer", "CloudTrail"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    iam_data = collect(context, "iam")
    access_analyzer_data = collect(context, "access_analyzer")
    cloudtrail_data = collect(context, "cloudtrail")
    gaps: List[str] = []
    errors = iam_data["errors"] + access_analyzer_data["errors"] + cloudtrail_data["errors"]

    if not iam_data["root_mfa_enabled"]:
        gaps.append("Root account MFA is not enabled.")
    if not iam_data["password_policy_present"]:
        gaps.append("IAM password policy is missing.")
    if access_analyzer_data["active_analyzer_count"] == 0:
        gaps.append("No active IAM Access Analyzer found.")
    if cloudtrail_data["logging_trail_count"] == 0:
        gaps.append("No CloudTrail trails are actively logging.")

    return {
        "iam": iam_data,
        "access_analyzer": access_analyzer_data,
        "cloudtrail": cloudtrail_data,
    }, gaps, errors
