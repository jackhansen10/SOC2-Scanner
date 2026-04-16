from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.controls.context import EvidenceContext, collect


CONTROL_ID = "CC1"
TITLE = "Control Environment"
CONTROL_LANGUAGE = (
    "The entity demonstrates a commitment to integrity, ethical values, "
    "and appropriate governance oversight."
)
SOURCES = ["Organizations", "CloudTrail"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    org_data = collect(context, "organizations")
    cloudtrail_data = collect(context, "cloudtrail")
    gaps: List[str] = []
    errors = org_data["errors"] + cloudtrail_data["errors"]

    if not org_data["organization_present"]:
        gaps.append("AWS Organizations is not enabled.")
    if org_data["scp_count"] == 0:
        gaps.append("No Service Control Policies detected.")
    if cloudtrail_data["logging_trail_count"] == 0:
        gaps.append("No CloudTrail trails are actively logging.")

    return {
        "organizations": org_data,
        "cloudtrail": cloudtrail_data,
    }, gaps, errors
