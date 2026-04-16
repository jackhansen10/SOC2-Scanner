from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.controls.context import EvidenceContext, collect


CONTROL_ID = "CC2"
TITLE = "Communication and Information"
CONTROL_LANGUAGE = (
    "The entity obtains or generates and communicates relevant information "
    "to support internal control."
)
SOURCES = ["CloudWatch", "VPC", "CloudTrail"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    cloudwatch_data = collect(context, "cloudwatch")
    vpc_data = collect(context, "vpc")
    cloudtrail_data = collect(context, "cloudtrail")
    gaps: List[str] = []
    errors = cloudwatch_data["errors"] + vpc_data["errors"] + cloudtrail_data["errors"]

    if cloudwatch_data["log_group_count"] == 0:
        gaps.append("No CloudWatch log groups detected.")
    if cloudwatch_data["alarm_count"] == 0:
        gaps.append("No CloudWatch alarms detected.")
    if vpc_data["active_flow_log_count"] == 0:
        gaps.append("No active VPC flow logs detected.")
    if cloudtrail_data["logging_trail_count"] == 0:
        gaps.append("No CloudTrail trails are actively logging.")

    return {
        "cloudwatch": cloudwatch_data,
        "vpc": vpc_data,
        "cloudtrail": cloudtrail_data,
    }, gaps, errors
