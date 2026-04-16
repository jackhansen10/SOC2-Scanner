from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.controls.context import EvidenceContext, collect


CONTROL_ID = "CC3"
TITLE = "Risk Assessment"
CONTROL_LANGUAGE = (
    "The entity specifies objectives and identifies and assesses risks "
    "to achieving those objectives."
)
SOURCES = ["Security Hub", "GuardDuty", "Inspector"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    securityhub_data = collect(context, "securityhub")
    guardduty_data = collect(context, "guardduty")
    inspector_data = collect(context, "inspector")
    gaps: List[str] = []
    errors = (
        securityhub_data["errors"]
        + guardduty_data["errors"]
        + inspector_data["errors"]
    )

    if securityhub_data["enabled_region_count"] == 0:
        gaps.append("Security Hub is not enabled in the provided regions.")
    if guardduty_data["enabled_detector_count"] == 0:
        gaps.append("GuardDuty is not enabled in the provided regions.")
    if inspector_data["coverage_region_count"] == 0:
        gaps.append("Inspector coverage not detected in the provided regions.")

    return {
        "securityhub": securityhub_data,
        "guardduty": guardduty_data,
        "inspector": inspector_data,
    }, gaps, errors
