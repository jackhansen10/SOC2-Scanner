from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.controls.context import EvidenceContext, collect


CONTROL_ID = "CC8"
TITLE = "Change Management"
CONTROL_LANGUAGE = (
    "The entity implements change management to ensure system changes are "
    "authorized, tested, and approved."
)
SOURCES = ["CodePipeline", "CodeBuild", "CloudTrail"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    codepipeline_data = collect(context, "codepipeline")
    codebuild_data = collect(context, "codebuild")
    cloudtrail_data = collect(context, "cloudtrail")
    gaps: List[str] = []
    errors = codepipeline_data["errors"] + codebuild_data["errors"] + cloudtrail_data["errors"]

    if codepipeline_data["pipeline_count"] == 0 and codebuild_data["project_count"] == 0:
        gaps.append("No CodePipeline or CodeBuild projects detected.")
    if cloudtrail_data["logging_trail_count"] == 0:
        gaps.append("No CloudTrail trails are actively logging.")

    return {
        "codepipeline": codepipeline_data,
        "codebuild": codebuild_data,
        "cloudtrail": cloudtrail_data,
    }, gaps, errors
