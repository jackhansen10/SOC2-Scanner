from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class EvidenceContext:
    session: Any
    regions: List[str]
    provider: str = "aws"
    project_id: Optional[str] = None
    cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def get_cached(
    context: EvidenceContext,
    key: str,
    collector: Callable[..., Dict[str, Any]],
    *args: Any,
) -> Dict[str, Any]:
    if key not in context.cache:
        context.cache[key] = collector(*args)
    return context.cache[key]


def status_from_findings(gaps: List[str], errors: List[str]) -> str:
    if errors:
        return "needs_review"
    if gaps:
        return "fail"
    return "pass"


def collect(context: "EvidenceContext", key: str) -> Dict[str, Any]:
    """Route evidence collection to the right provider with caching."""
    if key in context.cache:
        return context.cache[key]

    from soc2_scanner.collectors import (
        collect_access_analyzer,
        collect_backup,
        collect_cloudtrail,
        collect_cloudwatch,
        collect_codebuild,
        collect_codepipeline,
        collect_config,
        collect_config_rules,
        collect_guardduty,
        collect_iam,
        collect_inspector,
        collect_organizations,
        collect_securityhub,
        collect_ssm,
        collect_vpc,
        gcp,
    )

    aws_map: Dict[str, Callable[..., Dict[str, Any]]] = {
        "organizations": lambda: collect_organizations(context.session),
        "cloudtrail": lambda: collect_cloudtrail(context.session, context.regions),
        "cloudwatch": lambda: collect_cloudwatch(context.session, context.regions),
        "vpc": lambda: collect_vpc(context.session, context.regions),
        "securityhub": lambda: collect_securityhub(context.session, context.regions),
        "guardduty": lambda: collect_guardduty(context.session, context.regions),
        "inspector": lambda: collect_inspector(context.session, context.regions),
        "config": lambda: collect_config(context.session, context.regions),
        "config_rules": lambda: collect_config_rules(context.session, context.regions),
        "backup": lambda: collect_backup(context.session, context.regions),
        "iam": lambda: collect_iam(context.session),
        "access_analyzer": lambda: collect_access_analyzer(context.session, context.regions),
        "ssm": lambda: collect_ssm(context.session, context.regions),
        "codebuild": lambda: collect_codebuild(context.session, context.regions),
        "codepipeline": lambda: collect_codepipeline(context.session, context.regions),
    }
    gcp_map: Dict[str, Callable[..., Dict[str, Any]]] = {
        "organizations": lambda: gcp.collect_organizations(context.session, context.project_id),
        "cloudtrail": lambda: gcp.collect_cloudtrail(context.session, context.project_id, context.regions),
        "cloudwatch": lambda: gcp.collect_cloudwatch(context.session, context.project_id, context.regions),
        "vpc": lambda: gcp.collect_vpc(context.session, context.project_id, context.regions),
        "securityhub": lambda: gcp.collect_securityhub(context.session, context.project_id, context.regions),
        "guardduty": lambda: gcp.collect_guardduty(context.session, context.project_id, context.regions),
        "inspector": lambda: gcp.collect_inspector(context.session, context.project_id, context.regions),
        "config": lambda: gcp.collect_config(context.session, context.project_id, context.regions),
        "config_rules": lambda: gcp.collect_config_rules(context.session, context.project_id, context.regions),
        "backup": lambda: gcp.collect_backup(context.session, context.project_id, context.regions),
        "iam": lambda: gcp.collect_iam(context.session, context.project_id),
        "access_analyzer": lambda: gcp.collect_access_analyzer(context.session, context.project_id, context.regions),
        "ssm": lambda: gcp.collect_ssm(context.session, context.project_id, context.regions),
        "codebuild": lambda: gcp.collect_codebuild(context.session, context.project_id, context.regions),
        "codepipeline": lambda: gcp.collect_codepipeline(context.session, context.project_id, context.regions),
    }

    source = gcp_map if context.provider == "gcp" else aws_map
    context.cache[key] = source[key]()
    return context.cache[key]
