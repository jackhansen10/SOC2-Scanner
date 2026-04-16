__all__ = [
    "collect_access_analyzer",
    "collect_backup",
    "collect_cloudtrail",
    "collect_cloudwatch",
    "collect_codebuild",
    "collect_codepipeline",
    "collect_config",
    "collect_config_rules",
    "collect_guardduty",
    "collect_iam",
    "collect_inspector",
    "collect_kms",
    "collect_organizations",
    "collect_securityhub",
    "collect_ssm",
    "collect_vpc",
    "collect_waf",
    "gcp",
]

from soc2_scanner.collectors.access_analyzer import collect_access_analyzer
from soc2_scanner.collectors.backup import collect_backup
from soc2_scanner.collectors.cloudtrail import collect_cloudtrail
from soc2_scanner.collectors.cloudwatch import collect_cloudwatch
from soc2_scanner.collectors.codebuild import collect_codebuild
from soc2_scanner.collectors.codepipeline import collect_codepipeline
from soc2_scanner.collectors.config import collect_config
from soc2_scanner.collectors.config_rules import collect_config_rules
from soc2_scanner.collectors.guardduty import collect_guardduty
from soc2_scanner.collectors.iam import collect_iam
from soc2_scanner.collectors.inspector import collect_inspector
from soc2_scanner.collectors.kms import collect_kms
from soc2_scanner.collectors.organizations import collect_organizations
from soc2_scanner.collectors.securityhub import collect_securityhub
from soc2_scanner.collectors.ssm import collect_ssm
from soc2_scanner.collectors.vpc import collect_vpc
from soc2_scanner.collectors.waf import collect_waf
from soc2_scanner.collectors import gcp
