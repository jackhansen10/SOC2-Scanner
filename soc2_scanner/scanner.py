from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError

from soc2_scanner.controls import CONTROL_REGISTRY, EvidenceContext, evaluate_control
from soc2_scanner.controls.context import status_from_findings
from soc2_scanner.collectors import collect_organizations


@dataclass
class ScanConfig:
    controls: List[str]
    regions: List[str]
    profile: Optional[str]
    output_dir: str
    account_ids: List[str] = field(default_factory=list)
    all_accounts: bool = False
    role_name: str = "OrganizationAccountAccessRole"
    external_id: Optional[str] = None
    external_ids: Dict[str, str] = field(default_factory=dict)
    simulate: bool = False
    provider: str = "aws"
    project_id: Optional[str] = None


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _ensure_output_dir(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)


def _hash_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _write_hash_file(target_path: str) -> str:
    digest = _hash_file(target_path)
    hash_path = f"{target_path}.sha256"
    with open(hash_path, "w", encoding="utf-8") as handle:
        handle.write(f"{digest}  {os.path.basename(target_path)}\n")
    return hash_path


def _gap_recommendation_map() -> Dict[str, str]:
    return {
        "AWS Organizations is not enabled.": (
            "Enable AWS Organizations or mark org-based controls as not applicable "
            "for single-account deployments."
        ),
        "No Service Control Policies detected.": (
            "Create and attach Service Control Policies (SCPs) to enforce org-wide guardrails."
        ),
        "No active VPC flow logs detected.": (
            "Enable VPC Flow Logs and verify the flow log status is ACTIVE."
        ),
        "Inspector coverage not detected in the provided regions.": (
            "Enable Inspector2 coverage for EC2/ECR/Lambda and allow time for coverage to populate."
        ),
        "No SSM managed instances detected.": (
            "Install/activate SSM Agent on instances and ensure they are managed by SSM."
        ),
        "IAM password policy is missing.": (
            "Create an IAM account password policy that meets your security requirements."
        ),
        "No CloudTrail trails are actively logging.": (
            "Ensure CloudTrail is enabled and logging to an S3 bucket/CloudWatch Logs."
        ),
        "AWS Config is not recording in any provided region.": (
            "Enable AWS Config recorder and delivery channel in the target regions."
        ),
        "No AWS Backup plans detected.": (
            "Create AWS Backup plans to meet backup and retention requirements."
        ),
        "No CodePipeline or CodeBuild projects detected.": (
            "Create CI/CD pipelines or document alternative change management controls."
        ),
        "No CloudWatch alarms detected.": (
            "Create CloudWatch alarms for critical logs/metrics and ensure notifications are configured."
        ),
        "No CloudWatch log groups detected.": (
            "Ensure logging is enabled and logs are being delivered to CloudWatch log groups."
        ),
        "No active IAM Access Analyzer found.": (
            "Enable IAM Access Analyzer in each region to detect unintended access."
        ),
        "GuardDuty is not enabled in the provided regions.": (
            "Enable GuardDuty in each required region."
        ),
        "Security Hub is not enabled in the provided regions.": (
            "Enable Security Hub and required standards in each region."
        ),
    }

def _recommendation_for_gap(gap: str) -> str:
    return _gap_recommendation_map().get(gap, f"Review and remediate gap: {gap}")


def _recommendation_for_error(error: str) -> str:
    if "AWSOrganizationsNotInUseException" in error:
        return (
            "Enable AWS Organizations or run the scanner from an Organizations management account."
        )
    if "GetAccountPasswordPolicy" in error:
        return "Create an IAM account password policy to satisfy password requirements."
    return f"Resolve error and re-run scan: {error}"


def _recommendation_for_rule(rule_name: str, remediation_rule_map: Dict[str, str]) -> str:
    return remediation_rule_map.get(
        rule_name,
        f"Review AWS Config/Security Hub guidance for {rule_name} and remediate affected resources.",
    )


def _friendly_error_message(error: str) -> str:
    if "AWSOrganizationsNotInUseException" in error:
        return "AWS Organizations is not enabled for this account."
    if "GetAccountPasswordPolicy" in error:
        return "No IAM account password policy is configured."
    if "AccessDenied" in error or "AccessDeniedException" in error:
        return "Access was denied for this API call. Check IAM permissions."
    if "ValidationException" in error:
        return "The request was rejected as invalid by the AWS service."
    return "An AWS API error occurred while collecting evidence."


def _build_issue_rows(
    entry: Dict[str, Any],
    remediation_rule_map: Dict[str, str],
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []

    gaps = entry.get("gaps", [])
    errors = entry.get("errors", [])
    config_rules = entry.get("data", {}).get("config_rules", {})
    noncompliant_sample = [
        rule.get("name")
        for rule in config_rules.get("rules_sample", [])
        if rule.get("compliance") == "NON_COMPLIANT"
    ]

    for gap in gaps:
        rows.append(
            {
                "type": "Gap",
                "item": gap,
                "recommendation": _recommendation_for_gap(gap),
            }
        )

    for err in errors:
        rows.append(
            {
                "type": "Error",
                "item": f"{_friendly_error_message(err)} (Details: {err})",
                "recommendation": "—",
            }
        )

    for name in noncompliant_sample[:10]:
        rows.append(
            {
                "type": "Rule",
                "item": f"NON_COMPLIANT: {name}",
                "recommendation": _recommendation_for_rule(name, remediation_rule_map),
            }
        )

    return rows


def _control_summary(entry: Dict[str, Any]) -> str:
    gaps = entry.get("gaps", [])
    errors = entry.get("errors", [])
    config_rules = entry.get("data", {}).get("config_rules", {})
    noncompliant_count = config_rules.get("noncompliant_count", 0)
    return (
        f"{len(gaps)} gap(s), {len(errors)} error(s), "
        f"{noncompliant_count} noncompliant rule(s)."
    )


def _format_status_value(status: str) -> str:
    if not status:
        return "Unknown"
    return status.replace("_", " ").title()


def _simulate_account_ids(config: ScanConfig) -> Tuple[List[str], Dict[str, str]]:
    if config.account_ids:
        account_ids = [str(item) for item in config.account_ids]
    elif config.all_accounts:
        account_ids = ["111111111111", "222222222222", "333333333333"]
    else:
        account_ids = ["123456789012"]
    account_map = {
        account_id: f"Simulated Account {index + 1}"
        for index, account_id in enumerate(account_ids)
    }
    return account_ids, account_map


def _simulate_config_rules(seed: int) -> Dict[str, Any]:
    rule_names = [
        "securityhub-access-keys-rotated-dcc5e306",
        "cloudtrail-enabled-1a2b3c",
        "vpc-flow-logs-enabled-4d5e6f",
    ]
    noncompliant_count = seed % (len(rule_names) + 1)
    rules_sample = [
        {"name": rule_names[index], "compliance": "NON_COMPLIANT"}
        for index in range(noncompliant_count)
    ]
    return {
        "noncompliant_count": noncompliant_count,
        "rules_sample": rules_sample,
    }


def _simulate_evidence_entry(control: str, account_id: str) -> Dict[str, Any]:
    definition = CONTROL_REGISTRY.get(control)
    title = definition["title"] if definition else "Unknown Control"
    language = definition["language"] if definition else ""
    sources = definition["sources"] if definition else []

    seed = int(hashlib.sha256(f"{account_id}:{control}".encode("utf-8")).hexdigest(), 16)
    gap_pool = list(_gap_recommendation_map().keys())
    gaps: List[str] = []
    if gap_pool and seed % 3 == 0:
        gaps.append(gap_pool[seed % len(gap_pool)])
    if gap_pool and seed % 5 == 0:
        gaps.append(gap_pool[(seed // 7) % len(gap_pool)])

    errors: List[str] = []
    if seed % 7 == 0:
        errors.append("AccessDeniedException: Simulated access denied for this API call.")
    if seed % 11 == 0:
        errors.append("ValidationException: Simulated validation error.")

    status = status_from_findings(gaps, errors)
    config_rules = _simulate_config_rules(seed)

    return {
        "control_id": control,
        "title": title,
        "control_language": language,
        "status": status,
        "evidence_sources": sources,
        "collected_at": _utc_timestamp(),
        "gaps": gaps,
        "errors": errors,
        "data": {"config_rules": config_rules},
    }


def _run_simulated_scan(config: ScanConfig) -> Dict[str, Any]:
    _ensure_output_dir(config.output_dir)
    run_id = _run_id()
    run_dir = os.path.join(config.output_dir, run_id)
    _ensure_output_dir(run_dir)

    regions = config.regions or ["us-east-1"]
    account_ids, account_map = _simulate_account_ids(config)
    primary_account_id = account_ids[0] if account_ids else "123456789012"
    identity = {
        "account_id": primary_account_id,
        "arn": f"arn:aws:sts::{primary_account_id}:assumed-role/simulated/session",
        "identity_error": None,
    }
    organization_error: Optional[str] = None

    account_results: List[Dict[str, Any]] = []
    for account_id in account_ids:
        evidence_entries = [_simulate_evidence_entry(control, account_id) for control in config.controls]
        account_results.append(
            {
                "account_id": account_id,
                "account_name": account_map.get(account_id),
                "caller_arn": f"arn:aws:sts::{account_id}:assumed-role/simulated/session",
                "identity_error": None,
                "evidence": evidence_entries,
            }
        )

    primary_evidence = account_results[0]["evidence"] if account_results else []

    payload = {
        "generated_at": _utc_timestamp(),
        "run_id": run_id,
        "controls": config.controls,
        "regions": regions,
        "account_id": identity["account_id"],
        "caller_arn": identity["arn"],
        "identity_error": None,
        "organization_error": organization_error,
        "attribution": _report_attribution(),
        "evidence": primary_evidence,
        "accounts": account_results if len(account_results) > 1 else [],
    }

    json_path = os.path.join(run_dir, "evidence.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    csv_path = os.path.join(run_dir, "evidence_summary.csv")
    summary_rows: List[Dict[str, Any]] = []
    for account in account_results:
        for entry in account.get("evidence", []):
            config_rules = entry.get("data", {}).get("config_rules", {})
            noncompliant_rules = [
                rule.get("name")
                for rule in config_rules.get("rules_sample", [])
                if rule.get("compliance") == "NON_COMPLIANT"
            ]
            noncompliant_rules_sample = ", ".join(noncompliant_rules[:10])
            summary_rows.append(
                {
                    "account_id": account.get("account_id"),
                    "account_name": account.get("account_name"),
                    "control_id": entry.get("control_id"),
                    "title": entry.get("title"),
                    "status": entry.get("status"),
                    "gap_count": len(entry.get("gaps", [])),
                    "error_count": len(entry.get("errors", [])),
                    "noncompliant_rule_count": config_rules.get("noncompliant_count", 0),
                    "noncompliant_rules_sample": noncompliant_rules_sample,
                }
            )
    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(csv_path, index=False)

    hash_path = _write_hash_file(json_path)

    completeness_path = os.path.join(run_dir, "run_completeness.json")
    completeness_payload = {
        "run_id": run_id,
        "generated_at": payload["generated_at"],
        "account_id": payload["account_id"],
        "caller_arn": payload["caller_arn"],
        "regions": regions,
        "controls": config.controls,
        "identity_error": None,
        "organization_error": organization_error,
        "account_count": len(account_results),
        "attribution": _report_attribution(),
        "narrative": (
            "This simulated run generates example evidence without contacting AWS. "
            "Noncompliant values are synthetic and for demonstration only."
        ),
        "artifacts": {
            "evidence_json": os.path.basename(json_path),
            "evidence_csv": os.path.basename(csv_path),
            "evidence_hash": os.path.basename(hash_path),
        },
    }
    with open(completeness_path, "w", encoding="utf-8") as handle:
        json.dump(completeness_payload, handle, indent=2, sort_keys=True)
    completeness_hash = _write_hash_file(completeness_path)

    summary_path = os.path.join(run_dir, "report_summary.md")
    remediation_rule_map = {
        "securityhub-access-keys-rotated-dcc5e306": (
            "Rotate or deactivate IAM access keys that exceed your rotation policy. "
            "Remove unused keys and enforce MFA/SSO for users."
        )
    }

    summary_lines = [
        "# SOC 2 Evidence Summary",
        "",
        f"- Run ID: {run_id}",
        f"- Generated at (UTC): {payload['generated_at']}",
        f"- Account ID: {payload['account_id']}",
        f"- Caller ARN: {payload['caller_arn']}",
        f"- Regions: {', '.join(regions)}",
        f"- Controls: {', '.join(config.controls)}",
        f"- Account count: {len(account_results)}",
        f"- Attribution: {_report_attribution()}",
        "",
        "## Notes",
        completeness_payload["narrative"],
        "",
        "## Control Results",
    ]

    for account in account_results:
        summary_lines.extend(
            [
                "",
                f"### Account {account.get('account_id')}",
            ]
        )
        if account.get("account_name"):
            summary_lines.append(f"- Name: {account.get('account_name')}")
        if account.get("identity_error"):
            summary_lines.append(f"- Identity error: {account.get('identity_error')}")
        summary_lines.append("")

        for entry in account.get("evidence", []):
            summary_lines.extend(
                [
                    f"#### {entry.get('control_id')} - {entry.get('title')}",
                    f"- **Status:** {_format_status_value(entry.get('status', 'unknown'))}",
                    f"- **Control description:** {entry.get('control_language')}",
                    f"- Summary: {_control_summary(entry)}",
                    f"- Collected at: {entry.get('collected_at')}",
                ]
            )

            issue_rows = _build_issue_rows(entry, remediation_rule_map)
            if issue_rows:
                summary_lines.append("")
                summary_lines.append("| Type | Finding | Recommendation |")
                summary_lines.append("| --- | --- | --- |")
                for row in issue_rows:
                    summary_lines.append(
                        f"| {row['type']} | {row['item']} | {row['recommendation']} |"
                    )
            summary_lines.append("")

    summary_lines.extend(
        [
            "## Artifacts",
            f"- evidence.json",
            f"- evidence_summary.csv",
            f"- evidence.json.sha256",
            f"- run_completeness.json",
            f"- run_completeness.json.sha256",
        ]
    )
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(summary_lines).strip() + "\n")
    summary_hash = _write_hash_file(summary_path)
    pdf_path = _write_pdf_summary(run_dir, payload, account_results, completeness_payload)
    pdf_hash = _write_hash_file(pdf_path) if pdf_path else None

    return {
        "artifacts": [
            json_path,
            csv_path,
            hash_path,
            completeness_path,
            completeness_hash,
            summary_path,
            summary_hash,
            *(path for path in [pdf_path, pdf_hash] if path),
        ],
        "identity_error": None,
    }


def _write_pdf_summary(
    run_dir: str,
    payload: Dict[str, Any],
    account_results: List[Dict[str, Any]],
    completeness_payload: Dict[str, Any],
) -> Optional[str]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return None

    pdf_path = os.path.join(run_dir, "report_summary.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=LETTER,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
        title="SOC 2 Evidence Summary",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=9))
    styles.add(
        ParagraphStyle(
            name="SmallWrap",
            parent=styles["Small"],
            wordWrap="CJK",
            leading=11,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Subtitle",
            parent=styles["Title"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#374151"),
            spaceBefore=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetaLabel",
            parent=styles["BodyText"],
            fontSize=9,
            textColor=colors.HexColor("#6B7280"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetaValue",
            parent=styles["BodyText"],
            fontSize=9,
            textColor=colors.HexColor("#111827"),
        )
    )
    story = []
    remediation_rule_map = {
        "securityhub-access-keys-rotated-dcc5e306": (
            "Rotate or deactivate IAM access keys that exceed your rotation policy. "
            "Remove unused keys and enforce MFA/SSO for users."
        )
    }

    story.append(Paragraph("SOC 2 Evidence Summary", styles["Title"]))
    story.append(Paragraph("AWS Evidence Collection Report", styles["Subtitle"]))
    story.append(Spacer(1, 14))

    meta_rows = [
        [
            Paragraph("Run ID", styles["MetaLabel"]),
            Paragraph(payload["run_id"], styles["MetaValue"]),
            Paragraph("Generated (UTC)", styles["MetaLabel"]),
            Paragraph(payload["generated_at"], styles["MetaValue"]),
        ],
        [
            Paragraph("Account ID", styles["MetaLabel"]),
            Paragraph(payload["account_id"], styles["MetaValue"]),
            Paragraph("Caller ARN", styles["MetaLabel"]),
            Paragraph(payload["caller_arn"], styles["MetaValue"]),
        ],
        [
            Paragraph("Regions", styles["MetaLabel"]),
            Paragraph(", ".join(payload["regions"]), styles["MetaValue"]),
            Paragraph("Controls", styles["MetaLabel"]),
            Paragraph(", ".join(payload["controls"]), styles["MetaValue"]),
        ],
        [
            Paragraph("Account count", styles["MetaLabel"]),
            Paragraph(str(len(account_results)), styles["MetaValue"]),
            Paragraph("Report scope", styles["MetaLabel"]),
            Paragraph("SOC 2 Security (TSP 2017)", styles["MetaValue"]),
        ],
        [
            Paragraph("Attribution", styles["MetaLabel"]),
            Paragraph(_report_attribution(), styles["MetaValue"]),
            Paragraph("", styles["MetaLabel"]),
            Paragraph("", styles["MetaValue"]),
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[80, 185, 80, 185])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F9FAFB")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Notes", styles["Heading2"]))
    story.append(Paragraph(completeness_payload["narrative"], styles["BodyText"]))
    story.append(Spacer(1, 12))

    for account in account_results:
        story.append(PageBreak())
        story.append(Paragraph(f"Account {account.get('account_id')}", styles["Heading2"]))
        if account.get("account_name"):
            story.append(Paragraph(f"Name: {account.get('account_name')}", styles["Normal"]))
        if account.get("identity_error"):
            story.append(Paragraph(f"Identity error: {account.get('identity_error')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        table_data = [
            [
                "Control",
                "Title",
                "Status",
                "Gaps",
                "Errors",
                "Noncompliant Rules",
            ]
        ]
        for entry in account.get("evidence", []):
            config_rules = entry.get("data", {}).get("config_rules", {})
            noncompliant_count = config_rules.get("noncompliant_count", 0)
            table_data.append(
                [
                    entry.get("control_id"),
                    entry.get("title"),
                    entry.get("status"),
                    str(len(entry.get("gaps", []))),
                    str(len(entry.get("errors", []))),
                    str(noncompliant_count),
                ]
            )

        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 12))

        for entry in account.get("evidence", []):
            story.append(Paragraph(f"{entry.get('control_id')} Details", styles["Heading3"]))
            if entry.get("control_language"):
                story.append(
                    Paragraph(
                        f"<b>Control description:</b> {entry.get('control_language')}",
                        styles["Small"],
                    )
                )
            status_text = _format_status_value(entry.get("status", "unknown"))
            story.append(Paragraph(f"<b>Status:</b> {status_text}", styles["Small"]))
            story.append(Paragraph(_control_summary(entry), styles["Small"]))
            story.append(Paragraph(f"Collected at: {entry.get('collected_at')}", styles["Small"]))
            issue_rows = _build_issue_rows(entry, remediation_rule_map)
            if issue_rows:
                detail_table = [
                    ["Type", "Finding", "Recommendation"],
                ]
                for row in issue_rows:
                    detail_table.append(
                        [
                            Paragraph(row["type"], styles["Small"]),
                            Paragraph(row["item"], styles["SmallWrap"]),
                            Paragraph(row["recommendation"], styles["SmallWrap"]),
                        ]
                    )
                detail = Table(detail_table, repeatRows=1, colWidths=[60, 300, 160])
                detail.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                        ]
                    )
                )
                story.append(Spacer(1, 6))
                story.append(detail)
            story.append(Spacer(1, 8))

    def _draw_footer(canvas, doc_instance) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        canvas.drawString(36, 18, _report_attribution())
        canvas.restoreState()

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return pdf_path


def _write_reports(
    run_dir: str,
    run_id: str,
    config: ScanConfig,
    regions: List[str],
    identity: Dict[str, Optional[str]],
    account_results: List[Dict[str, Any]],
    organization_error: Optional[str],
    narrative: str,
) -> Dict[str, Any]:
    primary_evidence = account_results[0]["evidence"] if account_results else []

    payload = {
        "generated_at": _utc_timestamp(),
        "run_id": run_id,
        "controls": config.controls,
        "regions": regions,
        "provider": config.provider,
        "account_id": identity["account_id"],
        "caller_arn": identity["arn"],
        "identity_error": identity["identity_error"],
        "organization_error": organization_error,
        "attribution": _report_attribution(),
        "evidence": primary_evidence,
        "accounts": account_results if len(account_results) > 1 else [],
    }

    json_path = os.path.join(run_dir, "evidence.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    csv_path = os.path.join(run_dir, "evidence_summary.csv")
    summary_rows: List[Dict[str, Any]] = []
    for account in account_results:
        for entry in account.get("evidence", []):
            config_rules = entry.get("data", {}).get("config_rules", {})
            noncompliant_rules = [
                rule.get("name")
                for rule in config_rules.get("rules_sample", [])
                if rule.get("compliance") == "NON_COMPLIANT"
            ]
            noncompliant_rules_sample = ", ".join(noncompliant_rules[:10])
            summary_rows.append(
                {
                    "account_id": account.get("account_id"),
                    "account_name": account.get("account_name"),
                    "control_id": entry.get("control_id"),
                    "title": entry.get("title"),
                    "status": entry.get("status"),
                    "gap_count": len(entry.get("gaps", [])),
                    "error_count": len(entry.get("errors", [])),
                    "noncompliant_rule_count": config_rules.get("noncompliant_count", 0),
                    "noncompliant_rules_sample": noncompliant_rules_sample,
                }
            )
    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(csv_path, index=False)

    hash_path = _write_hash_file(json_path)

    completeness_path = os.path.join(run_dir, "run_completeness.json")
    completeness_payload = {
        "run_id": run_id,
        "generated_at": payload["generated_at"],
        "provider": config.provider,
        "account_id": payload["account_id"],
        "caller_arn": payload["caller_arn"],
        "regions": regions,
        "controls": config.controls,
        "identity_error": payload["identity_error"],
        "organization_error": organization_error,
        "account_count": len(account_results),
        "attribution": _report_attribution(),
        "narrative": narrative,
        "artifacts": {
            "evidence_json": os.path.basename(json_path),
            "evidence_csv": os.path.basename(csv_path),
            "evidence_hash": os.path.basename(hash_path),
        },
    }
    with open(completeness_path, "w", encoding="utf-8") as handle:
        json.dump(completeness_payload, handle, indent=2, sort_keys=True)
    completeness_hash = _write_hash_file(completeness_path)

    summary_path = os.path.join(run_dir, "report_summary.md")
    remediation_rule_map = {
        "securityhub-access-keys-rotated-dcc5e306": (
            "Rotate or deactivate IAM access keys that exceed your rotation policy. "
            "Remove unused keys and enforce MFA/SSO for users."
        )
    }

    summary_lines = [
        "# SOC 2 Evidence Summary",
        "",
        f"- Run ID: {run_id}",
        f"- Generated at (UTC): {payload['generated_at']}",
        f"- Provider: {config.provider.upper()}",
        f"- Account ID: {payload['account_id']}",
        f"- Caller ARN: {payload['caller_arn']}",
        f"- Regions: {', '.join(regions)}",
        f"- Controls: {', '.join(config.controls)}",
        f"- Account count: {len(account_results)}",
        f"- Attribution: {_report_attribution()}",
        "",
        "## Notes",
        completeness_payload["narrative"],
        "",
        "## Control Results",
    ]

    for account in account_results:
        summary_lines.extend(["", f"### Account {account.get('account_id')}"])
        if account.get("account_name"):
            summary_lines.append(f"- Name: {account.get('account_name')}")
        if account.get("identity_error"):
            summary_lines.append(f"- Identity error: {account.get('identity_error')}")
        summary_lines.append("")

        for entry in account.get("evidence", []):
            summary_lines.extend(
                [
                    f"#### {entry.get('control_id')} - {entry.get('title')}",
                    f"- **Status:** {_format_status_value(entry.get('status', 'unknown'))}",
                    f"- **Control description:** {entry.get('control_language')}",
                    f"- Summary: {_control_summary(entry)}",
                    f"- Collected at: {entry.get('collected_at')}",
                ]
            )

            issue_rows = _build_issue_rows(entry, remediation_rule_map)
            if issue_rows:
                summary_lines.append("")
                summary_lines.append("| Type | Finding | Recommendation |")
                summary_lines.append("| --- | --- | --- |")
                for row in issue_rows:
                    summary_lines.append(
                        f"| {row['type']} | {row['item']} | {row['recommendation']} |"
                    )
            summary_lines.append("")

    summary_lines.extend(
        [
            "## Artifacts",
            "- evidence.json",
            "- evidence_summary.csv",
            "- evidence.json.sha256",
            "- run_completeness.json",
            "- run_completeness.json.sha256",
        ]
    )
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(summary_lines).strip() + "\n")
    summary_hash = _write_hash_file(summary_path)
    pdf_path = _write_pdf_summary(run_dir, payload, account_results, completeness_payload)
    pdf_hash = _write_hash_file(pdf_path) if pdf_path else None

    return {
        "artifacts": [
            json_path,
            csv_path,
            hash_path,
            completeness_path,
            completeness_hash,
            summary_path,
            summary_hash,
            *(path for path in [pdf_path, pdf_hash] if path),
        ],
        "identity_error": identity["identity_error"],
    }


def _get_gcp_identity() -> Tuple[Any, Dict[str, Optional[str]]]:
    try:
        import google.auth  # type: ignore
    except ImportError as exc:
        return None, {"account_id": None, "arn": None, "identity_error": str(exc)}
    try:
        credentials, project_id = google.auth.default()
        service_account = getattr(credentials, "service_account_email", None) or str(credentials)
        return credentials, {
            "account_id": project_id,
            "arn": service_account,
            "identity_error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return None, {"account_id": None, "arn": None, "identity_error": str(exc)}


def _run_gcp_scan(config: ScanConfig) -> Dict[str, Any]:
    _ensure_output_dir(config.output_dir)
    run_id = _run_id()
    run_dir = os.path.join(config.output_dir, run_id)
    _ensure_output_dir(run_dir)

    credentials, identity = _get_gcp_identity()
    regions = config.regions or ["global"]

    project_ids: List[str] = []
    if config.account_ids:
        project_ids = list(dict.fromkeys(str(pid) for pid in config.account_ids))
    elif config.project_id:
        project_ids = [config.project_id]
    elif identity["account_id"]:
        project_ids = [identity["account_id"]]

    if not project_ids:
        project_ids = [""]

    account_results: List[Dict[str, Any]] = []
    for project_id in project_ids:
        context = EvidenceContext(
            session=credentials,
            regions=regions,
            provider="gcp",
            project_id=project_id or None,
        )
        evidence_entries = _build_evidence_entries(config.controls, context)
        account_results.append(
            {
                "account_id": project_id,
                "account_name": None,
                "caller_arn": identity["arn"],
                "identity_error": identity["identity_error"],
                "evidence": evidence_entries,
            }
        )

    narrative = (
        "NON_COMPLIANT values reflect GCP Organization Policy / Security Command "
        "Center findings, not a direct SOC 2 determination. They are supporting "
        "evidence that may indicate control gaps and require review."
    )
    return _write_reports(
        run_dir, run_id, config, regions, identity, account_results, None, narrative
    )


def _get_account_identity(session: boto3.Session) -> Dict[str, Optional[str]]:
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return {
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "identity_error": None,
        }
    except (BotoCoreError, ClientError) as exc:
        return {
            "account_id": None,
            "arn": None,
            "identity_error": str(exc),
        }


def _resolve_regions(session: boto3.Session, regions: List[str]) -> List[str]:
    if regions:
        return regions
    if session.region_name:
        return [session.region_name]
    return ["us-east-1"]


def _report_attribution() -> str:
    return (
        "Produced using the Compliance-Scanner repository "
        "(https://github.com/jackhansen10/Compliance-Scanner)."
    )


def _assume_role_session(
    base_session: boto3.Session,
    account_id: str,
    role_name: str,
    external_id: Optional[str],
) -> Tuple[Optional[boto3.Session], Optional[str]]:
    try:
        sts = base_session.client("sts")
        assume_kwargs: Dict[str, Any] = {
            "RoleArn": f"arn:aws:iam::{account_id}:role/{role_name}",
            "RoleSessionName": "soc2-scanner",
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id
        response = sts.assume_role(**assume_kwargs)
        credentials = response["Credentials"]
        return (
            boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=base_session.region_name,
            ),
            None,
        )
    except (BotoCoreError, ClientError) as exc:
        return None, str(exc)


def _list_org_accounts(
    session: boto3.Session,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        client = session.client("organizations")
        paginator = client.get_paginator("list_accounts")
        accounts: List[Dict[str, Any]] = []
        for page in paginator.paginate():
            accounts.extend(page.get("Accounts", []))
        return accounts, None
    except (BotoCoreError, ClientError) as exc:
        return [], str(exc)


def _needs_org_cache(controls: List[str]) -> bool:
    return any(control in {"CC1", "CC5"} for control in controls)


def _build_evidence_entries(
    controls: List[str], context: EvidenceContext
) -> List[Dict[str, Any]]:
    entries = []
    for control in controls:
        entries.append(evaluate_control(control, context))
    return entries


def run_scan(config: ScanConfig) -> Dict[str, Any]:
    if config.simulate:
        return _run_simulated_scan(config)
    if config.provider == "gcp":
        return _run_gcp_scan(config)

    _ensure_output_dir(config.output_dir)
    run_id = _run_id()
    run_dir = os.path.join(config.output_dir, run_id)
    _ensure_output_dir(run_dir)

    session = boto3.Session(
        profile_name=config.profile,
        region_name=config.regions[0] if config.regions else None,
    )

    identity = _get_account_identity(session)
    regions = _resolve_regions(session, config.regions)
    account_results: List[Dict[str, Any]] = []
    organization_error: Optional[str] = None

    org_cache: Optional[Dict[str, Any]] = None
    if _needs_org_cache(config.controls):
        org_cache = collect_organizations(session)

    account_ids: List[str] = []
    account_map: Dict[str, str] = {}
    if config.all_accounts:
        org_accounts, org_error = _list_org_accounts(session)
        if org_error:
            organization_error = org_error
        for account in org_accounts:
            if account.get("Status") == "ACTIVE":
                account_id = account.get("Id")
                if account_id:
                    account_ids.append(account_id)
                    account_map[account_id] = account.get("Name") or ""
    elif config.account_ids:
        account_ids = config.account_ids[:]

    if not account_ids:
        account_ids = [identity["account_id"] or ""]

    for account_id in dict.fromkeys(account_ids):
        if not account_id:
            continue
        if account_id == identity["account_id"]:
            account_session = session
            account_identity = identity
            assume_error = None
        else:
            account_external_id = config.external_ids.get(account_id) or config.external_id
            account_session, assume_error = _assume_role_session(
                session, account_id, config.role_name, account_external_id
            )
            if account_session:
                account_identity = _get_account_identity(account_session)
            else:
                account_identity = {"account_id": account_id, "arn": None, "identity_error": assume_error}

        if not account_session:
            account_results.append(
                {
                    "account_id": account_id,
                    "account_name": account_map.get(account_id),
                    "caller_arn": None,
                    "identity_error": assume_error,
                    "evidence": [],
                }
            )
            continue

        context = EvidenceContext(session=account_session, regions=regions)
        if org_cache is not None:
            context.cache["organizations"] = org_cache
        evidence_entries = _build_evidence_entries(config.controls, context)
        account_results.append(
            {
                "account_id": account_identity["account_id"],
                "account_name": account_map.get(account_id),
                "caller_arn": account_identity["arn"],
                "identity_error": account_identity["identity_error"] or assume_error,
                "evidence": evidence_entries,
            }
        )

    narrative = (
        "NON_COMPLIANT values reflect AWS Config/Security Hub rule failures, "
        "not a direct SOC 2 determination. They are supporting evidence that "
        "may indicate control gaps and require review."
    )
    return _write_reports(
        run_dir, run_id, config, regions, identity, account_results,
        organization_error, narrative,
    )
