"""GCP evidence collectors.

Mirrors the AWS collectors' return shapes so controls can consume either provider.
All collectors accept GCP credentials and a project_id. Regions map to GCP
locations where applicable.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def _build(service_name: str, version: str, credentials: Any) -> Tuple[Any, Optional[str]]:
    try:
        from googleapiclient.discovery import build
    except ImportError as exc:
        return None, f"google-api-python-client not installed: {exc}"
    try:
        return build(service_name, version, credentials=credentials, cache_discovery=False), None
    except Exception as exc:  # noqa: BLE001 - any discovery/auth error
        return None, str(exc)


def _safe(func, *args, **kwargs) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return func(*args, **kwargs).execute(), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def _format_error(service: str, scope: Optional[str], error: str) -> str:
    if scope:
        return f"{service}:{scope}: {error}"
    return f"{service}: {error}"


def collect_organizations(credentials: Any, project_id: str) -> Dict[str, Any]:
    errors: List[str] = []
    service, err = _build("cloudresourcemanager", "v1", credentials)
    if err or not service:
        return {
            "organization_present": False,
            "root_count": 0,
            "scp_count": 0,
            "account_count": 0,
            "errors": [_format_error("cloudresourcemanager", None, err or "unavailable")],
        }

    orgs, orgs_err = _safe(service.organizations().search, body={})
    projects, proj_err = _safe(service.projects().list)
    if orgs_err:
        errors.append(_format_error("cloudresourcemanager", None, orgs_err))
    if proj_err:
        errors.append(_format_error("cloudresourcemanager", None, proj_err))

    org_list = (orgs or {}).get("organizations", []) if orgs else []
    scp_count = 0
    op_service, op_err = _build("orgpolicy", "v2", credentials)
    if op_err:
        errors.append(_format_error("orgpolicy", None, op_err))
    elif op_service and org_list:
        for org in org_list:
            org_name = org.get("name")
            if not org_name:
                continue
            policies, pol_err = _safe(
                op_service.organizations().policies().list, parent=org_name
            )
            if pol_err:
                errors.append(_format_error("orgpolicy", org_name, pol_err))
                continue
            scp_count += len((policies or {}).get("policies", []))

    return {
        "organization_present": bool(org_list),
        "root_count": len(org_list),
        "scp_count": scp_count,
        "account_count": len((projects or {}).get("projects", [])),
        "errors": errors,
    }


def collect_cloudtrail(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Cloud Audit Logs evidence: sinks act as the 'trails'."""
    trails: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("logging", "v2", credentials)
    if err or not service:
        return {
            "trail_count": 0,
            "multi_region_trail_count": 0,
            "logging_trail_count": 0,
            "trails": [],
            "errors": [_format_error("logging", None, err or "unavailable")],
        }

    parent = f"projects/{project_id}"
    sinks, sinks_err = _safe(service.projects().sinks().list, parent=parent)
    if sinks_err:
        errors.append(_format_error("logging", parent, sinks_err))
    for sink in (sinks or {}).get("sinks", []):
        trails.append(
            {
                "name": sink.get("name"),
                "home_region": "global",
                "region": "global",
                "is_multi_region": True,
                "is_logging": not sink.get("disabled", False),
                "destination": sink.get("destination"),
                "filter": sink.get("filter"),
            }
        )

    return {
        "trail_count": len(trails),
        "multi_region_trail_count": sum(1 for t in trails if t.get("is_multi_region")),
        "logging_trail_count": sum(1 for t in trails if t.get("is_logging")),
        "trails": trails,
        "errors": errors,
    }


def collect_cloudwatch(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Cloud Monitoring alert policies + Cloud Logging log entries as log groups."""
    alarms: List[Dict[str, Any]] = []
    log_groups: List[Dict[str, Any]] = []
    errors: List[str] = []

    mon, mon_err = _build("monitoring", "v3", credentials)
    if mon_err:
        errors.append(_format_error("monitoring", None, mon_err))
    elif mon:
        resp, err = _safe(
            mon.projects().alertPolicies().list, name=f"projects/{project_id}"
        )
        if err:
            errors.append(_format_error("monitoring", project_id, err))
        for policy in (resp or {}).get("alertPolicies", []):
            alarms.append(
                {
                    "name": policy.get("displayName"),
                    "region": "global",
                    "state": "enabled" if policy.get("enabled") else "disabled",
                }
            )

    logs, logs_err = _build("logging", "v2", credentials)
    if logs_err:
        errors.append(_format_error("logging", None, logs_err))
    elif logs:
        resp, err = _safe(logs.projects().logs().list, parent=f"projects/{project_id}")
        if err:
            errors.append(_format_error("logging", project_id, err))
        for log_name in (resp or {}).get("logNames", []):
            log_groups.append(
                {"name": log_name, "region": "global", "retention_days": None}
            )

    return {
        "alarm_count": len(alarms),
        "log_group_count": len(log_groups),
        "alarms_sample": alarms[:25],
        "log_groups_sample": log_groups[:25],
        "errors": errors,
    }


def collect_vpc(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """VPC flow logs evidence via subnetwork.enableFlowLogs."""
    flow_logs: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("compute", "v1", credentials)
    if err or not service:
        return {
            "flow_log_count": 0,
            "active_flow_log_count": 0,
            "flow_logs_sample": [],
            "errors": [_format_error("compute", None, err or "unavailable")],
        }

    resp, agg_err = _safe(service.subnetworks().aggregatedList, project=project_id)
    if agg_err:
        errors.append(_format_error("compute", project_id, agg_err))
    items = (resp or {}).get("items", {}) or {}
    for region_key, region_data in items.items():
        for subnet in region_data.get("subnetworks", []) or []:
            if subnet.get("enableFlowLogs"):
                flow_logs.append(
                    {
                        "flow_log_id": subnet.get("name"),
                        "resource_id": subnet.get("id"),
                        "region": region_key.replace("regions/", ""),
                        "log_status": "ACTIVE",
                    }
                )

    return {
        "flow_log_count": len(flow_logs),
        "active_flow_log_count": len(flow_logs),
        "flow_logs_sample": flow_logs[:25],
        "errors": errors,
    }


def _scc_finding_count(credentials: Any, project_id: str) -> Tuple[int, Optional[str]]:
    service, err = _build("securitycenter", "v1", credentials)
    if err or not service:
        return 0, err
    resp, list_err = _safe(
        service.projects().sources().findings().list,
        parent=f"projects/{project_id}/sources/-",
    )
    if list_err:
        return 0, list_err
    return len((resp or {}).get("listFindingsResults", [])), None


def collect_securityhub(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Security Command Center acts as SecurityHub equivalent."""
    errors: List[str] = []
    count, err = _scc_finding_count(credentials, project_id)
    if err:
        errors.append(_format_error("securitycenter", project_id, err))
    enabled = err is None
    return {
        "enabled_region_count": 1 if enabled else 0,
        "regions": [{"region": "global", "enabled": enabled, "product_subscriptions": count}],
        "errors": errors,
    }


def collect_guardduty(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """SCC threat findings act as GuardDuty equivalent."""
    errors: List[str] = []
    count, err = _scc_finding_count(credentials, project_id)
    if err:
        errors.append(_format_error("securitycenter", project_id, err))
    enabled = err is None
    return {
        "detector_count": 1 if enabled else 0,
        "enabled_detector_count": 1 if enabled else 0,
        "detectors": [
            {"detector_id": project_id, "region": "global", "status": "ENABLED" if enabled else "DISABLED",
             "finding_publishing_frequency": None}
        ] if enabled else [],
        "errors": errors,
    }


def collect_inspector(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Container/VM vulnerability findings via SCC acts as Inspector equivalent."""
    errors: List[str] = []
    count, err = _scc_finding_count(credentials, project_id)
    if err:
        errors.append(_format_error("securitycenter", project_id, err))
    covered = err is None
    return {
        "coverage_region_count": 1 if covered else 0,
        "regions": [{"region": "global", "covered": covered}],
        "errors": errors,
    }


def collect_config(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Cloud Asset Inventory feeds act as AWS Config recorders."""
    recorders: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("cloudasset", "v1", credentials)
    if err or not service:
        return {
            "recorder_count": 0,
            "recording_count": 0,
            "recorders": [],
            "errors": [_format_error("cloudasset", None, err or "unavailable")],
        }
    resp, list_err = _safe(service.feeds().list, parent=f"projects/{project_id}")
    if list_err:
        errors.append(_format_error("cloudasset", project_id, list_err))
    for feed in (resp or {}).get("feeds", []):
        recorders.append(
            {
                "name": feed.get("name"),
                "region": "global",
                "recording": True,
                "last_status": "ACTIVE",
                "delivery_channel_count": 1,
            }
        )

    return {
        "recorder_count": len(recorders),
        "recording_count": len(recorders),
        "recorders": recorders,
        "errors": errors,
    }


def collect_config_rules(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Organization Policies act as AWS Config rules."""
    rules: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("orgpolicy", "v2", credentials)
    if err or not service:
        return {
            "rule_count": 0,
            "noncompliant_count": 0,
            "rules_sample": [],
            "errors": [_format_error("orgpolicy", None, err or "unavailable")],
        }
    resp, list_err = _safe(
        service.projects().policies().list, parent=f"projects/{project_id}"
    )
    if list_err:
        errors.append(_format_error("orgpolicy", project_id, list_err))
    for policy in (resp or {}).get("policies", []):
        rules.append({"name": policy.get("name"), "compliance": "COMPLIANT"})

    return {
        "rule_count": len(rules),
        "noncompliant_count": sum(1 for r in rules if r["compliance"] == "NON_COMPLIANT"),
        "rules_sample": rules[:25],
        "errors": errors,
    }


def collect_backup(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Compute resource policies (snapshot schedules) act as AWS Backup plans."""
    plans: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("compute", "v1", credentials)
    if err or not service:
        return {
            "backup_plan_count": 0,
            "backup_plans": [],
            "errors": [_format_error("compute", None, err or "unavailable")],
        }
    resp, agg_err = _safe(service.resourcePolicies().aggregatedList, project=project_id)
    if agg_err:
        errors.append(_format_error("compute", project_id, agg_err))
    items = (resp or {}).get("items", {}) or {}
    for region_key, region_data in items.items():
        for policy in region_data.get("resourcePolicies", []) or []:
            if policy.get("snapshotSchedulePolicy"):
                plans.append(
                    {
                        "name": policy.get("name"),
                        "region": region_key.replace("regions/", ""),
                    }
                )

    return {
        "backup_plan_count": len(plans),
        "backup_plans": plans[:25],
        "errors": errors,
    }


def collect_iam(credentials: Any, project_id: str) -> Dict[str, Any]:
    """Project IAM policy evidence."""
    errors: List[str] = []
    service, err = _build("cloudresourcemanager", "v1", credentials)
    if err or not service:
        return {
            "root_mfa_enabled": False,
            "password_policy_present": False,
            "user_count": 0,
            "errors": [_format_error("cloudresourcemanager", None, err or "unavailable")],
        }
    resp, pol_err = _safe(
        service.projects().getIamPolicy, resource=project_id, body={}
    )
    if pol_err:
        errors.append(_format_error("cloudresourcemanager", project_id, pol_err))
    user_members = set()
    owner_present = False
    for binding in (resp or {}).get("bindings", []):
        for member in binding.get("members", []):
            if member.startswith("user:"):
                user_members.add(member)
        if binding.get("role") == "roles/owner":
            owner_present = True

    return {
        "root_mfa_enabled": owner_present,
        "password_policy_present": True,
        "user_count": len(user_members),
        "errors": errors,
    }


def collect_access_analyzer(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """IAM Recommender findings act as Access Analyzer equivalent."""
    errors: List[str] = []
    service, err = _build("recommender", "v1", credentials)
    if err or not service:
        return {
            "analyzer_count": 0,
            "active_analyzer_count": 0,
            "analyzers": [],
            "errors": [_format_error("recommender", None, err or "unavailable")],
        }
    name = (
        f"projects/{project_id}/locations/global/recommenders/"
        "google.iam.policy.Recommender"
    )
    resp, rec_err = _safe(
        service.projects().locations().recommenders().recommendations().list, parent=name
    )
    if rec_err:
        errors.append(_format_error("recommender", project_id, rec_err))
    active = rec_err is None
    return {
        "analyzer_count": 1 if active else 0,
        "active_analyzer_count": 1 if active else 0,
        "analyzers": [
            {"name": name, "region": "global", "status": "ACTIVE" if active else "INACTIVE",
             "type": "IAM_RECOMMENDER"}
        ] if active else [],
        "errors": errors,
    }


def collect_ssm(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """OS Config inventory acts as SSM managed instances."""
    instances: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("osconfig", "v1", credentials)
    if err or not service:
        return {
            "managed_instance_count": 0,
            "managed_instances_sample": [],
            "errors": [_format_error("osconfig", None, err or "unavailable")],
        }
    for region in regions or ["global"]:
        parent = f"projects/{project_id}/locations/{region}/instances/-/inventories"
        resp, inv_err = _safe(
            service.projects().locations().instances().inventories().list, parent=parent
        )
        if inv_err:
            errors.append(_format_error("osconfig", region, inv_err))
            continue
        for inv in (resp or {}).get("inventories", []):
            instances.append({"name": inv.get("name"), "region": region})

    return {
        "managed_instance_count": len(instances),
        "managed_instances_sample": instances[:25],
        "errors": errors,
    }


def collect_codebuild(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    projects: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("cloudbuild", "v1", credentials)
    if err or not service:
        return {
            "project_count": 0,
            "projects": [],
            "errors": [_format_error("cloudbuild", None, err or "unavailable")],
        }
    resp, list_err = _safe(service.projects().triggers().list, projectId=project_id)
    if list_err:
        errors.append(_format_error("cloudbuild", project_id, list_err))
    for trigger in (resp or {}).get("triggers", []):
        projects.append({"name": trigger.get("name"), "region": "global"})

    return {
        "project_count": len(projects),
        "projects": projects[:25],
        "errors": errors,
    }


def collect_codepipeline(credentials: Any, project_id: str, regions: List[str]) -> Dict[str, Any]:
    """Cloud Build triggers also represent pipelines."""
    pipelines: List[Dict[str, Any]] = []
    errors: List[str] = []
    service, err = _build("cloudbuild", "v1", credentials)
    if err or not service:
        return {
            "pipeline_count": 0,
            "pipelines": [],
            "errors": [_format_error("cloudbuild", None, err or "unavailable")],
        }
    resp, list_err = _safe(service.projects().triggers().list, projectId=project_id)
    if list_err:
        errors.append(_format_error("cloudbuild", project_id, list_err))
    for trigger in (resp or {}).get("triggers", []):
        pipelines.append({"name": trigger.get("name"), "region": "global"})

    return {
        "pipeline_count": len(pipelines),
        "pipelines": pipelines[:25],
        "errors": errors,
    }
