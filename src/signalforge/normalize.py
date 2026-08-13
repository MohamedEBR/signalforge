from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from signalforge.models import Endpoint, Entity, SecurityEvent
from signalforge.util import parse_time, stable_id


class NormalizationError(ValueError):
    pass


def normalize(record: dict[str, Any], source_hint: str | None = None) -> SecurityEvent:
    source = source_hint or detect_source(record)
    normalizers: dict[str, Callable[[dict[str, Any]], SecurityEvent]] = {
        "aws.cloudtrail": normalize_cloudtrail,
        "microsoft.entra": normalize_entra,
        "sentinelflow": normalize_sentinelflow,
        "aegis.audit": normalize_aegis,
        "application.auth": normalize_application_auth,
    }
    if source not in normalizers:
        raise NormalizationError(f"unsupported source {source!r}")
    try:
        return normalizers[source](record)
    except (KeyError, TypeError, ValueError) as error:
        raise NormalizationError(f"invalid {source} event: {error}") from error


def detect_source(record: dict[str, Any]) -> str:
    if record.get("eventSource") and record.get("eventName"):
        return "aws.cloudtrail"
    if record.get("conditionalAccessStatus") is not None or record.get(
        "activityDisplayName"
    ):
        return "microsoft.entra"
    if record.get("schema_version") == "nids.alert.v1":
        return "sentinelflow"
    if record.get("type") and record.get("sequence") and record.get("hash"):
        return "aegis.audit"
    if record.get("schema_version") == "application.auth.v1":
        return "application.auth"
    raise NormalizationError("source could not be detected")


def normalize_cloudtrail(record: dict[str, Any]) -> SecurityEvent:
    when = parse_time(record["eventTime"])
    identity = record.get("userIdentity") or {}
    principal = str(
        identity.get("arn")
        or identity.get("principalId")
        or identity.get("userName")
        or "unknown"
    )
    target_account = str(
        record.get("recipientAccountId")
        or (record.get("requestParameters") or {}).get("roleArn")
        or "unknown"
    )
    error = record.get("errorCode")
    source_ip = valid_ip(record.get("sourceIPAddress"))
    activity = str(record["eventName"])
    observables: dict[str, str | int | float | bool] = {
        "event_source": str(record["eventSource"]),
        "user_type": str(identity.get("type") or "unknown"),
        "mfa_authenticated": str(
            ((identity.get("sessionContext") or {}).get("attributes") or {}).get(
                "mfaAuthenticated", "unknown"
            )
        ).lower(),
    }
    parameters = record.get("requestParameters") or {}
    request_observables = {
        "userName": "request_user_name",
        "roleArn": "role_arn",
        "roleSessionName": "role_session_name",
        "accessKeyId": "access_key_id",
    }
    for source_key, observable_key in request_observables.items():
        if parameters.get(source_key) is not None:
            observables[observable_key] = str(parameters[source_key])
    return SecurityEvent(
        id=str(record.get("eventID") or stable_id("AWS-", when, principal, activity)),
        time=when,
        source="aws.cloudtrail",
        category="identity_access",
        activity=activity,
        outcome="failure" if error else "success",
        severity="medium" if error else "informational",
        actor=Entity(type="cloud_principal", id=principal),
        source_endpoint=Endpoint(ip=source_ip),
        target=Entity(type="aws_account", id=target_account),
        observables=observables,
        raw_ref=str(record.get("eventID") or ""),
    )


def normalize_entra(record: dict[str, Any]) -> SecurityEvent:
    when = parse_time(record.get("createdDateTime") or record.get("activityDateTime"))
    activity = str(
        record.get("activityDisplayName") or record.get("activity") or "SignIn"
    )
    user = str(
        record.get("userPrincipalName")
        or record.get("initiatedBy", {}).get("user", {}).get("userPrincipalName")
        or record.get("userId")
        or "unknown"
    )
    status = record.get("status") or {}
    conditional_access = str(record.get("conditionalAccessStatus") or "unknown")
    failed = bool(status.get("errorCode")) or conditional_access in {
        "failure",
        "notAppliedFailure",
    }
    target_id = str(
        record.get("resourceDisplayName") or record.get("appDisplayName") or "entra"
    )
    targets = record.get("targetResources") or []
    if targets and isinstance(targets[0], dict):
        target_id = str(
            targets[0].get("id") or targets[0].get("displayName") or target_id
        )
    return SecurityEvent(
        id=str(record.get("id") or stable_id("ENTRA-", when, user, activity)),
        time=when,
        source="microsoft.entra",
        category="identity_access",
        activity=activity,
        outcome="failure" if failed else "success",
        severity="medium" if failed else "informational",
        actor=Entity(type="user", id=user, name=user),
        source_endpoint=Endpoint(ip=valid_ip(record.get("ipAddress"))),
        target=Entity(type="entra_resource", id=target_id),
        observables={
            "conditional_access": conditional_access,
            "risk_level": str(record.get("riskLevelAggregated") or "none"),
            "client_app": str(record.get("clientAppUsed") or "unknown"),
            "status_code": int(status.get("errorCode") or 0),
        },
        raw_ref=str(record.get("id") or ""),
    )


def normalize_sentinelflow(record: dict[str, Any]) -> SecurityEvent:
    when = parse_time(record["observed_at"])
    source = record.get("source") or {}
    destination = record.get("destination") or {}
    score = float(record.get("score") or 0.0)
    category = str(record.get("attack_category") or "network_anomaly")
    activity = "NetworkIntrusion:" + category
    return SecurityEvent(
        id=str(
            record.get("alert_id") or stable_id("NIDS-", when, record.get("flow_id"))
        ),
        time=when,
        source="sentinelflow",
        category="network_activity",
        activity=activity,
        outcome="success" if record.get("verdict") == "attack" else "unknown",
        severity=map_severity(record.get("severity")),
        actor=Entity(type="ip", id=str(source.get("ip") or "unknown")),
        source_endpoint=Endpoint(
            ip=valid_ip(source.get("ip")), port=optional_port(source.get("port"))
        ),
        target=Entity(
            type="network_endpoint", id=str(destination.get("ip") or "unknown")
        ),
        observables={
            "score": score,
            "sensor": str(record.get("sensor") or "unknown"),
            "protocol": str(record.get("protocol") or "unknown"),
            "destination_port": int(destination.get("port") or 0),
            "model_version": str(record.get("model_version") or "unknown"),
            "feature_coverage": float(record.get("feature_coverage") or 0.0),
        },
        labels=[category],
        raw_ref=str(record.get("flow_id") or ""),
    )


def normalize_aegis(record: dict[str, Any]) -> SecurityEvent:
    when = parse_time(record["timestamp"])
    details = record.get("details") or {}
    outcome_value = str(record.get("outcome") or "unknown")
    if outcome_value in {"success", "allowed", "issued"}:
        outcome = "success"
    elif outcome_value in {"failure", "failed", "denied", "revoked"}:
        outcome = "failure"
    else:
        outcome = "unknown"
    subject = str(record.get("subject") or record.get("actor") or "unknown")
    observables: dict[str, str | int | float | bool] = {}
    for key in ("jti", "reason", "audience", "policy_version", "certificate_bound"):
        value = details.get(key)
        if isinstance(value, (str, int, float, bool)):
            observables[key] = value
    observables["audit_action"] = str(record.get("action") or "unknown")
    observables["raw_outcome"] = outcome_value
    return SecurityEvent(
        id=stable_id("AEGIS-", record.get("sequence"), record.get("hash")),
        time=when,
        source="aegis.audit",
        category="identity_access",
        activity=str(record.get("type") or "unknown"),
        outcome=outcome,
        severity="high" if outcome == "failure" else "informational",
        actor=Entity(type="workload", id=subject),
        target=Entity(type="resource", id=str(record.get("resource") or "unknown")),
        observables=observables,
        raw_ref=str(record.get("sequence") or ""),
    )


def normalize_application_auth(record: dict[str, Any]) -> SecurityEvent:
    when = parse_time(record["time"])
    principal = str(record["principal"])
    failed = str(record.get("outcome")) == "failure"
    return SecurityEvent(
        id=str(record.get("id") or stable_id("APP-", when, principal)),
        time=when,
        source="application.auth",
        category="authentication",
        activity=str(record.get("activity") or "ApiAuthentication"),
        outcome="failure" if failed else "success",
        severity="medium" if failed else "informational",
        actor=Entity(type="api_principal", id=principal),
        source_endpoint=Endpoint(ip=valid_ip(record.get("source_ip"))),
        target=Entity(type="api", id=str(record.get("target") or "unknown")),
        observables={"reason": str(record.get("reason") or "unknown")},
        raw_ref=str(record.get("id") or ""),
    )


def valid_ip(value: Any) -> str | None:
    if value in (None, "", "AWS Internal", "AWS Internal/#"):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def optional_port(value: Any) -> int | None:
    if value is None:
        return None
    port = int(value)
    return port if 0 <= port <= 65535 else None


def map_severity(value: Any) -> str:
    normalized = str(value or "informational").lower()
    if normalized in {"informational", "low", "medium", "high", "critical"}:
        return normalized
    return "medium"


def generated_at() -> datetime:
    return datetime.now(tz=UTC)
