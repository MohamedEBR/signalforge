from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from signalforge.models import (
    DetectionRule,
    Entity,
    Finding,
    Incident,
    ResponsePlan,
    SecurityEvent,
)
from signalforge.util import stable_id, unique_ordered

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def correlate(
    findings: list[Finding],
    events: list[SecurityEvent],
    rules: list[DetectionRule],
    *,
    window: timedelta = timedelta(minutes=30),
) -> list[Incident]:
    if not findings:
        return []
    event_index = {event.id: event for event in events}
    rule_index = {rule.id: rule for rule in rules}
    parent = list(range(len(findings)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parent[right_root] = left_root

    entity_to_findings: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, finding in enumerate(findings):
        for entity in finding.entities:
            entity_to_findings[(entity.type, entity.id)].append(index)
    for indexes in entity_to_findings.values():
        for left_position, left in enumerate(indexes):
            for right in indexes[left_position + 1 :]:
                if abs(findings[right].first_seen - findings[left].last_seen) <= window:
                    union(left, right)

    groups: dict[int, list[Finding]] = defaultdict(list)
    for index, finding in enumerate(findings):
        groups[root(index)].append(finding)
    return sorted(
        [
            build_incident(group, event_index=event_index, rule_index=rule_index)
            for group in groups.values()
        ],
        key=lambda incident: (incident.first_seen, incident.id),
    )


def build_incident(
    findings: list[Finding],
    *,
    event_index: dict[str, SecurityEvent],
    rule_index: dict[str, DetectionRule],
) -> Incident:
    findings = sorted(findings, key=lambda item: (item.first_seen, item.id))
    entities: dict[tuple[str, str], Entity] = {}
    for finding in findings:
        for entity in finding.entities:
            entities[(entity.type, entity.id)] = entity
    rule_ids = unique_ordered(item.rule_id for item in findings)
    event_ids = unique_ordered(
        event_id for finding in findings for event_id in finding.matched_event_ids
    )
    events = sorted(
        [event_index[event_id] for event_id in event_ids if event_id in event_index],
        key=lambda event: (event.time, event.id),
    )
    response_plans: list[ResponsePlan] = []
    seen_actions: set[tuple[str, str | None]] = set()
    for rule_id in rule_ids:
        rule = rule_index[rule_id]
        for response in rule.responses:
            target = None
            for event in reversed(events):
                value = event.field_value(response.target_field)
                if value is not None:
                    target = str(value)
                    break
            signature = (response.action, target)
            if signature not in seen_actions:
                seen_actions.add(signature)
                response_plans.append(
                    ResponsePlan(
                        action=response.action,
                        target=target,
                        description=response.description,
                    )
                )
    severity = max(findings, key=lambda item: SEVERITY_RANK[item.severity]).severity
    sources = unique_ordered(event.source for event in events)
    confidence = min(0.98, 0.55 + 0.08 * len(rule_ids) + 0.05 * len(sources))
    timeline = [
        (
            f"{event.time.isoformat()} — {event.source} {event.activity} "
            f"({event.outcome}) [{event.id}]"
        )
        for event in events
    ]
    principal_entities = [
        entity for entity in entities.values() if entity.type not in {"ip"}
    ]
    entity_summary = (
        ", ".join(f"{entity.type}:{entity.id}" for entity in principal_entities[:3])
        or "shared security entities"
    )
    explanation = (
        f"SignalForge correlated {len(findings)} finding(s) from "
        f"{len(sources)} source(s) around {entity_summary}. "
        f"The evidence spans {len(events)} ordered event(s); proposed actions remain "
        "non-executable pending explicit human approval."
    )
    identifier = stable_id("INC-", *sorted(item.id for item in findings))
    return Incident(
        id=identifier,
        title=" / ".join(unique_ordered(item.rule_name for item in findings)),
        severity=severity,
        confidence=round(confidence, 2),
        first_seen=min(item.first_seen for item in findings),
        last_seen=max(item.last_seen for item in findings),
        finding_ids=[item.id for item in findings],
        rule_ids=rule_ids,
        entities=list(entities.values()),
        evidence=[item for finding in findings for item in finding.evidence],
        timeline=timeline,
        tactics=unique_ordered(
            item for finding in findings for item in finding.tactics
        ),
        techniques=unique_ordered(
            item for finding in findings for item in finding.techniques
        ),
        response_plans=response_plans,
        explanation=explanation,
    )
