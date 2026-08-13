import json
from pathlib import Path

from signalforge.engine import DetectionEngine
from signalforge.models import DetectionRule
from signalforge.normalize import normalize

ROOT = Path(__file__).resolve().parents[1]


def scenario_events(name: str):
    lines = (ROOT / "scenarios" / name / "events.jsonl").read_text().splitlines()
    return [normalize(json.loads(line)) for line in lines if line]


def select_rule(rules: list[DetectionRule], rule_id: str) -> DetectionRule:
    return next(rule for rule in rules if rule.id == rule_id)


def test_sequence_is_time_ordered_and_non_overlapping(
    rules: list[DetectionRule],
) -> None:
    events = list(reversed(scenario_events("entra_privilege")))
    rule = select_rule(rules, "SF-ENTRA-PRIVILEGE-SEQUENCE")

    findings = DetectionEngine([rule]).evaluate(events)

    assert len(findings) == 1
    assert findings[0].matched_event_ids == [
        "entra-fail-1",
        "entra-success-1",
        "entra-role-1",
    ]


def test_threshold_consumes_a_completed_window(rules: list[DetectionRule]) -> None:
    events = scenario_events("entra_privilege")
    rule = select_rule(rules, "SF-ENTRA-CA-FAILURE-BURST")

    findings = DetectionEngine([rule]).evaluate(events)

    assert len(findings) == 1
    assert findings[0].matched_event_ids == [
        "entra-fail-1",
        "entra-fail-2",
        "entra-fail-3",
    ]


def test_missing_group_key_fails_closed(rules: list[DetectionRule]) -> None:
    events = scenario_events("entra_privilege")
    for event in events:
        if event.source_endpoint:
            event.source_endpoint.ip = None
    rule = select_rule(rules, "SF-ENTRA-CA-FAILURE-BURST")

    assert DetectionEngine([rule]).evaluate(events) == []


def test_automation_exclusion_prevents_finding(rules: list[DetectionRule]) -> None:
    rule = select_rule(rules, "SF-AWS-ACCESS-KEY-ROLE-CHAIN")
    assert DetectionEngine([rule]).evaluate(scenario_events("benign_automation")) == []


def test_finding_id_and_evidence_are_deterministic(rules: list[DetectionRule]) -> None:
    rule = select_rule(rules, "SF-AWS-ACCESS-KEY-ROLE-CHAIN")
    engine = DetectionEngine([rule])
    events = scenario_events("aws_role_chain")

    first = engine.evaluate(events)[0]
    second = engine.evaluate(events)[0]

    assert first.id == second.id
    assert first.evidence == second.evidence
    assert first.group == ["arn:aws:iam::111122223333:user/alice"]


def test_deprecated_rules_are_skipped(rules: list[DetectionRule]) -> None:
    rule = select_rule(rules, "SF-SENTINELFLOW-CRITICAL").model_copy(deep=True)
    rule.status = "deprecated"

    assert DetectionEngine([rule]).evaluate(scenario_events("network_api")) == []
