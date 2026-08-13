import json
from pathlib import Path

from signalforge.engine import DetectionEngine
from signalforge.incidents import correlate
from signalforge.models import DetectionRule
from signalforge.normalize import normalize

ROOT = Path(__file__).resolve().parents[1]


def test_cross_source_findings_correlate_with_safe_response_plans(
    rules: list[DetectionRule],
) -> None:
    lines = (ROOT / "scenarios/network_api/events.jsonl").read_text().splitlines()
    events = [normalize(json.loads(line)) for line in lines if line]
    selected = [
        rule
        for rule in rules
        if rule.id in {"SF-NETWORK-AUTH-CORRELATION", "SF-SENTINELFLOW-CRITICAL"}
    ]
    findings = DetectionEngine(selected).evaluate(events)

    incidents = correlate(findings, events, selected)

    assert len(findings) == 2
    assert len(incidents) == 1
    assert set(incidents[0].rule_ids) == {
        "SF-NETWORK-AUTH-CORRELATION",
        "SF-SENTINELFLOW-CRITICAL",
    }
    assert all(
        plan.status == "pending_approval" for plan in incidents[0].response_plans
    )
    assert all(not plan.executable for plan in incidents[0].response_plans)
    assert {plan.target for plan in incidents[0].response_plans} == {"198.51.100.88"}
    assert "non-executable" in incidents[0].explanation


def test_sequence_response_uses_latest_relevant_target(
    rules: list[DetectionRule],
) -> None:
    lines = (ROOT / "scenarios/entra_privilege/events.jsonl").read_text().splitlines()
    events = [normalize(json.loads(line)) for line in lines if line]
    selected = [rule for rule in rules if rule.id == "SF-ENTRA-PRIVILEGE-SEQUENCE"]
    incidents = correlate(DetectionEngine(selected).evaluate(events), events, selected)

    targets = {plan.action: plan.target for plan in incidents[0].response_plans}
    assert targets["revoke_user_sessions"] == "alice@example.test"
    assert targets["remove_role_assignment"] == "Global Administrator"


def test_findings_without_shared_entities_remain_separate(
    rules: list[DetectionRule],
) -> None:
    aws_lines = (
        (ROOT / "scenarios/aws_role_chain/events.jsonl").read_text().splitlines()
    )
    aegis_lines = (
        (ROOT / "scenarios/aegis_revoked/events.jsonl").read_text().splitlines()
    )
    events = [
        normalize(json.loads(line)) for line in [*aws_lines, *aegis_lines] if line
    ]
    selected = [
        rule
        for rule in rules
        if rule.id in {"SF-AWS-ACCESS-KEY-ROLE-CHAIN", "SF-AEGIS-REVOKED-USE"}
    ]
    findings = DetectionEngine(selected).evaluate(events)

    assert len(correlate(findings, events, selected)) == 2
