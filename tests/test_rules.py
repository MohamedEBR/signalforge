from datetime import UTC, datetime
from pathlib import Path

import pytest

from signalforge.models import (
    DetectionRule,
    Endpoint,
    EventMatch,
    Predicate,
    SecurityEvent,
)
from signalforge.rules import (
    RuleError,
    event_matches,
    load_rules,
    predicate_matches,
    validate_predicate,
    validate_rule,
)


def sample_event() -> SecurityEvent:
    return SecurityEvent(
        id="event-1",
        time=datetime(2026, 8, 13, tzinfo=UTC),
        source="application.auth",
        category="authentication",
        activity="ApiAuthentication",
        outcome="failure",
        source_endpoint=Endpoint(ip="198.51.100.10"),
        observables={"score": 0.97, "reason": "invalid_signature"},
    )


def test_repository_rules_load_and_are_unique(rules: list[DetectionRule]) -> None:
    assert len(rules) == 6
    assert len({rule.id for rule in rules}) == len(rules)
    assert all(rule.runbook for rule in rules)
    assert all(rule.techniques for rule in rules)


@pytest.mark.parametrize(
    ("predicate", "expected"),
    [
        (Predicate(field="outcome", op="eq", value="failure"), True),
        (Predicate(field="outcome", op="ne", value="success"), True),
        (Predicate(field="outcome", op="in", value=["failure"]), True),
        (Predicate(field="outcome", op="not_in", value=["success"]), True),
        (Predicate(field="source_endpoint.ip", op="exists", value=True), True),
        (Predicate(field="observables.reason", op="contains", value="signature"), True),
        (Predicate(field="observables.reason", op="regex", value="^invalid_"), True),
        (
            Predicate(field="source_endpoint.ip", op="cidr", value="198.51.100.0/24"),
            True,
        ),
        (Predicate(field="observables.score", op="gte", value=0.9), True),
        (Predicate(field="observables.score", op="lte", value=1), True),
    ],
)
def test_predicate_operators(predicate: Predicate, expected: bool) -> None:
    assert predicate_matches(sample_event(), predicate) is expected


def test_matcher_requires_all_and_honors_exclusions() -> None:
    matcher = EventMatch(
        sources=["application.auth"],
        outcomes=["failure"],
        all=[Predicate(field="observables.score", op="gte", value=0.9)],
        none=[Predicate(field="source_endpoint.ip", op="cidr", value="10.0.0.0/8")],
    )

    assert event_matches(sample_event(), matcher)


@pytest.mark.parametrize(
    "predicate",
    [
        Predicate(field="bad-field!", value="x"),
        Predicate(field="outcome", op="exists", value="yes"),
        Predicate(field="outcome", op="in", value="failure"),
        Predicate(field="actor.id", op="regex", value="(a+)+$"),
        Predicate(field="source_endpoint.ip", op="cidr", value="not-a-network"),
    ],
)
def test_unsafe_or_malformed_predicates_are_rejected(predicate: Predicate) -> None:
    with pytest.raises(RuleError):
        validate_predicate(predicate, "TEST")


def test_rule_rejects_unbounded_window_and_undeclared_source(
    rules: list[DetectionRule],
) -> None:
    rule = rules[0].model_copy(deep=True)
    rule.window = "8d"
    with pytest.raises(RuleError, match="seven days"):
        validate_rule(rule)

    rule = rules[0].model_copy(deep=True)
    rule.stages[0].match.sources = ["undeclared.source"]
    with pytest.raises(RuleError, match="undeclared source"):
        validate_rule(rule)


def test_rule_loader_rejects_duplicate_ids(
    tmp_path: Path, rules: list[DetectionRule]
) -> None:
    document = rules[0].model_dump(mode="json", exclude_none=True)
    import yaml

    (tmp_path / "one.yaml").write_text(yaml.safe_dump(document))
    (tmp_path / "two.yaml").write_text(yaml.safe_dump(document))

    with pytest.raises(RuleError, match="duplicate rule ID"):
        load_rules(tmp_path)
