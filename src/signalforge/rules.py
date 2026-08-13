from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from signalforge.models import DetectionRule, EventMatch, Predicate, SecurityEvent
from signalforge.util import parse_duration


class RuleError(ValueError):
    pass


def load_rules(path: Path) -> list[DetectionRule]:
    if not path.exists():
        raise RuleError(f"no YAML rules found in {path}")
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    if not files:
        raise RuleError(f"no YAML rules found in {path}")
    rules: list[DetectionRule] = []
    identifiers: set[str] = set()
    for file in files:
        if file.stat().st_size > 1_000_000:
            raise RuleError(f"{file}: rule file exceeds 1 MB")
        try:
            document = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            raise RuleError(f"{file}: invalid YAML: {error}") from error
        documents = document if isinstance(document, list) else [document]
        for raw in documents:
            try:
                rule = DetectionRule.model_validate(raw)
            except ValidationError as error:
                raise RuleError(f"{file}: invalid rule: {error}") from error
            validate_rule(rule, file)
            if rule.id in identifiers:
                raise RuleError(f"duplicate rule ID {rule.id}")
            identifiers.add(rule.id)
            rules.append(rule)
    return sorted(rules, key=lambda rule: rule.id)


def validate_rule(rule: DetectionRule, source: Path | None = None) -> None:
    prefix = f"{source}: " if source else ""
    if rule.type in {"match", "threshold"} and rule.match is None:
        raise RuleError(f"{prefix}{rule.id}: {rule.type} requires match")
    if rule.type == "sequence" and len(rule.stages) < 2:
        raise RuleError(f"{prefix}{rule.id}: sequence requires at least two stages")
    if rule.type != "sequence" and rule.stages:
        raise RuleError(f"{prefix}{rule.id}: stages are only valid for sequences")
    if rule.type != "match" and not rule.group_by:
        raise RuleError(f"{prefix}{rule.id}: {rule.type} requires group_by")
    try:
        parse_duration(rule.window)
    except ValueError as error:
        raise RuleError(f"{prefix}{rule.id}: {error}") from error
    matchers = [rule.match, *(stage.match for stage in rule.stages)]
    declared_sources = set(rule.required_sources)
    used_sources = {
        item for matcher in matchers if matcher is not None for item in matcher.sources
    }
    if used_sources and not used_sources.issubset(declared_sources):
        undeclared = ", ".join(sorted(used_sources - declared_sources))
        raise RuleError(f"{prefix}{rule.id}: undeclared source(s): {undeclared}")
    for field in [*rule.group_by, *(item.target_field for item in rule.responses)]:
        validate_field(field, prefix + rule.id)
    for matcher in matchers:
        if matcher is None:
            continue
        for predicate in [*matcher.all, *matcher.none]:
            validate_predicate(predicate, prefix + rule.id)


def validate_predicate(predicate: Predicate, prefix: str) -> None:
    validate_field(predicate.field, prefix)
    if predicate.op in {"in", "not_in"} and not isinstance(predicate.value, list):
        raise RuleError(f"{prefix}: {predicate.op} predicate requires a list")
    if predicate.op in {"in", "not_in"} and len(predicate.value) > 256:
        raise RuleError(f"{prefix}: {predicate.op} list cannot exceed 256 values")
    if predicate.op == "exists" and not isinstance(predicate.value, bool):
        raise RuleError(f"{prefix}: exists predicate requires a boolean")
    if predicate.op == "regex":
        if not isinstance(predicate.value, str) or len(predicate.value) > 256:
            raise RuleError(f"{prefix}: regex must be a string of at most 256 chars")
        try:
            re.compile(predicate.value)
        except re.error as error:
            raise RuleError(f"{prefix}: invalid regex: {error}") from error
        unsafe_regex_features = [
            r"\\[1-9]",  # backreferences
            r"\(\?[=!<]",  # lookaround
            r"\([^)]*(?:[*+]|\{\d+(?:,\d*)?\})[^)]*\)(?:[*+]|\{\d+(?:,\d*)?\})",
            r"(?:[*+]|\{\d+(?:,\d*)?\})(?:[*+]|\{\d+(?:,\d*)?\})",
        ]
        if any(
            re.search(pattern, predicate.value) for pattern in unsafe_regex_features
        ):
            raise RuleError(
                f"{prefix}: regex uses nested quantifiers, backreferences, or lookaround"
            )
    if predicate.op == "cidr":
        try:
            ipaddress.ip_network(str(predicate.value), strict=False)
        except ValueError as error:
            raise RuleError(f"{prefix}: invalid CIDR {predicate.value!r}") from error


def validate_field(field: str, prefix: str) -> None:
    if len(field) > 128 or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.]{0,127}", field):
        raise RuleError(f"{prefix}: invalid field {field!r}")


def event_matches(event: SecurityEvent, matcher: EventMatch) -> bool:
    if matcher.sources and event.source not in matcher.sources:
        return False
    if matcher.activities and event.activity not in matcher.activities:
        return False
    if matcher.outcomes and event.outcome not in matcher.outcomes:
        return False
    if not all(predicate_matches(event, item) for item in matcher.all):
        return False
    return not any(predicate_matches(event, item) for item in matcher.none)


def predicate_matches(event: SecurityEvent, predicate: Predicate) -> bool:
    actual = event.field_value(predicate.field)
    expected = predicate.value
    try:
        if predicate.op == "exists":
            return (actual is not None) is bool(expected)
        if predicate.op == "eq":
            return actual == expected
        if predicate.op == "ne":
            return actual != expected
        if predicate.op == "in":
            return actual in expected
        if predicate.op == "not_in":
            return actual not in expected
        if predicate.op == "contains":
            return expected in actual
        if predicate.op == "regex":
            return re.search(expected, str(actual)) is not None
        if predicate.op == "cidr":
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                str(expected), strict=False
            )
        if predicate.op == "gte":
            return float(actual) >= float(expected)
        if predicate.op == "lte":
            return float(actual) <= float(expected)
    except (TypeError, ValueError):
        return False
    return False
