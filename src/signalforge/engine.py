from __future__ import annotations

import statistics
import time
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime

from signalforge.models import DetectionRule, Entity, Finding, SecurityEvent
from signalforge.rules import event_matches
from signalforge.util import parse_duration, stable_id, unique_ordered


class DetectionEngine:
    def __init__(self, rules: Iterable[DetectionRule]):
        self.rules = list(rules)

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Finding]:
        ordered = sorted(events, key=lambda event: (event.time, event.id))
        findings: list[Finding] = []
        detected_at = datetime.now(tz=UTC)
        for rule in self.rules:
            if rule.status == "deprecated":
                continue
            if rule.type == "match":
                findings.extend(self._match(rule, ordered, detected_at))
            elif rule.type == "threshold":
                findings.extend(self._threshold(rule, ordered, detected_at))
            else:
                findings.extend(self._sequence(rule, ordered, detected_at))
        return sorted(
            findings, key=lambda item: (item.first_seen, item.rule_id, item.id)
        )

    def _match(
        self, rule: DetectionRule, events: list[SecurityEvent], detected_at: datetime
    ) -> list[Finding]:
        assert rule.match is not None
        return [
            build_finding(rule, [event], detected_at)
            for event in events
            if event_matches(event, rule.match)
        ]

    def _threshold(
        self, rule: DetectionRule, events: list[SecurityEvent], detected_at: datetime
    ) -> list[Finding]:
        assert rule.match is not None
        groups = group_events(
            [event for event in events if event_matches(event, rule.match)],
            rule.group_by,
        )
        window = parse_duration(rule.window)
        findings: list[Finding] = []
        for grouped_events in groups.values():
            start = 0
            index = 0
            while index < len(grouped_events):
                while grouped_events[index].time - grouped_events[start].time > window:
                    start += 1
                if index - start + 1 >= rule.threshold:
                    matched = grouped_events[start : index + 1]
                    findings.append(build_finding(rule, matched, detected_at))
                    start = index + 1
                index += 1
        return findings

    def _sequence(
        self, rule: DetectionRule, events: list[SecurityEvent], detected_at: datetime
    ) -> list[Finding]:
        groups = group_events(events, rule.group_by)
        window = parse_duration(rule.window)
        findings: list[Finding] = []
        first_matcher = rule.stages[0].match
        for grouped_events in groups.values():
            start_index = 0
            while start_index < len(grouped_events):
                start_event = grouped_events[start_index]
                if not event_matches(start_event, first_matcher):
                    start_index += 1
                    continue
                matched = [start_event]
                matched_indexes = [start_index]
                stage_index = 1
                for candidate_index, candidate in enumerate(
                    grouped_events[start_index + 1 :], start=start_index + 1
                ):
                    if candidate.time - start_event.time > window:
                        break
                    if event_matches(candidate, rule.stages[stage_index].match):
                        matched.append(candidate)
                        matched_indexes.append(candidate_index)
                        stage_index += 1
                        if stage_index == len(rule.stages):
                            break
                if stage_index != len(rule.stages):
                    start_index += 1
                    continue
                findings.append(build_finding(rule, matched, detected_at))
                start_index = matched_indexes[-1] + 1
        return findings


def group_events(
    events: Iterable[SecurityEvent], group_by: list[str]
) -> dict[tuple[str, ...], list[SecurityEvent]]:
    groups: dict[tuple[str, ...], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        values = [event.field_value(path) for path in group_by]
        if any(value is None or value == "unknown" for value in values):
            continue
        groups[tuple(str(value) for value in values)].append(event)
    for grouped in groups.values():
        grouped.sort(key=lambda event: (event.time, event.id))
    return groups


def build_finding(
    rule: DetectionRule, events: list[SecurityEvent], detected_at: datetime
) -> Finding:
    entities: dict[tuple[str, str], Entity] = {}
    for event in events:
        for entity in event.entities():
            entities[(entity.type, entity.id)] = entity
    group = [
        str(events[0].field_value(path))
        for path in rule.group_by
        if events[0].field_value(path) is not None
    ]
    evidence = [
        (
            f"{event.time.isoformat()} {event.source}:{event.activity} "
            f"outcome={event.outcome} event={event.id}"
        )
        for event in events
    ]
    identifier = stable_id("FND-", rule.id, *(event.id for event in events))
    return Finding(
        id=identifier,
        rule_id=rule.id,
        rule_version=rule.version,
        rule_name=rule.name,
        severity=rule.severity,
        first_seen=events[0].time,
        last_seen=events[-1].time,
        detected_at=detected_at,
        group=group,
        matched_event_ids=[event.id for event in events],
        evidence=evidence,
        entities=list(entities.values()),
        tactics=unique_ordered(rule.tactics),
        techniques=unique_ordered(rule.techniques),
        runbook=rule.runbook,
    )


def evaluate_with_timing(
    engine: DetectionEngine, events: list[SecurityEvent]
) -> tuple[list[Finding], float]:
    started = time.perf_counter()
    findings = engine.evaluate(events)
    return findings, round((time.perf_counter() - started) * 1000, 3)


def median_runtime(values: list[float]) -> float:
    return round(statistics.median(values), 3) if values else 0.0
