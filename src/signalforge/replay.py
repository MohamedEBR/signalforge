from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

import yaml
from pydantic import ValidationError

from signalforge.engine import DetectionEngine, evaluate_with_timing, median_runtime
from signalforge.incidents import correlate
from signalforge.models import (
    ReplayReport,
    ScenarioExpectation,
    ScenarioResult,
    SecurityEvent,
)
from signalforge.normalize import normalize
from signalforge.util import load_jsonl


class ReplayError(ValueError):
    pass


def load_scenario(path: Path) -> tuple[str, list[SecurityEvent], ScenarioExpectation]:
    manifest_path = path / "scenario.yaml"
    if not manifest_path.exists():
        raise ReplayError(f"{path}: scenario.yaml is missing")
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ReplayError(f"{manifest_path}: invalid YAML") from error
    if not isinstance(manifest, dict):
        raise ReplayError(f"{manifest_path}: manifest must be an object")
    name = str(manifest.get("name") or path.name)
    inputs = manifest.get("inputs") or ["events.jsonl"]
    if not isinstance(inputs, list) or len(inputs) > 16:
        raise ReplayError(f"{manifest_path}: inputs must contain at most 16 files")
    try:
        expectation = ScenarioExpectation.model_validate(manifest)
    except ValidationError as error:
        raise ReplayError(f"{manifest_path}: invalid expectations: {error}") from error
    events: list[SecurityEvent] = []
    for relative in inputs:
        input_path = (path / str(relative)).resolve()
        if path.resolve() not in input_path.parents:
            raise ReplayError(f"{manifest_path}: input escapes the scenario directory")
        for record in load_jsonl(input_path):
            events.append(normalize(record))
    return name, sorted(events, key=lambda event: (event.time, event.id)), expectation


def replay_scenario(path: Path, engine: DetectionEngine) -> ScenarioResult:
    name, events, expectation = load_scenario(path)
    findings, engine_ms = evaluate_with_timing(engine, events)
    incidents = correlate(findings, events, engine.rules)
    fired = sorted({finding.rule_id for finding in findings})
    missing = sorted(set(expectation.expected_rules) - set(fired))
    unexpected = sorted(set(expectation.forbidden_rules) & set(fired))
    return ScenarioResult(
        name=name,
        event_count=len(events),
        finding_count=len(findings),
        incident_count=len(incidents),
        fired_rules=fired,
        expected_rules=sorted(expectation.expected_rules),
        forbidden_rules=sorted(expectation.forbidden_rules),
        passed=not missing and not unexpected,
        missing_rules=missing,
        unexpected_rules=unexpected,
        engine_ms=engine_ms,
        findings=findings,
        incidents=incidents,
    )


def replay_suite(path: Path, engine: DetectionEngine) -> ReplayReport:
    started = perf_counter()
    scenario_paths = sorted(
        item
        for item in path.iterdir()
        if item.is_dir() and (item / "scenario.yaml").exists()
    )
    if not scenario_paths:
        raise ReplayError(f"no scenarios found in {path}")
    scenarios = [replay_scenario(item, engine) for item in scenario_paths]
    true_positives = sum(
        len(set(item.fired_rules) & set(item.expected_rules)) for item in scenarios
    )
    false_positives = sum(len(item.unexpected_rules) for item in scenarios)
    false_negatives = sum(len(item.missing_rules) for item in scenarios)
    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 1.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else 1.0
    )
    _ = perf_counter() - started
    return ReplayReport(
        generated_at=datetime.now(tz=UTC),
        scenario_count=len(scenarios),
        passed_scenarios=sum(item.passed for item in scenarios),
        failed_scenarios=sum(not item.passed for item in scenarios),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        median_engine_ms=median_runtime([item.engine_ms for item in scenarios]),
        scenarios=scenarios,
    )


def write_report(report: ReplayReport, json_path: Path, markdown_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")


def render_markdown(report: ReplayReport) -> str:
    lines = [
        "# SignalForge replay report",
        "",
        f"Generated: {report.generated_at.isoformat()}",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Scenarios | {report.scenario_count} |",
        f"| Passed | {report.passed_scenarios} |",
        f"| Failed | {report.failed_scenarios} |",
        f"| Precision | {report.precision:.4f} |",
        f"| Recall | {report.recall:.4f} |",
        f"| Median engine time | {report.median_engine_ms:.3f} ms |",
        "",
        "## Scenarios",
        "",
        "| Scenario | Events | Findings | Incidents | Rules | Result |",
        "|---|---:|---:|---:|---|---|",
    ]
    for scenario in report.scenarios:
        result = "PASS" if scenario.passed else "FAIL"
        rules = ", ".join(scenario.fired_rules) or "none"
        lines.append(
            f"| {scenario.name} | {scenario.event_count} | {scenario.finding_count} | "
            f"{scenario.incident_count} | {rules} | {result} |"
        )
    lines.extend(["", "## Incident explanations", ""])
    for scenario in report.scenarios:
        for incident in scenario.incidents:
            lines.extend(
                [
                    f"### {scenario.name}: {incident.id}",
                    "",
                    incident.explanation,
                    "",
                    f"- Severity: {incident.severity}",
                    f"- Confidence: {incident.confidence:.2f}",
                    f"- Rules: {', '.join(incident.rule_ids)}",
                    f"- ATT&CK: {', '.join(incident.techniques)}",
                    "- Response: "
                    + (
                        "; ".join(
                            f"{plan.action}({plan.target or 'unresolved'}) — pending approval"
                            for plan in incident.response_plans
                        )
                        or "investigate using the rule runbook"
                    ),
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def compact_report(report: ReplayReport) -> dict[str, Any]:
    return json.loads(
        report.model_dump_json(
            exclude={"scenarios": {"__all__": {"findings", "incidents"}}}
        )
    )
