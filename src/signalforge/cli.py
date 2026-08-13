from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from signalforge.engine import DetectionEngine, evaluate_with_timing
from signalforge.incidents import correlate
from signalforge.models import SecurityEvent
from signalforge.normalize import NormalizationError, normalize
from signalforge.replay import ReplayError, compact_report, replay_suite, write_report
from signalforge.rules import RuleError, load_rules
from signalforge.util import load_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signalforge",
        description="Normalize, detect, correlate, and replay security telemetry.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-rules", help="validate rule contracts")
    validate.add_argument("rules", type=Path)

    normalize_command = subparsers.add_parser("normalize", help="normalize raw JSONL")
    normalize_command.add_argument("input", type=Path)
    normalize_command.add_argument("--source")
    normalize_command.add_argument("--output", type=Path)

    detect = subparsers.add_parser("detect", help="run rules on normalized JSONL")
    detect.add_argument("input", type=Path)
    detect.add_argument("--rules", type=Path, default=Path("rules"))
    detect.add_argument("--output", type=Path)

    replay = subparsers.add_parser("replay", help="run labeled deterministic scenarios")
    replay.add_argument("scenarios", type=Path)
    replay.add_argument("--rules", type=Path, default=Path("rules"))
    replay.add_argument("--json", type=Path, default=Path("reports/replay.json"))
    replay.add_argument("--markdown", type=Path, default=Path("reports/replay.md"))

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "validate-rules":
            rules = load_rules(arguments.rules)
            print(json.dumps({"status": "valid", "rule_count": len(rules)}, indent=2))
        elif arguments.command == "normalize":
            events = [
                normalize(record, arguments.source)
                for record in load_jsonl(arguments.input)
            ]
            emit_jsonl(events, arguments.output)
        elif arguments.command == "detect":
            rules = load_rules(arguments.rules)
            events = [
                SecurityEvent.model_validate(record)
                for record in load_jsonl(arguments.input)
            ]
            findings, engine_ms = evaluate_with_timing(DetectionEngine(rules), events)
            incidents = correlate(findings, events, rules)
            result = {
                "event_count": len(events),
                "finding_count": len(findings),
                "incident_count": len(incidents),
                "engine_ms": engine_ms,
                "findings": [item.model_dump(mode="json") for item in findings],
                "incidents": [item.model_dump(mode="json") for item in incidents],
            }
            emit_json(result, arguments.output)
        elif arguments.command == "replay":
            report = replay_suite(
                arguments.scenarios, DetectionEngine(load_rules(arguments.rules))
            )
            write_report(report, arguments.json, arguments.markdown)
            print(json.dumps(compact_report(report), indent=2))
            if report.failed_scenarios:
                raise SystemExit(1)
    except (
        RuleError,
        ReplayError,
        NormalizationError,
        ValidationError,
        TypeError,
        ValueError,
    ) as error:
        parser.error(str(error))


def emit_jsonl(items: list[SecurityEvent], output: Path | None) -> None:
    content = "".join(item.model_dump_json() + "\n" for item in items)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


def emit_json(value: object, output: Path | None) -> None:
    content = json.dumps(value, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


if __name__ == "__main__":
    main()
