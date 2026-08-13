from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from signalforge.engine import DetectionEngine
from signalforge.models import Endpoint, Entity, SecurityEvent
from signalforge.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]


def synthetic_events(count: int) -> list[SecurityEvent]:
    base = datetime(2026, 8, 13, tzinfo=UTC)
    events: list[SecurityEvent] = []
    for index in range(count):
        block = index // 1_000
        source_ip = f"198.51.100.{(block % 200) + 1}"
        signal_position = index % 1_000
        if signal_position == 0:
            events.append(
                SecurityEvent(
                    id=f"bench-nids-{index}",
                    time=base + timedelta(milliseconds=index),
                    source="sentinelflow",
                    category="network_activity",
                    activity="NetworkIntrusion:Reconnaissance",
                    outcome="success",
                    severity="critical",
                    actor=Entity(type="ip", id=source_ip),
                    source_endpoint=Endpoint(ip=source_ip, port=40_000),
                    target=Entity(type="network_endpoint", id="10.10.0.20"),
                    observables={"score": 0.991, "feature_coverage": 1.0},
                )
            )
        else:
            events.append(
                SecurityEvent(
                    id=f"bench-auth-{index}",
                    time=base + timedelta(milliseconds=index),
                    source="application.auth",
                    category="authentication",
                    activity="ApiAuthentication",
                    outcome="failure",
                    severity="medium",
                    actor=Entity(type="api_principal", id=f"principal-{index % 256}"),
                    source_endpoint=Endpoint(ip=source_ip),
                    target=Entity(type="api", id="payments-api"),
                    observables={"reason": "invalid_signature"},
                )
            )
    return events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=25_000)
    parser.add_argument("--iterations", type=int, default=7)
    parser.add_argument("--rules", type=Path, default=ROOT / "rules")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if not 1 <= arguments.events <= 1_000_000:
        parser.error("--events must be between 1 and 1,000,000")
    if not 1 <= arguments.iterations <= 100:
        parser.error("--iterations must be between 1 and 100")

    events = synthetic_events(arguments.events)
    engine = DetectionEngine(load_rules(arguments.rules))
    durations: list[float] = []
    finding_count = 0
    for _ in range(arguments.iterations):
        started = time.perf_counter()
        findings = engine.evaluate(events)
        durations.append((time.perf_counter() - started) * 1_000)
        finding_count = len(findings)
    median_ms = statistics.median(durations)
    sorted_durations = sorted(durations)
    p95_index = max(0, int(len(sorted_durations) * 0.95) - 1)
    report = {
        "schema_version": "signalforge.benchmark.v1",
        "event_count": arguments.events,
        "rule_count": len(engine.rules),
        "finding_count": finding_count,
        "iterations": arguments.iterations,
        "median_ms": round(median_ms, 3),
        "p95_ms": round(sorted_durations[p95_index], 3),
        "events_per_second": round(arguments.events / (median_ms / 1_000), 1),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    content = json.dumps(report, indent=2) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(content, encoding="utf-8")
    sys.stdout.write(content)


if __name__ == "__main__":
    main()
