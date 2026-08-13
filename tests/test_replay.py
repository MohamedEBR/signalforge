from pathlib import Path

import pytest

from signalforge.engine import DetectionEngine
from signalforge.replay import (
    ReplayError,
    compact_report,
    load_scenario,
    replay_suite,
    write_report,
)

ROOT = Path(__file__).resolve().parents[1]


def test_full_replay_suite_is_green(engine: DetectionEngine) -> None:
    report = replay_suite(ROOT / "scenarios", engine)

    assert report.scenario_count == 5
    assert report.passed_scenarios == 5
    assert report.failed_scenarios == 0
    assert report.true_positives == 6
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.precision == 1.0
    assert report.recall == 1.0


def test_reports_include_summary_but_compact_output_omits_evidence(
    tmp_path: Path, engine: DetectionEngine
) -> None:
    report = replay_suite(ROOT / "scenarios", engine)
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    write_report(report, json_path, markdown_path)
    compact = compact_report(report)

    assert '"precision": 1.0' in json_path.read_text()
    assert "## Incident explanations" in markdown_path.read_text()
    assert "findings" not in compact["scenarios"][0]
    assert "incidents" not in compact["scenarios"][0]


def test_scenario_input_cannot_escape_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n")
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "scenario.yaml").write_text(
        "name: escape\ninputs: [../outside.jsonl]\n"
    )

    with pytest.raises(ReplayError, match="escapes"):
        load_scenario(scenario)


def test_empty_suite_is_rejected(tmp_path: Path, engine: DetectionEngine) -> None:
    with pytest.raises(ReplayError, match="no scenarios"):
        replay_suite(tmp_path, engine)
