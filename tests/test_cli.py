import json
from pathlib import Path

import pytest

from signalforge.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_validate_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    main(["validate-rules", str(ROOT / "rules")])

    result = json.loads(capsys.readouterr().out)
    assert result == {"status": "valid", "rule_count": 6}


def test_normalize_then_detect_commands(tmp_path: Path) -> None:
    normalized = tmp_path / "normalized.jsonl"
    result_path = tmp_path / "detections.json"

    main(
        [
            "normalize",
            str(ROOT / "scenarios/network_api/events.jsonl"),
            "--output",
            str(normalized),
        ]
    )
    main(
        [
            "detect",
            str(normalized),
            "--rules",
            str(ROOT / "rules"),
            "--output",
            str(result_path),
        ]
    )

    result = json.loads(result_path.read_text())
    assert result["event_count"] == 3
    assert result["finding_count"] == 2
    assert result["incident_count"] == 1


def test_normalize_can_emit_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    main(["normalize", str(ROOT / "scenarios/aegis_revoked/events.jsonl")])

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert {json.loads(line)["source"] for line in lines} == {"aegis.audit"}


def test_replay_command_writes_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    json_path = tmp_path / "replay.json"
    markdown_path = tmp_path / "replay.md"

    main(
        [
            "replay",
            str(ROOT / "scenarios"),
            "--rules",
            str(ROOT / "rules"),
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert output["failed_scenarios"] == 0
    assert json_path.exists()
    assert markdown_path.exists()


def test_cli_reports_input_errors(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["validate-rules", str(ROOT / "does-not-exist")])

    assert raised.value.code == 2
    assert "no YAML rules" in capsys.readouterr().err
