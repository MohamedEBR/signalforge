from datetime import timedelta
from pathlib import Path

import pytest

from signalforge.util import load_jsonl, parse_duration, parse_time, stable_id


def test_duration_is_bounded() -> None:
    assert parse_duration("15m") == timedelta(minutes=15)
    with pytest.raises(ValueError, match="expected"):
        parse_duration("0m")
    with pytest.raises(ValueError, match="seven days"):
        parse_duration("8d")


def test_timestamp_requires_timezone() -> None:
    assert parse_time("2026-08-13T00:00:00Z").utcoffset() == timedelta(0)
    with pytest.raises(ValueError, match="timezone"):
        parse_time("2026-08-13T00:00:00")
    with pytest.raises(TypeError):
        parse_time(object())


def test_jsonl_rejects_bad_json_and_non_objects(tmp_path: Path) -> None:
    path = tmp_path / "input.jsonl"
    path.write_text("not json\n")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_jsonl(path)

    path.write_text("[]\n")
    with pytest.raises(TypeError, match="must be an object"):
        load_jsonl(path)


def test_jsonl_record_bound(tmp_path: Path) -> None:
    path = tmp_path / "input.jsonl"
    path.write_text('{"id": 1}\n{"id": 2}\n')
    with pytest.raises(ValueError, match="exceeds 1 records"):
        load_jsonl(path, maximum_records=1)


def test_stable_ids_are_content_addressed() -> None:
    assert stable_id("X-", "a", 1) == stable_id("X-", "a", 1)
    assert stable_id("X-", "a", 1) != stable_id("X-", "a", 2)
