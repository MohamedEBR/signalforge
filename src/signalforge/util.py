from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=UTC)
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value)
    else:
        raise TypeError(f"unsupported timestamp {value!r}")
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def parse_duration(value: str) -> timedelta:
    match = re.fullmatch(r"([1-9][0-9]*)(s|m|h|d)", value)
    if not match:
        raise ValueError(f"invalid duration {value!r}; expected e.g. 30s, 5m, 2h")
    amount = int(match.group(1))
    unit = match.group(2)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    seconds = amount * multiplier
    if seconds > 7 * 86400:
        raise ValueError("rule windows cannot exceed seven days")
    return timedelta(seconds=seconds)


def stable_id(prefix: str, *parts: object) -> str:
    encoded = "\x00".join(str(part) for part in parts).encode()
    return prefix + hashlib.sha256(encoded).hexdigest()[:20].upper()


def load_jsonl(path: Path, *, maximum_records: int = 100_000) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(line) > 2_000_000:
                raise ValueError(f"{path}:{line_number}: line exceeds 2 MB")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from error
            if not isinstance(record, dict):
                raise TypeError(f"{path}:{line_number}: record must be an object")
            records.append(record)
            if len(records) > maximum_records:
                raise ValueError(f"{path}: exceeds {maximum_records} records")
    return records


def unique_ordered(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
