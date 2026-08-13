from pathlib import Path

import pytest

from signalforge.engine import DetectionEngine
from signalforge.models import DetectionRule
from signalforge.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def rules() -> list[DetectionRule]:
    return load_rules(ROOT / "rules")


@pytest.fixture(scope="session")
def engine(rules: list[DetectionRule]) -> DetectionEngine:
    return DetectionEngine(rules)
