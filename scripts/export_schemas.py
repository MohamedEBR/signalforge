from __future__ import annotations

import json
from pathlib import Path

from signalforge.models import Finding, Incident, ReplayReport, SecurityEvent

ROOT = Path(__file__).resolve().parents[1]
MODELS = {
    "event.schema.json": SecurityEvent,
    "finding.schema.json": Finding,
    "incident.schema.json": Incident,
    "replay.schema.json": ReplayReport,
}


def main() -> None:
    output = ROOT / "schemas"
    output.mkdir(exist_ok=True)
    for filename, model in MODELS.items():
        content = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (output / filename).write_text(content, encoding="utf-8")
        print(f"wrote {output / filename}")


if __name__ == "__main__":
    main()
